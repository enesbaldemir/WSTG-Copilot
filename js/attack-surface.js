/*
 * Saldırı Yüzeyi — salt-okunur özetleme katmanı.
 *
 * Girdi yalnızca mevcut API yanıtlarıdır:
 *   GET /api/projects/<id>/assets  -> { subdomains, technologies, endpoints, runs: [ReconRun.to_dict()] }
 *   GET /api/projects/<id>/scope   -> [ScopeItem.to_dict()]
 * Bu dosya hiçbir ağ isteği yapmaz ve hiçbir veri uydurmaz:
 *   - "hedef -> varlık" ilişkisi, varlığın o hedefin tarama kaydında bulunmasından gelir;
 *   - "endpoint -> WSTG testi" ilişkisi, recon'un kaydettiği gerekçe metninden
 *     ("<neden>: <yol>") türetilir ve `derived: true` olarak işaretlenir;
 *   - kayıtta olmayan alanlar (ör. teknolojinin hangi alt alan adında çalıştığı) üretilmez.
 * Tarayıcıda window.WSTGAttackSurface, Node'da module.exports olarak kullanılır.
 */
(function(root, factory){
  const api = factory();
  if(typeof module === 'object' && module.exports) module.exports = api;
  else root.WSTGAttackSurface = api;
})(typeof self !== 'undefined' ? self : this, function(){
  'use strict';

  const LEVEL_ORDER = { high: 3, medium: 2, low: 1, info: 0 };

  function norm(v){ return String(v == null ? '' : v).trim().toLowerCase(); }

  // Backend zaman damgaları UTC'dir ama saat dilimi eki taşımaz.
  function parseDate(value){
    if(!value) return null;
    const str = String(value);
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(str) ? str : str + 'Z');
    return isNaN(d.getTime()) ? null : d;
  }

  function ipv4ToInt(ip){
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
    if(!m) return null;
    const parts = m.slice(1).map(Number);
    if(parts.some(n => n > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  }

  function cidrContains(cidr, ip){
    const [base, bitsRaw] = String(cidr).split('/');
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    const b = ipv4ToInt(norm(base)), i = ipv4ToInt(norm(ip));
    if(b === null || i === null || !(bits >= 0 && bits <= 32)) return false;
    if(bits === 0) return true;
    const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
    return ((b & mask) >>> 0) === ((i & mask) >>> 0);
  }

  // Kapsam eşleşmesi bilinçli olarak muhafazakârdır:
  //  "example.com"   -> yalnızca example.com
  //  "*.example.com" -> example.com'un alt alan adları (example.com'un kendisi değil)
  function scopeItemMatches(host, item){
    const h = norm(host), v = norm(item && item.value);
    if(!h || !v) return false;
    if(item.type === 'ip') return h === v;
    if(item.type === 'cidr') return cidrContains(v, h);
    if(v.startsWith('*.')) return h.endsWith('.' + v.slice(2));
    return h === v;
  }

  // 'undefined' (kapsam tanımlanmamış) | 'out' | 'in' | 'unknown'
  function scopeStatus(host, scopeItems){
    const items = Array.isArray(scopeItems) ? scopeItems : [];
    if(!items.length) return 'undefined';
    if(items.some(i => !i.in_scope && scopeItemMatches(host, i))) return 'out';
    if(items.some(i => i.in_scope && scopeItemMatches(host, i))) return 'in';
    return 'unknown';
  }

  // Recon gerekçeleri "<neden>: <değer>" biçimindedir (bkz. recon.map_to_wstg).
  // Değer bir yol ise o endpoint ile test arasında türetilmiş bir ilişki kurulur.
  function endpointTestIndex(suggestions){
    const index = {};
    Object.keys(suggestions || {}).forEach(testId => {
      const info = suggestions[testId] || {};
      (info.reasons || []).forEach(reason => {
        const r = String(reason);
        const at = r.lastIndexOf(': ');
        if(at === -1) return;
        const value = r.slice(at + 2).trim();
        if(!value.startsWith('/')) return;
        const list = index[value] = index[value] || [];
        if(!list.some(x => x.test_id === testId)) list.push({ test_id: testId, level: info.level || 'info', reason: r, derived: true });
      });
    });
    Object.keys(index).forEach(k => index[k].sort(byLevelThenId));
    return index;
  }

  function byLevelThenId(a, b){
    return (LEVEL_ORDER[b.level] || 0) - (LEVEL_ORDER[a.level] || 0) || String(a.test_id).localeCompare(String(b.test_id));
  }

  function touch(map, key, base, seenAt){
    let row = map.get(key);
    if(!row){
      row = Object.assign({ firstSeen: seenAt, lastSeen: seenAt, runCount: 0 }, base);
      map.set(key, row);
    }
    if(seenAt && (!row.lastSeen || seenAt > row.lastSeen)) row.lastSeen = seenAt;
    if(seenAt && (!row.firstSeen || seenAt < row.firstSeen)) row.firstSeen = seenAt;
    row.runCount += 1;
    return row;
  }

  /**
   * @param {object} assetsResp  GET /assets yanıtı
   * @param {Array}  scopeItems  GET /scope yanıtı
   * @param {Set|Array} doneTestIds  projede tamamlanmış test ID'leri
   */
  function buildSurface(assetsResp, scopeItems, doneTestIds){
    const done = doneTestIds instanceof Set ? doneTestIds : new Set(doneTestIds || []);
    const runs = ((assetsResp && assetsResp.runs) || []).slice()
      .map(r => Object.assign({}, r, { _at: parseDate(r.created_at) }))
      .sort((a, b) => (b._at ? b._at.getTime() : 0) - (a._at ? a._at.getTime() : 0));

    // Her hedef için en son tarama (öneriler bu kayıttan okunur).
    const latestByTarget = new Map();
    runs.forEach(r => {
      const tkey = norm(r.target);
      if(tkey && !latestByTarget.has(tkey)) latestByTarget.set(tkey, r);
    });

    const rows = new Map();
    const targets = new Map();
    runs.forEach(run => {
      const target = run.target || '';
      const tkey = norm(target);
      const seenAt = run._at;
      if(!tkey) return;
      const tgroup = targets.get(tkey) || { target, baseUrl: run.baseUrl || null, lastScanAt: seenAt, subdomains: new Set(), endpoints: new Set(), technologies: new Set() };
      targets.set(tkey, tgroup);

      touch(rows, `domain|${tkey}`, { type: 'domain', value: target, target, record: 'target' }, seenAt);

      (run.subdomains || []).forEach(sub => {
        if(norm(sub) === tkey) return; // hedefin kendisi
        tgroup.subdomains.add(sub);
        touch(rows, `subdomain|${norm(sub)}`, { type: 'subdomain', value: sub, target, record: 'resolved' }, seenAt);
      });

      const statusByPath = {};
      (run.interestingPaths || []).forEach(p => { if(p && p.path) statusByPath[p.path] = p.status; });
      const apis = new Set(run.apis || []);
      (run.endpoints || []).forEach(ep => {
        tgroup.endpoints.add(ep);
        const row = touch(rows, `endpoint|${tkey}|${ep}`, { type: 'endpoint', value: ep, target, record: 'link' }, seenAt);
        if(statusByPath[ep] !== undefined){ row.record = 'http'; row.httpStatus = statusByPath[ep]; }
        if(apis.has(ep)) row.isApi = true;
      });

      (run.technologies || []).forEach(tech => {
        tgroup.technologies.add(tech);
        touch(rows, `technology|${tkey}|${norm(tech)}`, { type: 'technology', value: tech, target, record: 'detected' }, seenAt);
      });
    });

    const testIndexByTarget = new Map();
    latestByTarget.forEach((run, tkey) => testIndexByTarget.set(tkey, endpointTestIndex(run.suggestions)));

    const inventory = Array.from(rows.values()).map(row => {
      const tkey = norm(row.target);
      let tests = [];
      if(row.type === 'endpoint'){
        tests = ((testIndexByTarget.get(tkey) || {})[row.value] || []).map(x => Object.assign({ done: done.has(x.test_id) }, x));
      }
      let scope = null;
      if(row.type === 'domain' || row.type === 'subdomain') scope = scopeStatus(row.value, scopeItems);
      return Object.assign({}, row, {
        tests,
        scope,
        lastSeen: row.lastSeen ? row.lastSeen.toISOString() : null,
        firstSeen: row.firstSeen ? row.firstSeen.toISOString() : null,
      });
    });

    const typeOrder = { domain: 0, subdomain: 1, endpoint: 2, technology: 3 };
    inventory.sort((a, b) => (typeOrder[a.type] - typeOrder[b.type]) || String(a.value).localeCompare(String(b.value)));

    // Öneriler: her hedefin en son kaydındaki `suggestions` birleştirilir.
    const sugg = new Map();
    latestByTarget.forEach(run => {
      const s = run.suggestions || {};
      Object.keys(s).forEach(testId => {
        const info = s[testId] || {};
        const cur = sugg.get(testId) || { test_id: testId, level: info.level || 'info', reasons: [], targets: [] };
        if((LEVEL_ORDER[info.level] || 0) > (LEVEL_ORDER[cur.level] || 0)) cur.level = info.level;
        (info.reasons || []).forEach(r => { if(!cur.reasons.includes(r)) cur.reasons.push(r); });
        if(run.target && !cur.targets.includes(run.target)) cur.targets.push(run.target);
        sugg.set(testId, cur);
      });
    });
    const suggestions = Array.from(sugg.values())
      .map(s => Object.assign(s, { done: done.has(s.test_id) }))
      .sort((a, b) => (a.done - b.done) || byLevelThenId(a, b));

    const count = type => inventory.filter(r => r.type === type).length;
    const latest = runs[0] || null;

    return {
      runCount: runs.length,
      lastScanAt: latest && latest._at ? latest._at.toISOString() : null,
      latestTarget: latest ? latest.target || null : null,
      latestBaseUrl: latest ? latest.baseUrl || null : null,
      targetScope: latest && latest.target ? scopeStatus(latest.target, scopeItems) : null,
      scopeItemCount: Array.isArray(scopeItems) ? scopeItems.length : 0,
      targets: Array.from(targets.values()).map(g => ({
        target: g.target, baseUrl: g.baseUrl,
        lastScanAt: g.lastScanAt ? g.lastScanAt.toISOString() : null,
        subdomains: Array.from(g.subdomains).sort(),
        endpoints: Array.from(g.endpoints).sort(),
        technologies: Array.from(g.technologies).sort(),
      })),
      inventory,
      counts: {
        domain: count('domain'), subdomain: count('subdomain'), endpoint: count('endpoint'),
        api: inventory.filter(r => r.type === 'endpoint' && r.isApi).length,
        technology: count('technology'), total: inventory.length,
      },
      suggestions,
    };
  }

  function filterInventory(inventory, filters){
    const f = filters || {};
    const q = norm(f.q);
    return (inventory || []).filter(r => {
      if(f.type && f.type !== 'all' && r.type !== f.type) return false;
      if(f.scope && f.scope !== 'all' && r.scope !== f.scope) return false;
      if(q){
        const hay = [r.value, r.target].concat((r.tests || []).map(x => x.test_id)).map(norm).join(' ');
        if(!hay.includes(q)) return false;
      }
      return true;
    });
  }

  return { LEVEL_ORDER, parseDate, scopeItemMatches, scopeStatus, endpointTestIndex, buildSurface, filterInventory };
});
