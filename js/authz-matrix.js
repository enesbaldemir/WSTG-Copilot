/*
 * Yetkilendirme matrisi için DOM'suz yardımcılar (roller x endpoint'ler).
 * Tarayıcıda window.WSTGAuthz, Node'da module.exports (js/tests/authz-matrix.test.js).
 *
 * Hücre: { expected: 'allow'|'deny'|null, observed: 'allowed'|'denied'|null,
 *          note: string, finding_id: number|null }
 * Bu modül hiçbir ağ isteği yapmaz; sonuçları pentester girer.
 */
(function(root, factory){
  const api = factory();
  if(typeof module === 'object' && module.exports) module.exports = api;
  else root.WSTGAuthz = api;
})(typeof self !== 'undefined' ? self : this, function(){
  'use strict';

  const MAX_ROLES = 12;
  const MAX_ENDPOINTS = 500;
  const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ANY'];
  const PRIVILEGED_ROLE_RE = /admin|yönetici|yonetici|root|super|owner|sahip/i;

  function newId(prefix){
    return (prefix || 'x') + Date.now().toString(36).slice(-5) + Math.random().toString(36).slice(2, 7);
  }
  function cellKey(endpointId, roleId){ return endpointId + ':' + roleId; }
  function emptyCell(){ return { expected: null, observed: null, note: '', finding_id: null }; }

  function getCell(doc, endpointId, roleId){
    return (doc.cells && doc.cells[cellKey(endpointId, roleId)]) || emptyCell();
  }

  // Hücrenin durumu:
  //  violation: beklenen yasak, gözlenen erişti  (yetkilendirme açığı)
  //  over:      beklenen izinli, gözlenen engellendi (fazla kısıtlı)
  //  ok:        beklenen = gözlenen
  //  observed:  sonuç var, beklenti girilmemiş
  //  untested:  beklenti var, henüz denenmedi
  //  unset:     boş
  function cellStatus(cell){
    const c = cell || {};
    if(!c.observed) return c.expected ? 'untested' : 'unset';
    if(!c.expected) return 'observed';
    if(c.expected === 'deny' && c.observed === 'allowed') return 'violation';
    if(c.expected === 'allow' && c.observed === 'denied') return 'over';
    return 'ok';
  }

  function summarize(doc){
    const roles = doc.roles || [], endpoints = doc.endpoints || [];
    const out = { cells: roles.length * endpoints.length, tested: 0, violations: 0, over_restricted: 0, untested: 0 };
    endpoints.forEach(e => roles.forEach(r => {
      const st = cellStatus(getCell(doc, e.id, r.id));
      if(st === 'violation') out.violations++;
      if(st === 'over') out.over_restricted++;
      if(st === 'violation' || st === 'over' || st === 'ok' || st === 'observed') out.tested++;
    }));
    out.untested = out.cells - out.tested;
    return out;
  }

  function violations(doc){
    const list = [];
    (doc.endpoints || []).forEach(e => (doc.roles || []).forEach(r => {
      const cell = getCell(doc, e.id, r.id);
      if(cellStatus(cell) === 'violation') list.push({ key: cellKey(e.id, r.id), endpoint: e, role: r, cell });
    }));
    return list;
  }

  function normalizePath(path){
    let p = String(path || '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
    if(p && !/^https?:\/\//i.test(p) && p[0] !== '/') p = '/' + p;
    return p;
  }

  // items: [{method, path}] -> yeni belge + eklenen/atlanan sayıları
  function addEndpoints(doc, items){
    const endpoints = (doc.endpoints || []).slice();
    const seen = new Set(endpoints.map(e => e.method + ' ' + e.path));
    let added = 0, skipped = 0;
    (items || []).forEach(it => {
      const method = String((it && it.method) || 'GET').trim().toUpperCase();
      const path = normalizePath(it && it.path);
      if(!path || METHODS.indexOf(method) === -1 || path.length > 500){ skipped++; return; }
      const key = method + ' ' + path;
      if(seen.has(key) || endpoints.length >= MAX_ENDPOINTS){ skipped++; return; }
      seen.add(key);
      endpoints.push({ id: newId('e'), method, path, note: '' });
      added++;
    });
    return { doc: Object.assign({}, doc, { endpoints }), added, skipped };
  }

  function defaultRoles(lang){
    const names = lang === 'en' ? ['Anonymous', 'User', 'Admin'] : ['Anonim', 'Kullanıcı', 'Yönetici'];
    return names.map((name, i) => ({ id: 'r' + (i + 1), name }));
  }

  // Bir rol yasak olduğu bir endpoint'e erişebiliyorsa: endpoint'e yalnızca
  // ayrıcalıklı roller (admin vb.) izinliyse dikey yetki yükseltme
  // (ATHZ-03), değilse genel yetkilendirme atlatma (ATHZ-02).
  function findingDraft(doc, v, lang){
    const tr = lang !== 'en';
    const allowedRoles = (doc.roles || []).filter(r => getCell(doc, v.endpoint.id, r.id).expected === 'allow');
    const vertical = allowedRoles.length > 0 && allowedRoles.every(r => PRIVILEGED_ROLE_RE.test(r.name)) && !PRIVILEGED_ROLE_RE.test(v.role.name);
    const target = `${v.endpoint.method} ${v.endpoint.path}`;
    const label = { allow: tr ? 'İzinli' : 'Allowed', deny: tr ? 'Yasak' : 'Denied', allowed: tr ? 'Erişti' : 'Accessible', denied: tr ? 'Engellendi' : 'Blocked' };
    const rows = (doc.roles || []).map(r => {
      const c = getCell(doc, v.endpoint.id, r.id);
      return `- ${r.name}: ${tr ? 'beklenen' : 'expected'} ${c.expected ? label[c.expected] : '—'}, ${tr ? 'gözlenen' : 'observed'} ${c.observed ? label[c.observed] : (tr ? 'denenmedi' : 'not tested')}`;
    }).join('\n');
    const description = tr
      ? `"${v.role.name}" rolü, erişmemesi gereken ${target} adresine erişebildi.${v.cell.note ? '\n\nTest notu: ' + v.cell.note : ''}\n\nYetkilendirme matrisi:\n${rows}`
      : `The "${v.role.name}" role could access ${target}, which it should not be able to.${v.cell.note ? '\n\nTest note: ' + v.cell.note : ''}\n\nAuthorization matrix:\n${rows}`;
    return {
      title: tr ? `Yetkisiz erişim: "${v.role.name}" rolü ${target}` : `Unauthorized access: "${v.role.name}" role on ${target}`,
      severity: 'high',
      endpoint: v.endpoint.path.slice(0, 300),
      test_id: vertical ? 'WSTG-ATHZ-03' : 'WSTG-ATHZ-02',
      description,
      remediation: tr
        ? 'Her istekte yetki kontrolünü sunucu tarafında, oturumdaki kullanıcının rolüne göre yapın; varsayılan olarak reddedin ve istemciden gelen rol/kimlik değerlerine güvenmeyin.'
        : 'Enforce authorization on the server for every request based on the session user\'s role; deny by default and never trust role or identity values sent by the client.',
      status: 'open',
    };
  }

  function csvCell(v){
    let s = v === null || v === undefined ? '' : String(v);
    if(/^[=+\-@\t\r]/.test(s)) s = "'" + s;   // Excel formül enjeksiyonu
    return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function toCsv(doc, labels){
    const L = Object.assign({ method: 'Method', path: 'Path', allow: 'allow', deny: 'deny', allowed: 'allowed', denied: 'denied', none: '-' }, labels || {});
    const roles = doc.roles || [];
    const lines = [[L.method, L.path].concat(roles.map(r => r.name)).map(csvCell).join(',')];
    (doc.endpoints || []).forEach(e => {
      const cells = roles.map(r => {
        const c = getCell(doc, e.id, r.id);
        if(!c.expected && !c.observed) return '';
        return `${c.expected ? L[c.expected] : L.none} / ${c.observed ? L[c.observed] : L.none}`;
      });
      lines.push([e.method, e.path].concat(cells).map(csvCell).join(','));
    });
    return lines.join('\n');
  }

  return {
    MAX_ROLES, MAX_ENDPOINTS, METHODS,
    newId, cellKey, emptyCell, getCell, cellStatus, summarize, violations,
    normalizePath, addEndpoints, defaultRoles, findingDraft, toCsv,
  };
});
