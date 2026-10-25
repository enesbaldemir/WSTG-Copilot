/*
 * Arayüz akışı için DOM'suz yardımcılar: başlangıç modu, proje sayfası
 * bölümleri ve hızlı proje formundaki hedef adresin ayrıştırılması.
 * Tarayıcıda window.WSTGFlow, Node'da module.exports (js/tests/ux-flow.test.js).
 *
 * Not: parseTarget yalnızca metni ayrıştırır; hedefe hiçbir istek göndermez.
 */
(function(root, factory){
  const api = factory();
  if(typeof module === 'object' && module.exports) module.exports = api;
  else root.WSTGFlow = api;
})(typeof self !== 'undefined' ? self : this, function(){
  'use strict';

  // Proje sayfasının bölümleri, kenar çubuğundaki pentest adımlarına göre.
  // advanced: başlangıç modunda gizlenir (veri silinmez, yalnızca görünmez).
  const SECTIONS = [
    { tab: 'overview', step: 0 },
    { tab: 'scope', step: 1 },
    { tab: 'assets', step: 2 },
    { tab: 'recon', step: 2 },
    { tab: 'testplan', step: 2 },
    { tab: 'wstg', step: 3 },
    { tab: 'authz', step: 3 },
    { tab: 'findings', step: 4 },
    { tab: 'evidence', step: 4 },
    { tab: 'reports', step: 5 },
    { tab: 'retest', step: 5 },
    { tab: 'timeline', step: 0, advanced: true },
    { tab: 'kanban', step: 0, advanced: true },
    { tab: 'chains', step: 0, advanced: true },
    { tab: 'tools', step: 0, advanced: true }
  ];
  const BY_TAB = {};
  SECTIONS.forEach(s => { BY_TAB[s.tab] = s; });

  // Kayıt yoksa (ilk kurulum) başlangıç modu açıktır; yalnızca '0' kapatır.
  function isBeginner(stored){
    return stored !== '0';
  }

  function isAdvancedTab(tab){
    return !!(BY_TAB[tab] && BY_TAB[tab].advanced);
  }

  // Bilinmeyen sekme ya da başlangıç modunda gizli bir sekme istenirse özet açılır.
  function resolveTab(tab, beginner){
    if(!BY_TAB[tab]) return 'overview';
    if(beginner && isAdvancedTab(tab)) return 'overview';
    return tab;
  }

  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

  // "example.com", "https://app.example.com/login", "10.0.0.5:8080" gibi bir
  // girdiden kapsam kaydı üretir. Geçersizse null döner.
  // { url, host, scopeType: 'domain' | 'ip' }
  function parseTarget(raw){
    const text = String(raw == null ? '' : raw).trim();
    if(!text || text.length > 2048 || /\s/.test(text)) return null;
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text);
    if(hasScheme && !/^https?:\/\//i.test(text)) return null;
    let parsed;
    try{ parsed = new URL(hasScheme ? text : 'https://' + text); }catch(e){ return null; }
    if(parsed.username || parsed.password) return null;
    let host = parsed.hostname.toLowerCase();
    if(!host) return null;
    if(host.startsWith('[') && host.endsWith(']')){
      return { url: parsed.href, host: host.slice(1, -1), scopeType: 'ip' };
    }
    if(host.endsWith('.')) host = host.slice(0, -1);
    if(IPV4_RE.test(host)) return { url: parsed.href, host, scopeType: 'ip' };
    if(!HOST_RE.test(host) || /^\d+(\.\d+)*$/.test(host)) return null;
    return { url: parsed.href, host, scopeType: 'domain' };
  }

  // ---- Proje ilerlemesi: beş adım ve "sıradaki adım" ----
  // st: { scope, recon, assets, done, total, findings, reported, reconSkipped }
  // Keşif isteğe bağlıdır: atlanınca, teste başlanınca ya da bulgu kaydedilince geçilmiş sayılır.
  function projectSteps(st){
    const s = Object.assign({ scope: 0, recon: 0, assets: 0, done: 0, total: 0, findings: 0, reported: false, reconSkipped: false }, st || {});
    const action = nextAction(s);
    const currentStep = { scope: 1, recon: 2, firstTest: 3, keepTesting: 3, report: 5, retest: 5 }[action];
    const doneFlags = [
      s.scope > 0,
      s.recon > 0 || s.assets > 0 || s.done > 0 || s.findings > 0 || !!s.reconSkipped,
      s.total > 0 && s.done >= s.total,
      s.findings > 0,
      !!s.reported
    ];
    const steps = doneFlags.map((isDone, i) => ({
      step: i + 1,
      state: isDone ? 'done' : (i + 1 === currentStep ? 'current' : 'todo')
    }));
    // Sıradaki adım tamamlanmış görünse bile (ör. rapor yeniden alınabilir) vurgulanır.
    steps[currentStep - 1].current = true;
    return { action, currentStep, steps };
  }

  function nextAction(s){
    if(!(s.scope > 0)) return 'scope';
    // Teste başlanmış ya da bulgu kaydedilmişse keşif geride kalmıştır.
    if(!(s.recon > 0 || s.assets > 0 || s.done > 0 || s.findings > 0 || s.reconSkipped)) return 'recon';
    if(!(s.findings > 0)) return s.done > 0 ? 'keepTesting' : 'firstTest';
    if(!s.reported) return 'report';
    return 'retest';
  }

  // Resmi sıraya göre ilk tamamlanmamış test.
  function firstPendingTest(categories, progress){
    const done = progress || {};
    for(const c of categories || []){
      for(const test of c.tests || []){
        if(!done[test.id]) return { catId: c.id, testId: test.id, title: test.title };
      }
    }
    return null;
  }

  // ---- WSTG kodlarının açıklaması ----
  const WSTG_CATEGORIES = {
    INFO: { en: 'Information Gathering', tr: 'Bilgi Toplama' },
    CONF: { en: 'Configuration and Deployment Management', tr: 'Yapılandırma ve Dağıtım Yönetimi' },
    IDNT: { en: 'Identity Management', tr: 'Kimlik Yönetimi' },
    ATHN: { en: 'Authentication', tr: 'Kimlik Doğrulama' },
    ATHZ: { en: 'Authorization', tr: 'Yetkilendirme' },
    SESS: { en: 'Session Management', tr: 'Oturum Yönetimi' },
    INPV: { en: 'Input Validation', tr: 'Girdi Doğrulama' },
    ERRH: { en: 'Error Handling', tr: 'Hata Yönetimi' },
    CRYP: { en: 'Cryptography', tr: 'Kriptografi' },
    BUSL: { en: 'Business Logic', tr: 'İş Mantığı' },
    CLNT: { en: 'Client-side', tr: 'İstemci Tarafı' },
    APIT: { en: 'API Testing', tr: 'API Testleri' }
  };

  // "WSTG-ATHN" ya da "WSTG-ATHN-03" için okunabilir açıklama; tanınmayan kodda null.
  function explainCode(code, lang){
    const m = /^WSTG-([A-Z]{4})(?:-(\d{1,3}))?$/.exec(String(code || '').trim().toUpperCase());
    if(!m || !WSTG_CATEGORIES[m[1]]) return null;
    const cat = WSTG_CATEGORIES[m[1]];
    const tr = lang !== 'en';
    const parts = [
      tr ? 'WSTG = OWASP Web Güvenliği Test Rehberi' : 'WSTG = OWASP Web Security Testing Guide',
      tr ? `${m[1]} = ${cat.en} (${cat.tr})` : `${m[1]} = ${cat.en}`
    ];
    if(m[2]) parts.push(tr ? `${m[2]} = bu kategorideki ${Number(m[2])}. test` : `${m[2]} = test number ${Number(m[2])} in this category`);
    return parts.join(' · ');
  }

  return { SECTIONS, isBeginner, isAdvancedTab, resolveTab, parseTarget, projectSteps, nextAction, firstPendingTest, explainCode };
});
