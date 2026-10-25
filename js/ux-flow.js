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

  return { SECTIONS, isBeginner, isAdvancedTab, resolveTab, parseTarget };
});
