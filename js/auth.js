/*
 * Kimlik doğrulama için saf yardımcılar (ağ isteği yapmaz, DOM'a dokunmaz).
 *
 * Oturum, API'nin (127.0.0.1:5000) koyduğu SameSite=Strict bir çerezdir.
 * Çerezler porta göre ayrılmaz ama host'a göre ayrılır; localhost ile
 * 127.0.0.1 farklı "site" sayılır. Sayfa hangi adresten açıldıysa API de aynı
 * host'tan çağrılmalı ki çerez gönderilsin:
 *   http://127.0.0.1:8000  -> http://127.0.0.1:5000/api
 *   http://localhost:8000  -> http://localhost:5000/api
 * Tarayıcıda window.WSTGAuth, Node'da module.exports olarak kullanılır.
 */
(function(root, factory){
  const api = factory();
  if(typeof module === 'object' && module.exports) module.exports = api;
  else root.WSTGAuth = api;
})(typeof self !== 'undefined' ? self : this, function(){
  'use strict';

  const API_PORT = 5000;
  const FALLBACK_HOST = 'localhost';

  // loc: window.location benzeri { protocol, hostname }
  function apiBaseFor(loc, port){
    port = port || API_PORT;
    const isWeb = !!(loc && loc.hostname && (loc.protocol === 'http:' || loc.protocol === 'https:'));
    // file:// gibi host'suz açılışlar: eski varsayılan adres.
    if(!isWeb) return `http://${FALLBACK_HOST}:${port}/api`;
    let host = loc.hostname;
    // IPv6: location.hostname tarayıcıya göre köşeli parantezli ya da parantezsiz gelir.
    if(host.indexOf(':') !== -1 && host.charAt(0) !== '[') host = `[${host}]`;
    return `${loc.protocol}//${host}:${port}/api`;
  }

  // Backend'in döndürdüğü `code` -> I18N anahtarı.
  const ERROR_KEYS = {
    password_required: 'authErrPasswordRequired',
    password_too_short: 'authErrPasswordTooShort',
    password_too_long: 'authErrPasswordTooLong',
    password_whitespace: 'authErrPasswordWhitespace',
    password_unchanged: 'authErrPasswordUnchanged',
    password_mismatch: 'authErrPasswordMismatch',
    invalid_password: 'authErrInvalidPassword',
    invalid_current_password: 'authErrInvalidCurrentPassword',
    too_many_attempts: 'authErrTooManyAttempts',
    setup_loopback_only: 'authErrSetupLoopbackOnly',
    already_configured: 'authErrAlreadyConfigured',
    setup_required: 'authErrSetupRequired',
    auth_required: 'authErrSessionExpired'
  };

  function errorKey(code){
    return ERROR_KEYS[code] || null;
  }

  // Yalnızca giriş kapısının 401'i "oturum düştü" demektir; hatalı parola
  // (invalid_password) ya da ileride başka bir sebeple dönen 401 değil.
  function isSessionLost(status, body){
    return status === 401 && !!body && body.code === 'auth_required';
  }

  return { API_PORT, apiBaseFor, errorKey, isSessionLost, ERROR_KEYS };
});
