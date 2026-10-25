/*
 * Hazır bulgu şablonları: sık görülen web açıkları için başlık, açıklama,
 * etki ve çözüm önerisi (TR/EN), WSTG test ID'si, CWE ve OWASP Top 10:2025
 * kategorisi. Metinler savunma amaçlıdır; saldırı adımı içermez. Hedefe özel
 * bilgiler (endpoint, parametre, tekrarlama adımları) kullanıcı tarafından yazılır.
 * Tarayıcıda window.WSTGTemplates, Node'da module.exports (js/tests/finding-templates.test.js).
 */
(function(root, factory){
  const api = factory();
  if(typeof module === 'object' && module.exports) module.exports = api;
  else root.WSTGTemplates = api;
})(typeof self !== 'undefined' ? self : this, function(){
  'use strict';

  const CS = 'https://cheatsheetseries.owasp.org/cheatsheets/';
  const cwe = n => `https://cwe.mitre.org/data/definitions/${n}.html`;

  const GROUPS = {
    injection: { tr: 'Enjeksiyon', en: 'Injection' },
    access: { tr: 'Erişim kontrolü', en: 'Access control' },
    session: { tr: 'Oturum yönetimi', en: 'Session management' },
    auth: { tr: 'Kimlik doğrulama', en: 'Authentication' },
    config: { tr: 'Yapılandırma ve kriptografi', en: 'Configuration and cryptography' },
    client: { tr: 'İstemci tarafı', en: 'Client side' }
  };

  const TEMPLATES = [
    { id: 'xss-reflected', group: 'injection', test_id: 'WSTG-INPV-01', cwe: 'CWE-79', owasp: 'A05:2025 Injection', severity: 'high',
      refs: [CS + 'Cross_Site_Scripting_Prevention_Cheat_Sheet.html', cwe(79)],
      tr: { title: 'Yansıtılan siteler arası betik çalıştırma (Reflected XSS)',
        description: 'Kullanıcıdan gelen bir parametre, uygun çıktı kodlaması yapılmadan yanıt sayfasına yansıtılıyor. Hazırlanmış bir bağlantıya tıklayan kullanıcının tarayıcısında saldırganın betiği çalışabiliyor.',
        impact: 'Oturum çerezlerinin çalınması, kullanıcı adına işlem yapılması, sayfa içeriğinin değiştirilmesi ve kimlik avı.',
        remediation: 'Tüm kullanıcı verisini çıktı bağlamına göre (HTML, öznitelik, JavaScript, URL) kodlayın; otomatik kaçış yapan şablon motoru kullanın. Ek savunma olarak katı bir Content-Security-Policy tanımlayın ve oturum çerezlerinde HttpOnly bayrağını kullanın.' },
      en: { title: 'Reflected cross-site scripting (XSS)',
        description: 'A user-supplied parameter is reflected into the response page without proper output encoding. A user who follows a crafted link can have the attacker\'s script executed in their browser.',
        impact: 'Theft of session cookies, actions performed on the user\'s behalf, page defacement and phishing.',
        remediation: 'Encode all user data for its output context (HTML, attribute, JavaScript, URL) and use a templating engine with automatic escaping. As defence in depth, set a strict Content-Security-Policy and mark session cookies HttpOnly.' } },
    { id: 'xss-stored', group: 'injection', test_id: 'WSTG-INPV-02', cwe: 'CWE-79', owasp: 'A05:2025 Injection', severity: 'high',
      refs: [CS + 'Cross_Site_Scripting_Prevention_Cheat_Sheet.html', cwe(79)],
      tr: { title: 'Kalıcı siteler arası betik çalıştırma (Stored XSS)',
        description: 'Kullanıcıdan alınan içerik kaydediliyor ve diğer kullanıcılara kodlanmadan gösteriliyor. Sayfayı görüntüleyen her kullanıcının tarayıcısında saldırganın betiği çalışabiliyor.',
        impact: 'Sayfayı ziyaret eden tüm kullanıcıların (yöneticiler dahil) oturumlarının ele geçirilmesi ve hesapları adına işlem yapılması.',
        remediation: 'Saklanan içeriği gösterirken çıktı bağlamına göre kodlayın. Zengin metin gerekiyorsa izin listesine dayalı bir HTML temizleyici kullanın. Katı bir Content-Security-Policy ekleyin.' },
      en: { title: 'Stored cross-site scripting (XSS)',
        description: 'User-supplied content is stored and later shown to other users without encoding. Every user who views the page can have the attacker\'s script executed in their browser.',
        impact: 'Takeover of the sessions of every visitor (including administrators) and actions performed in their name.',
        remediation: 'Encode stored content for its output context when rendering it. If rich text is required, use an allow-list HTML sanitizer. Add a strict Content-Security-Policy.' } },
    { id: 'sqli', group: 'injection', test_id: 'WSTG-INPV-05', cwe: 'CWE-89', owasp: 'A05:2025 Injection', severity: 'critical',
      refs: [CS + 'SQL_Injection_Prevention_Cheat_Sheet.html', cwe(89)],
      tr: { title: 'SQL enjeksiyonu',
        description: 'Kullanıcı girdisi veritabanı sorgusuna doğrudan ekleniyor. Girdi, sorgunun yapısını değiştirebiliyor.',
        impact: 'Veritabanındaki verilerin okunması, değiştirilmesi ya da silinmesi; kimlik doğrulamanın atlatılması; bazı yapılandırmalarda sunucuda komut çalıştırılması.',
        remediation: 'Tüm sorgularda parametreli sorgu (prepared statement) ya da güvenli bir ORM kullanın; girdiyi sorgu metnine birleştirmeyin. Veritabanı kullanıcısına yalnızca gereken yetkileri verin ve hata mesajlarında sorgu ayrıntısı göstermeyin.' },
      en: { title: 'SQL injection',
        description: 'User input is concatenated directly into a database query, allowing the input to change the structure of the query.',
        impact: 'Reading, modifying or deleting database data; bypassing authentication; in some configurations, executing commands on the server.',
        remediation: 'Use parameterized queries (prepared statements) or a safe ORM for every query; never concatenate input into query text. Give the database account only the privileges it needs and keep query details out of error messages.' } },
    { id: 'cmdi', group: 'injection', test_id: 'WSTG-INPV-13', cwe: 'CWE-78', owasp: 'A05:2025 Injection', severity: 'critical',
      refs: [CS + 'OS_Command_Injection_Defense_Cheat_Sheet.html', cwe(78)],
      tr: { title: 'İşletim sistemi komut enjeksiyonu',
        description: 'Kullanıcı girdisi sunucuda çalıştırılan bir işletim sistemi komutuna ekleniyor ve komutun anlamını değiştirebiliyor.',
        impact: 'Sunucuda uygulamanın yetkileriyle istenen komutların çalıştırılması; verilerin ve sunucunun tamamen ele geçirilmesi.',
        remediation: 'Mümkünse kabuk komutu çağırmak yerine dilin kendi kütüphanelerini kullanın. Komut gerekiyorsa kabuk kullanmadan, argüman listesiyle çağırın ve girdiyi izin listesiyle doğrulayın. Uygulamayı en az yetkiyle çalıştırın.' },
      en: { title: 'OS command injection',
        description: 'User input is inserted into an operating system command executed on the server and can change what the command does.',
        impact: 'Arbitrary command execution with the application\'s privileges; full compromise of data and the server.',
        remediation: 'Prefer language libraries over shell commands. When a command is unavoidable, invoke it without a shell using an argument list, and validate input against an allow-list. Run the application with least privilege.' } },
    { id: 'ssrf', group: 'injection', test_id: 'WSTG-INPV-20', cwe: 'CWE-918', owasp: 'A01:2025 Broken Access Control', severity: 'high',
      refs: [CS + 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html', cwe(918)],
      tr: { title: 'Sunucu taraflı istek sahteciliği (SSRF)',
        description: 'Uygulama, kullanıcının verdiği bir adrese sunucu tarafından istek gönderiyor ve hedef adresi yeterince kısıtlamıyor.',
        impact: 'İç ağdaki servislere ve bulut meta veri uç noktalarına erişim; iç sistemlerin taranması; kimlik bilgilerinin sızması.',
        remediation: 'Gidilebilecek adresleri izin listesiyle sınırlayın; özel, loopback ve link-local IP aralıklarını DNS çözümlemesinden sonra engelleyin; yönlendirmeleri takip etmeyin. Sunucunun dışarı çıkışını ağ seviyesinde de kısıtlayın.' },
      en: { title: 'Server-side request forgery (SSRF)',
        description: 'The application sends a server-side request to a user-supplied address without sufficiently restricting the destination.',
        impact: 'Access to internal services and cloud metadata endpoints, scanning of internal systems and credential exposure.',
        remediation: 'Restrict destinations with an allow-list; block private, loopback and link-local ranges after DNS resolution; do not follow redirects. Also restrict the server\'s outbound traffic at the network level.' } },
    { id: 'path-traversal', group: 'injection', test_id: 'WSTG-INPV-11', cwe: 'CWE-22', owasp: 'A01:2025 Broken Access Control', severity: 'high',
      refs: [cwe(22)],
      tr: { title: 'Dizin geçişi / yerel dosya dahil etme',
        description: 'Kullanıcının verdiği dosya adı ya da yolu doğrulanmadan dosya okumak için kullanılıyor; uygulama klasörünün dışındaki dosyalara erişilebiliyor.',
        impact: 'Yapılandırma dosyaları, kaynak kod ve kimlik bilgileri gibi hassas dosyaların okunması.',
        remediation: 'Dosyaları kullanıcı girdisiyle değil, sunucu tarafında tutulan kimliklerle (ör. izin listesindeki bir anahtar) seçin. Yol gerekiyorsa normalleştirip izin verilen kök klasörün içinde kaldığını doğrulayın.' },
      en: { title: 'Path traversal / local file inclusion',
        description: 'A user-supplied file name or path is used to read files without validation, allowing access to files outside the application directory.',
        impact: 'Reading sensitive files such as configuration files, source code and credentials.',
        remediation: 'Select files by server-side identifiers (e.g. an allow-listed key) rather than user input. If a path is required, canonicalize it and verify that it stays inside the permitted base directory.' } },
    { id: 'idor', group: 'access', test_id: 'WSTG-ATHZ-04', cwe: 'CWE-639', owasp: 'A01:2025 Broken Access Control', severity: 'high',
      refs: [CS + 'Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html', cwe(639)],
      tr: { title: 'Güvensiz doğrudan nesne referansı (IDOR)',
        description: 'Uygulama, istekteki nesne kimliğine (ör. sipariş ya da kullanıcı numarası) göre veri döndürüyor ancak nesnenin isteği yapan kullanıcıya ait olup olmadığını kontrol etmiyor.',
        impact: 'Başka kullanıcıların verilerinin görüntülenmesi ya da değiştirilmesi.',
        remediation: 'Her istekte sunucu tarafında nesnenin oturumdaki kullanıcıya ait olduğunu (ya da erişim yetkisi bulunduğunu) doğrulayın. Kimlikleri tahmin edilemez yapmak tek başına yeterli değildir.' },
      en: { title: 'Insecure direct object reference (IDOR)',
        description: 'The application returns data based on an object identifier in the request (e.g. an order or user number) without checking that the object belongs to the requesting user.',
        impact: 'Viewing or modifying other users\' data.',
        remediation: 'On every request, verify on the server that the object belongs to (or is accessible by) the authenticated user. Unpredictable identifiers alone are not sufficient.' } },
    { id: 'privesc', group: 'access', test_id: 'WSTG-ATHZ-03', cwe: 'CWE-269', owasp: 'A01:2025 Broken Access Control', severity: 'high',
      refs: [CS + 'Authorization_Cheat_Sheet.html', cwe(269)],
      tr: { title: 'Yetki yükseltme (eksik yetki kontrolü)',
        description: 'Yalnızca yetkili rollerin kullanması gereken bir işlev ya da uç nokta, daha düşük yetkili bir kullanıcı tarafından da çağrılabiliyor.',
        impact: 'Düşük yetkili kullanıcıların yönetici işlemleri yapabilmesi; verilerin ve ayarların yetkisiz değiştirilmesi.',
        remediation: 'Yetki kontrolünü her uç noktada sunucu tarafında, varsayılan olarak reddeden merkezi bir mekanizmayla yapın. Arayüzde düğmeleri gizlemek yetki kontrolü değildir.' },
      en: { title: 'Privilege escalation (missing authorization check)',
        description: 'A function or endpoint meant for privileged roles can also be called by a lower-privileged user.',
        impact: 'Low-privileged users can perform administrative actions and change data and settings without authorization.',
        remediation: 'Enforce authorization on the server for every endpoint through a central, deny-by-default mechanism. Hiding buttons in the UI is not access control.' } },
    { id: 'csrf', group: 'session', test_id: 'WSTG-SESS-05', cwe: 'CWE-352', owasp: 'A01:2025 Broken Access Control', severity: 'medium',
      refs: [CS + 'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html', cwe(352)],
      tr: { title: 'Siteler arası istek sahteciliği (CSRF)',
        description: 'Durum değiştiren bir istek, isteğin kullanıcının kendi isteğiyle gönderildiğini doğrulayan bir belirteç ya da kontrol olmadan kabul ediliyor.',
        impact: 'Oturumu açık kullanıcının, ziyaret ettiği başka bir site aracılığıyla habersizce işlem yapmaya zorlanması.',
        remediation: 'Durum değiştiren tüm isteklerde CSRF belirteci kullanın ya da framework korumasını açın; oturum çerezlerinde SameSite=Lax veya Strict kullanın. Durum değiştiren işlemleri GET ile yapmayın.' },
      en: { title: 'Cross-site request forgery (CSRF)',
        description: 'A state-changing request is accepted without a token or check proving that the user intentionally sent it.',
        impact: 'A logged-in user can be made to perform actions unknowingly via another site they visit.',
        remediation: 'Use CSRF tokens (or the framework\'s built-in protection) on every state-changing request and set SameSite=Lax or Strict on session cookies. Never change state with GET requests.' } },
    { id: 'cookie-flags', group: 'session', test_id: 'WSTG-SESS-02', cwe: 'CWE-614', owasp: 'A02:2025 Security Misconfiguration', severity: 'low',
      refs: [CS + 'Session_Management_Cheat_Sheet.html', cwe(614)],
      tr: { title: 'Oturum çerezinde güvenlik bayrakları eksik',
        description: 'Oturum çerezi Secure, HttpOnly ve/veya SameSite özellikleri olmadan gönderiliyor.',
        impact: 'Çerezin şifresiz bağlantı üzerinden sızması, XSS ile JavaScript tarafından okunması ve siteler arası isteklerde gönderilmesi.',
        remediation: 'Oturum çerezlerini Secure, HttpOnly ve SameSite=Lax (ya da Strict) ile ayarlayın; mümkünse __Host- önekini kullanın.' },
      en: { title: 'Missing security flags on the session cookie',
        description: 'The session cookie is sent without the Secure, HttpOnly and/or SameSite attributes.',
        impact: 'The cookie can leak over unencrypted connections, be read by JavaScript through XSS and be sent with cross-site requests.',
        remediation: 'Set session cookies with Secure, HttpOnly and SameSite=Lax (or Strict); use the __Host- prefix where possible.' } },
    { id: 'session-fixation', group: 'session', test_id: 'WSTG-SESS-03', cwe: 'CWE-384', owasp: 'A07:2025 Authentication Failures', severity: 'medium',
      refs: [CS + 'Session_Management_Cheat_Sheet.html', cwe(384)],
      tr: { title: 'Oturum sabitleme (session fixation)',
        description: 'Kullanıcı giriş yaptığında oturum kimliği yenilenmiyor; girişten önce bilinen kimlik girişten sonra da geçerli kalıyor.',
        impact: 'Kurbana önceden belirlenmiş bir oturum kimliği kullandırılarak giriş sonrası hesabının ele geçirilmesi.',
        remediation: 'Başarılı girişten (ve yetki değişikliğinden) sonra yeni bir oturum kimliği üretin ve eskisini geçersiz kılın; URL\'de oturum kimliği kabul etmeyin.' },
      en: { title: 'Session fixation',
        description: 'The session identifier is not renewed on login; an identifier known before login remains valid afterwards.',
        impact: 'Account takeover after login by making the victim use a session identifier chosen in advance.',
        remediation: 'Issue a new session identifier after successful login (and any privilege change) and invalidate the old one; do not accept session identifiers in URLs.' } },
    { id: 'logout', group: 'session', test_id: 'WSTG-SESS-06', cwe: 'CWE-613', owasp: 'A07:2025 Authentication Failures', severity: 'medium',
      refs: [CS + 'Session_Management_Cheat_Sheet.html', cwe(613)],
      tr: { title: 'Çıkışta oturum sonlandırılmıyor',
        description: 'Kullanıcı çıkış yaptıktan sonra eski oturum kimliği (ya da belirteci) sunucu tarafında geçerli kalmaya devam ediyor.',
        impact: 'Ele geçirilmiş ya da paylaşılan bir bilgisayarda kalmış oturumun çıkıştan sonra da kullanılabilmesi.',
        remediation: 'Çıkışta oturumu sunucu tarafında geçersiz kılın; belirteç kullanılıyorsa iptal listesi ya da kısa ömür uygulayın. Hareketsizlik ve mutlak oturum süresi tanımlayın.' },
      en: { title: 'Session not terminated on logout',
        description: 'After the user logs out, the old session identifier (or token) remains valid on the server.',
        impact: 'A stolen session, or one left on a shared computer, can still be used after logout.',
        remediation: 'Invalidate the session on the server at logout; for tokens, use revocation or short lifetimes. Define idle and absolute session timeouts.' } },
    { id: 'creds-http', group: 'auth', test_id: 'WSTG-ATHN-01', cwe: 'CWE-319', owasp: 'A04:2025 Cryptographic Failures', severity: 'high',
      refs: [CS + 'Transport_Layer_Security_Cheat_Sheet.html', cwe(319)],
      tr: { title: 'Kimlik bilgileri şifresiz kanal üzerinden gönderiliyor',
        description: 'Giriş formu ya da kimlik bilgisi içeren istekler HTTP (TLS olmadan) üzerinden gönderiliyor.',
        impact: 'Aynı ağdaki bir saldırganın kullanıcı adı, parola ve oturum bilgilerini ele geçirmesi.',
        remediation: 'Tüm uygulamayı yalnızca HTTPS üzerinden sunun, HTTP isteklerini HTTPS\'e yönlendirin ve HSTS başlığı ekleyin.' },
      en: { title: 'Credentials sent over an unencrypted channel',
        description: 'The login form or requests carrying credentials are sent over HTTP (without TLS).',
        impact: 'An attacker on the same network can capture usernames, passwords and session data.',
        remediation: 'Serve the entire application over HTTPS only, redirect HTTP to HTTPS and add an HSTS header.' } },
    { id: 'default-creds', group: 'auth', test_id: 'WSTG-ATHN-02', cwe: 'CWE-1392', owasp: 'A07:2025 Authentication Failures', severity: 'high',
      refs: [CS + 'Authentication_Cheat_Sheet.html', cwe(1392)],
      tr: { title: 'Varsayılan kimlik bilgileri kullanılıyor',
        description: 'Uygulamada ya da bir yönetim arayüzünde üreticinin varsayılan kullanıcı adı ve parolasıyla giriş yapılabiliyor.',
        impact: 'İlgili arayüzün tamamen ele geçirilmesi.',
        remediation: 'Varsayılan hesapları kaldırın ya da ilk kurulumda parola değişikliğini zorunlu tutun; yönetim arayüzlerini internete kapatın.' },
      en: { title: 'Default credentials in use',
        description: 'It is possible to log in to the application or an administrative interface with the vendor\'s default username and password.',
        impact: 'Full takeover of the affected interface.',
        remediation: 'Remove default accounts or force a password change on first setup; do not expose administrative interfaces to the internet.' } },
    { id: 'no-lockout', group: 'auth', test_id: 'WSTG-ATHN-03', cwe: 'CWE-307', owasp: 'A07:2025 Authentication Failures', severity: 'medium',
      refs: [CS + 'Authentication_Cheat_Sheet.html', cwe(307)],
      tr: { title: 'Kaba kuvvet denemelerine karşı koruma yok',
        description: 'Giriş uç noktası, art arda yapılan başarısız denemeleri sınırlamıyor ya da yavaşlatmıyor.',
        impact: 'Parola tahmini ve sızdırılmış parola listeleriyle (credential stuffing) hesapların ele geçirilmesi.',
        remediation: 'Başarısız denemeleri hesap ve IP bazında sınırlayın, giderek artan bekleme süresi uygulayın; şüpheli durumlarda CAPTCHA ya da çok faktörlü doğrulama isteyin.' },
      en: { title: 'No protection against brute-force attempts',
        description: 'The login endpoint does not limit or slow down repeated failed attempts.',
        impact: 'Account takeover through password guessing and credential stuffing.',
        remediation: 'Rate-limit failed attempts per account and per IP with increasing delays; require CAPTCHA or multi-factor authentication when activity looks suspicious.' } },
    { id: 'weak-password', group: 'auth', test_id: 'WSTG-ATHN-07', cwe: 'CWE-521', owasp: 'A07:2025 Authentication Failures', severity: 'medium',
      refs: [CS + 'Authentication_Cheat_Sheet.html', cwe(521)],
      tr: { title: 'Zayıf parola politikası',
        description: 'Uygulama çok kısa ya da yaygın parolaların (ör. "123456") belirlenmesine izin veriyor.',
        impact: 'Hesapların tahmin ve sızdırılmış parola listeleriyle kolayca ele geçirilmesi.',
        remediation: 'En az 8 (tercihen 12+) karakter isteyin, sızdırılmış ve yaygın parolaları engelleyin, uzun parolalara izin verin; çok faktörlü doğrulama sunun.' },
      en: { title: 'Weak password policy',
        description: 'The application allows very short or common passwords (e.g. "123456").',
        impact: 'Accounts are easily compromised through guessing and leaked password lists.',
        remediation: 'Require at least 8 (preferably 12+) characters, block breached and common passwords, allow long passphrases and offer multi-factor authentication.' } },
    { id: 'hsts', group: 'config', test_id: 'WSTG-CONF-07', cwe: 'CWE-319', owasp: 'A02:2025 Security Misconfiguration', severity: 'low',
      refs: [CS + 'HTTP_Strict_Transport_Security_Cheat_Sheet.html', cwe(319)],
      tr: { title: 'HTTP Strict Transport Security (HSTS) başlığı eksik',
        description: 'HTTPS yanıtlarında Strict-Transport-Security başlığı bulunmuyor.',
        impact: 'Kullanıcının ilk isteğinin HTTP üzerinden gitmesi; SSL stripping gibi saldırılarla trafiğin şifresiz kanala düşürülmesi.',
        remediation: 'HTTPS yanıtlarına "Strict-Transport-Security: max-age=31536000; includeSubDomains" başlığını ekleyin; uygunsa preload listesine başvurun.' },
      en: { title: 'Missing HTTP Strict Transport Security (HSTS) header',
        description: 'HTTPS responses do not include the Strict-Transport-Security header.',
        impact: 'The user\'s first request may go over HTTP, and traffic can be downgraded to an unencrypted channel (e.g. SSL stripping).',
        remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to HTTPS responses and consider HSTS preloading.' } },
    { id: 'weak-tls', group: 'config', test_id: 'WSTG-CRYP-01', cwe: 'CWE-326', owasp: 'A04:2025 Cryptographic Failures', severity: 'medium',
      refs: [CS + 'Transport_Layer_Security_Cheat_Sheet.html', cwe(326)],
      tr: { title: 'Zayıf TLS yapılandırması',
        description: 'Sunucu eski protokolleri (ör. TLS 1.0/1.1) ya da zayıf şifreleme takımlarını kabul ediyor.',
        impact: 'Trafiğin çözülmesi ya da değiştirilmesi riskinin artması; uyumluluk gereksinimlerinin karşılanmaması.',
        remediation: 'Yalnızca TLS 1.2 ve 1.3\'ü etkinleştirin; ileri gizlilik (forward secrecy) sağlayan güçlü şifreleme takımlarını kullanın, eskileri kapatın.' },
      en: { title: 'Weak TLS configuration',
        description: 'The server accepts legacy protocols (e.g. TLS 1.0/1.1) or weak cipher suites.',
        impact: 'Higher risk of traffic being decrypted or modified; compliance requirements are not met.',
        remediation: 'Enable only TLS 1.2 and 1.3; use strong cipher suites with forward secrecy and disable legacy ones.' } },
    { id: 'stack-trace', group: 'config', test_id: 'WSTG-ERRH-02', cwe: 'CWE-209', owasp: 'A10:2025 Mishandling of Exceptional Conditions', severity: 'low',
      refs: [CS + 'Error_Handling_Cheat_Sheet.html', cwe(209)],
      tr: { title: 'Ayrıntılı hata mesajı ve yığın izi (stack trace)',
        description: 'Beklenmeyen bir girdide uygulama; yığın izi, dosya yolları, sorgu ya da sürüm bilgisi içeren ayrıntılı bir hata mesajı döndürüyor.',
        impact: 'Saldırganın kullanılan teknolojiler ve iç yapı hakkında başka saldırıları kolaylaştıran bilgi edinmesi.',
        remediation: 'Kullanıcıya genel bir hata mesajı ve hata kimliği gösterin; ayrıntıları yalnızca sunucu günlüklerine yazın. Üretimde hata ayıklama modunu kapatın.' },
      en: { title: 'Verbose error message and stack trace',
        description: 'On unexpected input the application returns a detailed error containing a stack trace, file paths, queries or version information.',
        impact: 'The attacker learns about the technologies and internals, which makes further attacks easier.',
        remediation: 'Show users a generic error message with an error ID and write details only to server logs. Disable debug mode in production.' } },
    { id: 'server-banner', group: 'config', test_id: 'WSTG-INFO-02', cwe: 'CWE-200', owasp: 'A02:2025 Security Misconfiguration', severity: 'info',
      refs: [CS + 'HTTP_Headers_Cheat_Sheet.html', cwe(200)],
      tr: { title: 'Sunucu ve yazılım sürümü ifşası',
        description: 'Yanıt başlıkları (ör. Server, X-Powered-By) kullanılan yazılımın adını ve sürümünü açıklıyor.',
        impact: 'Saldırganın bilinen açıkları hedefleyebilmesi için keşfi kolaylaştırır; tek başına doğrudan risk oluşturmaz.',
        remediation: 'Sürüm bilgisi içeren başlıkları kaldırın ya da genelleştirin; yazılımları güncel tutun.' },
      en: { title: 'Server and software version disclosure',
        description: 'Response headers (e.g. Server, X-Powered-By) reveal the name and version of the software in use.',
        impact: 'Makes reconnaissance easier for targeting known vulnerabilities; not a direct risk on its own.',
        remediation: 'Remove or generalize headers that reveal versions and keep software up to date.' } },
    { id: 'backup-files', group: 'config', test_id: 'WSTG-CONF-04', cwe: 'CWE-530', owasp: 'A02:2025 Security Misconfiguration', severity: 'medium',
      refs: [cwe(530)],
      tr: { title: 'Yedek ve unutulmuş dosyalara erişilebiliyor',
        description: 'Web kökünde yedek, eski ya da geçici dosyalar (ör. .bak, .old, .zip, .git) herkes tarafından indirilebiliyor.',
        impact: 'Kaynak kodun, yapılandırmanın ve içindeki kimlik bilgilerinin sızması.',
        remediation: 'Yedek ve geçici dosyaları web kökünden kaldırın; dağıtımda yalnızca gereken dosyaları yayınlayın; sunucuda bu uzantılara ve gizli klasörlere erişimi engelleyin.' },
      en: { title: 'Backup and unreferenced files are accessible',
        description: 'Backup, old or temporary files in the web root (e.g. .bak, .old, .zip, .git) can be downloaded by anyone.',
        impact: 'Leakage of source code, configuration and the credentials they contain.',
        remediation: 'Remove backup and temporary files from the web root, deploy only the files that are needed, and block access to such extensions and hidden directories on the server.' } },
    { id: 'open-redirect', group: 'client', test_id: 'WSTG-CLNT-04', cwe: 'CWE-601', owasp: 'A01:2025 Broken Access Control', severity: 'medium',
      refs: [CS + 'Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html', cwe(601)],
      tr: { title: 'Doğrulanmamış yönlendirme (open redirect)',
        description: 'Uygulama, kullanıcının verdiği bir adrese doğrulama yapmadan yönlendiriyor.',
        impact: 'Güvenilir alan adı üzerinden kimlik avı sayfalarına yönlendirme; bazı akışlarda belirteçlerin sızması.',
        remediation: 'Yönlendirme hedeflerini izin listesiyle sınırlayın ya da yalnızca uygulama içi göreli yollara izin verin; kullanıcıdan tam URL almayın.' },
      en: { title: 'Unvalidated redirect (open redirect)',
        description: 'The application redirects to a user-supplied address without validation.',
        impact: 'Phishing via a trusted domain; in some flows, leakage of tokens.',
        remediation: 'Restrict redirect targets with an allow-list or allow only relative in-app paths; do not accept full URLs from users.' } },
    { id: 'clickjacking', group: 'client', test_id: 'WSTG-CLNT-09', cwe: 'CWE-1021', owasp: 'A02:2025 Security Misconfiguration', severity: 'low',
      refs: [CS + 'Clickjacking_Defense_Cheat_Sheet.html', cwe(1021)],
      tr: { title: 'Tıklama korsanlığına (clickjacking) karşı koruma yok',
        description: 'Sayfalar başka bir sitedeki iframe içinde yüklenebiliyor; X-Frame-Options ya da CSP frame-ancestors tanımlı değil.',
        impact: 'Kullanıcının, görünmez bir çerçeve içindeki düğmelere habersizce tıklatılarak işlem yapması.',
        remediation: 'Content-Security-Policy: frame-ancestors \'self\' (ya da \'none\') ekleyin; eski tarayıcılar için X-Frame-Options: DENY veya SAMEORIGIN kullanın.' },
      en: { title: 'No protection against clickjacking',
        description: 'Pages can be loaded inside an iframe on another site; neither X-Frame-Options nor CSP frame-ancestors is set.',
        impact: 'Users can be tricked into clicking buttons inside an invisible frame and performing actions.',
        remediation: 'Add Content-Security-Policy: frame-ancestors \'self\' (or \'none\'); for older browsers also send X-Frame-Options: DENY or SAMEORIGIN.' } },
    { id: 'cors', group: 'client', test_id: 'WSTG-CLNT-07', cwe: 'CWE-942', owasp: 'A02:2025 Security Misconfiguration', severity: 'medium',
      refs: [cwe(942)],
      tr: { title: 'Gevşek CORS yapılandırması',
        description: 'Sunucu, isteğin Origin başlığını Access-Control-Allow-Origin olarak geri yansıtıyor (ya da "null" kökeni kabul ediyor) ve kimlik bilgili isteklere izin veriyor.',
        impact: 'Kullanıcının ziyaret ettiği kötü niyetli bir sitenin, kullanıcının oturumuyla API\'den veri okuması.',
        remediation: 'İzin verilen kökenleri sabit bir izin listesiyle tanımlayın; Origin değerini yansıtmayın, "null" kökeni kabul etmeyin; kimlik bilgili isteklere yalnızca gerekli kökenler için izin verin.' },
      en: { title: 'Permissive CORS configuration',
        description: 'The server reflects the request\'s Origin header in Access-Control-Allow-Origin (or accepts the "null" origin) and allows credentialed requests.',
        impact: 'A malicious site visited by the user can read API data using the user\'s session.',
        remediation: 'Define allowed origins with a fixed allow-list; do not reflect the Origin value or accept "null"; allow credentialed requests only for the origins that need them.' } }
  ];

  function localized(tpl, lang){
    const text = tpl[lang === 'en' ? 'en' : 'tr'];
    return {
      id: tpl.id, group: tpl.group, test_id: tpl.test_id, cwe: tpl.cwe, owasp_category: tpl.owasp,
      severity: tpl.severity, references: tpl.refs.join('\n'),
      title: text.title, description: text.description, impact: text.impact, remediation: text.remediation
    };
  }

  function list(lang){
    return TEMPLATES.map(tpl => localized(tpl, lang));
  }

  function get(id, lang){
    const tpl = TEMPLATES.find(x => x.id === id);
    return tpl ? localized(tpl, lang) : null;
  }

  function groupLabel(group, lang){
    const g = GROUPS[group];
    return g ? g[lang === 'en' ? 'en' : 'tr'] : group;
  }

  // Şablonu forma uygular: yalnızca boş alanlar doldurulur, kullanıcının
  // yazdığı hiçbir şey silinmez. { values, filled: [alan adları] } döner.
  const FILLABLE = ['title', 'test_id', 'cwe', 'owasp_category', 'description', 'impact', 'remediation', 'references'];
  function applyToForm(current, tpl){
    const values = Object.assign({}, current);
    const filled = [];
    FILLABLE.forEach(key => {
      if(tpl[key] && !String(values[key] || '').trim()){
        values[key] = tpl[key];
        filled.push(key);
      }
    });
    if(tpl.severity && !values.severity){ values.severity = tpl.severity; filled.push('severity'); }
    return { values, filled };
  }

  return { GROUPS: Object.keys(GROUPS), list, get, groupLabel, applyToForm, FILLABLE };
});
