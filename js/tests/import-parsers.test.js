// Çalıştırma: node --test js/tests/*.test.js
// Burp Suite / OWASP ZAP içe aktarmanın DOM'suz kısmı. XML okuma
// (DOMParser) tarayıcıda uçtan uca denenir; burada eşleme, metin
// temizleme ve normalleştirme test edilir.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const IMP = require('../import-parsers.js');

const DATA = path.join(__dirname, '..', '..', 'data');
function wstgIds(lang) {
  const d = JSON.parse(fs.readFileSync(path.join(DATA, `wstg-checklist.${lang}.json`), 'utf8'));
  return new Set(d.categories.flatMap(c => c.tests.map(t => t.id)));
}

test('eşleme tablolarındaki her WSTG ID checklist veri setinde var (TR ve EN)', () => {
  for (const lang of ['tr', 'en']) {
    const ids = wstgIds(lang);
    const used = [
      ...IMP.SCANNER_RULES.flatMap(r => r.ids),
      ...Object.values(IMP.CWE_TO_WSTG).flat(),
      ...IMP.KEYWORD_RULES.flatMap(r => r.ids),
      'WSTG-INFO-04',
    ];
    const missing = [...new Set(used)].filter(id => !ids.has(id));
    assert.deepEqual(missing, [], `${lang}: ${missing.join(', ')}`);
  }
});

test('gerçek Burp/ZAP sorun adları doğru WSTG maddesine gider', () => {
  const cases = [
    // Burp Suite
    ['Cross-site scripting (reflected)', 'WSTG-INPV-01'],
    ['Cross-site scripting (stored)', 'WSTG-INPV-02'],
    ['Cross-site scripting (DOM-based)', 'WSTG-CLNT-01'],
    ['Browser cross-site scripting filter disabled', 'WSTG-CONF-02'],
    ['SQL injection', 'WSTG-INPV-05'],
    ['OS command injection', 'WSTG-INPV-13'],
    ['File path traversal', 'WSTG-ATHZ-01'],
    ['XML external entity injection', 'WSTG-INPV-07'],
    ['External service interaction (DNS)', 'WSTG-INPV-20'],
    ['HTTP request smuggling', 'WSTG-INPV-16'],
    ['Host header poisoning', 'WSTG-INPV-18'],
    ['Cross-site request forgery', 'WSTG-SESS-05'],
    ['TLS cookie without secure flag set', 'WSTG-SESS-02'],
    ['Session token in URL', 'WSTG-SESS-04'],
    ['Open redirection (reflected)', 'WSTG-CLNT-04'],
    ['Frameable response (potential Clickjacking)', 'WSTG-CLNT-09'],
    ['Cross-origin resource sharing: arbitrary origin trusted', 'WSTG-CLNT-07'],
    ['Strict transport security not enforced', 'WSTG-CONF-07'],
    ['Cleartext submission of password', 'WSTG-ATHN-01'],
    ['Password field with autocomplete enabled', 'WSTG-ATHN-05'],
    ['Cacheable HTTPS response', 'WSTG-ATHN-06'],
    ['Unencrypted communications', 'WSTG-CRYP-03'],
    ['Vulnerable JavaScript dependency', 'WSTG-INFO-08'],
    ['Email addresses disclosed', 'WSTG-INFO-05'],
    // OWASP ZAP
    ['Cross Site Scripting (Persistent)', 'WSTG-INPV-02'],
    ['Cross Site Scripting (DOM Based)', 'WSTG-CLNT-01'],
    ['SQL Injection - SQLite', 'WSTG-INPV-05'],
    ['Remote OS Command Injection', 'WSTG-INPV-13'],
    ['Server Side Template Injection', 'WSTG-INPV-19'],
    ['Server Side Include', 'WSTG-INPV-08'],
    ['Server Side Request Forgery', 'WSTG-INPV-20'],
    ['Path Traversal', 'WSTG-ATHZ-01'],
    ['CRLF Injection', 'WSTG-INPV-16'],
    ['Absence of Anti-CSRF Tokens', 'WSTG-SESS-05'],
    ['Cookie No HttpOnly Flag', 'WSTG-SESS-02'],
    ['Cookie without SameSite Attribute', 'WSTG-SESS-02'],
    ['Session ID in URL Rewrite', 'WSTG-SESS-04'],
    ['Missing Anti-clickjacking Header', 'WSTG-CLNT-09'],
    ['Cross-Domain Misconfiguration', 'WSTG-CLNT-07'],
    ['Strict-Transport-Security Header Not Set', 'WSTG-CONF-07'],
    ['Content Security Policy (CSP) Header Not Set', 'WSTG-CONF-02'],
    ['X-Content-Type-Options Header Missing', 'WSTG-CONF-02'],
    ['Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)', 'WSTG-INFO-02'],
    ['Information Disclosure - Debug Error Messages', 'WSTG-ERRH-01'],
    ['Information Disclosure - Suspicious Comments', 'WSTG-INFO-05'],
    ['Application Error Disclosure', 'WSTG-ERRH-01'],
    ['Re-examine Cache-control Directives', 'WSTG-ATHN-06'],
    ['Secure Pages Include Mixed Content', 'WSTG-CRYP-03'],
    ['Vulnerable JS Library', 'WSTG-INFO-08'],
    ['Insecure HTTP Method', 'WSTG-CONF-06'],
  ];
  const wrong = cases.filter(([name, id]) => IMP.mapScannerIssue(name, null).testIds[0] !== id)
    .map(([name, id]) => `${name}: ${IMP.mapScannerIssue(name, null).testIds[0]} (beklenen ${id})`);
  assert.deepEqual(wrong, []);
});

test('ad eşleşmezse CWE, o da yoksa "kategori önerisi yok"', () => {
  assert.deepEqual(IMP.mapScannerIssue('Weird Plugin 9000', '918'), { testIds: ['WSTG-INPV-20'], unmatched: false });
  assert.deepEqual(IMP.mapScannerIssue('Weird Plugin 9000', 'CWE-639'), { testIds: ['WSTG-ATHZ-04'], unmatched: false });
  assert.deepEqual(IMP.mapScannerIssue('Modern Web Application', '-1'), { testIds: ['WSTG-INFO-04'], unmatched: true });
  assert.equal(IMP.mapScannerIssue('User Agent Fuzzer', '0').unmatched, true);
});

test('htmlToText: etiketleri ve script içeriğini atar, varlıkları çözer', () => {
  assert.equal(IMP.htmlToText('<p>A &amp; B</p><ul><li>bir</li><li>iki</li></ul>'), 'A & B\n• bir\n• iki');
  assert.equal(IMP.htmlToText('x<script>alert(1)</script>y<style>p{}</style>'), 'xy');
  assert.equal(IMP.htmlToText('&lt;img src=x onerror=alert(1)&gt; &#39;q&#39; &#x41;'), "<img src=x onerror=alert(1)> 'q' A");
  assert.equal(IMP.htmlToText('satır<br>satır2'), 'satır\nsatır2');
  assert.equal(IMP.htmlToText(null), '');
});

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }

test('normalizeBurpIssue: alanlar, parametre, CWE, kaynaklar, HTTP kanıtı', () => {
  const f = IMP.normalizeBurpIssue({
    name: 'SQL injection', host: 'https://portal.acme.test', path: '/login', location: '/login [username parameter]',
    severity: 'High', confidence: 'Firm',
    issueBackground: '<p>SQL injection vulnerabilities arise when…</p>',
    issueDetail: 'The <b>username</b> parameter appears to be vulnerable.',
    remediationBackground: '<p>Use parameterized queries.</p>',
    vulnerabilityClassifications: '<ul><li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: SQL Injection</a></li></ul>',
    references: '<ul><li><a href="https://portswigger.net/web-security/sql-injection">Web Security Academy</a></li></ul>',
    requestResponses: [{
      request: b64('POST /login HTTP/1.1\r\nHost: portal.acme.test\r\nCookie: sid=abc\r\n\r\nusername=a%27'), requestBase64: true,
      response: b64('HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\nSQL syntax error'), responseBase64: true,
    }],
  });
  assert.deepEqual(f.testIds, ['WSTG-INPV-05']);
  assert.equal(f.severity, 'high');
  assert.equal(f.pro.endpoint, 'https://portal.acme.test/login');
  assert.equal(f.pro.parameter, 'username');
  assert.equal(f.pro.cwe, 'CWE-89');
  assert.equal(f.pro.references, 'https://portswigger.net/web-security/sql-injection');
  assert.match(f.pro.description, /SQL injection vulnerabilities arise/);
  assert.match(f.pro.description, /Kaynak: Burp Suite \(güven: Firm\)/);
  assert.equal(f.pro.remediation, 'Use parameterized queries.');
  assert.match(f.http.request, /^POST \/login HTTP\/1\.1/);
  assert.match(f.http.response, /SQL syntax error/);
  assert.match(f.detail, /parametre: username/);
});

test('normalizeBurpIssue: Information -> info, false positive atlanır, ikili gövde saklanmaz', () => {
  const info = IMP.normalizeBurpIssue({ name: 'Email addresses disclosed', host: 'https://a.test', path: '/', severity: 'Information' });
  assert.equal(info.severity, 'info');
  assert.equal(info.http, undefined);
  assert.equal(IMP.normalizeBurpIssue({ name: 'x', severity: 'False positive' }), null);
  const png = Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 13])]);
  const bin = IMP.normalizeBurpIssue({ name: 'x', severity: 'Low', requestResponses: [{ response: png.toString('base64'), responseBase64: true }] });
  assert.match(bin.http.response, /^HTTP\/1\.1 200 OK/);
  assert.match(bin.http.response, /\[ikili içerik atlandı, \d+ bayt\]$/);
  assert.doesNotMatch(bin.http.response, /\u0000/);
});

const ZAP_JSON = {
  '@programName': 'ZAP', '@version': '2.15.0',
  site: [{
    '@name': 'https://portal.acme.test', '@host': 'portal.acme.test',
    alerts: [
      {
        pluginid: '40018', alert: 'SQL Injection', name: 'SQL Injection', riskcode: '3', confidence: '2',
        desc: '<p>SQL injection may be possible.</p>', solution: '<p>Do not trust client side input.</p>',
        otherinfo: '<p>The page results were successfully manipulated.</p>',
        reference: '<p>https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html</p>',
        cweid: '89', instances: [
          { uri: 'https://portal.acme.test/search?q=1', method: 'GET', param: 'q', attack: "1' OR '1'='1", evidence: '',
            'request-header': 'GET /search?q=1 HTTP/1.1\r\nHost: portal.acme.test\r\n', 'response-header': 'HTTP/1.1 200 OK\r\n', 'response-body': 'results' },
          { uri: 'https://portal.acme.test/list?id=2', method: 'GET', param: 'id' },
        ],
      },
      { pluginid: '10021', name: 'X-Content-Type-Options Header Missing', riskcode: '1', confidence: '2', desc: '<p>…</p>', cweid: '693',
        instances: [{ uri: 'https://portal.acme.test/', method: 'GET' }] },
      { pluginid: '10096', name: 'Timestamp Disclosure - Unix', riskcode: '0', confidence: '1', cweid: '200', instances: [] },
      { pluginid: '1', name: 'Yanlış pozitif', riskcode: '3', confidence: '0', cweid: '79', instances: [] },
    ],
  }],
};

test('parseZapJson: risk, güven, örnekler, CWE, HTTP; yanlış pozitif atlanır', () => {
  const fs_ = IMP.parseZapJson(JSON.stringify(ZAP_JSON));
  assert.equal(fs_.length, 3);
  const [sqli, xcto, ts] = fs_;
  assert.deepEqual(sqli.testIds, ['WSTG-INPV-05']);
  assert.equal(sqli.severity, 'high');
  assert.equal(sqli.pro.endpoint, 'https://portal.acme.test/search?q=1');
  assert.equal(sqli.pro.parameter, 'q');
  assert.equal(sqli.pro.cwe, 'CWE-89');
  assert.match(sqli.pro.description, /Etkilenen adresler:\n- GET https:\/\/portal\.acme\.test\/search\?q=1 \[q\]\n- GET https:\/\/portal\.acme\.test\/list\?id=2 \[id\]/);
  assert.match(sqli.pro.description, /Kaynak: OWASP ZAP \(güven: Medium\)/);
  assert.equal(sqli.pro.remediation, 'Do not trust client side input.');
  assert.match(sqli.pro.references, /^https:\/\/cheatsheetseries\.owasp\.org/);
  assert.match(sqli.http.request, /^GET \/search\?q=1 HTTP\/1\.1/);
  assert.match(sqli.http.response, /results$/);
  assert.equal(xcto.severity, 'low');
  assert.deepEqual(xcto.testIds, ['WSTG-CONF-02']);
  assert.equal(xcto.http, undefined);
  assert.equal(ts.severity, 'info');
  assert.equal(ts.pro.endpoint, 'https://portal.acme.test');
});

test('detectTool: Burp/ZAP biçimleri, mevcut araçlar etkilenmez', () => {
  const dtd = '<!DOCTYPE issues [' + '<!ELEMENT x (#PCDATA)>'.repeat(400) + ']>';
  assert.equal(IMP.detectTool(`<?xml version="1.0"?>\n${dtd}\n<issues burpVersion="2024.1"><issue></issue></issues>`, 'r.xml'), 'burp-xml');
  assert.equal(IMP.detectTool('<?xml version="1.0"?><OWASPZAPReport version="2.15.0"><site/></OWASPZAPReport>', 'z.xml'), 'zap-xml');
  assert.equal(IMP.detectTool(JSON.stringify(ZAP_JSON), 'zap.json'), 'zap-json');
  assert.equal(IMP.detectTool('<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>', 'a.xml'), 'nmap');
  assert.equal(IMP.detectTool(JSON.stringify({ version: { number: '6.0' }, plugins: {} }), 'w.json'), 'wpscan-json');
  assert.equal(IMP.parse(JSON.stringify(ZAP_JSON), 'auto', 'zap.json').tool, 'zap-json');
});
