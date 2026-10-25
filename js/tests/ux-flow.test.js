const test = require('node:test');
const assert = require('node:assert');
const flow = require('../ux-flow.js');

test('başlangıç modu varsayılan olarak açıktır', () => {
  assert.strictEqual(flow.isBeginner(null), true);
  assert.strictEqual(flow.isBeginner(undefined), true);
  assert.strictEqual(flow.isBeginner('1'), true);
  assert.strictEqual(flow.isBeginner('0'), false);
});

test('gelişmiş sekmeler başlangıç modunda özete düşer', () => {
  for(const tab of ['timeline', 'kanban', 'chains', 'tools']){
    assert.strictEqual(flow.isAdvancedTab(tab), true, tab);
    assert.strictEqual(flow.resolveTab(tab, true), 'overview', tab);
    assert.strictEqual(flow.resolveTab(tab, false), tab, tab);
  }
  for(const tab of ['overview', 'scope', 'assets', 'wstg', 'authz', 'findings', 'evidence', 'reports', 'retest']){
    assert.strictEqual(flow.resolveTab(tab, true), tab, tab);
  }
  assert.strictEqual(flow.resolveTab('yok', false), 'overview');
  assert.strictEqual(flow.resolveTab(undefined, true), 'overview');
});

test('her bölüm bir pentest adımına bağlıdır', () => {
  const steps = new Set(flow.SECTIONS.filter(s => !s.advanced).map(s => s.step));
  assert.deepStrictEqual([...steps].sort(), [0, 1, 2, 3, 4, 5]);
});

test('hedef adresi kapsam kaydına çevrilir', () => {
  assert.deepStrictEqual(flow.parseTarget('example.com'), { url: 'https://example.com/', host: 'example.com', scopeType: 'domain' });
  assert.deepStrictEqual(flow.parseTarget('  https://App.Example.com/login?x=1 '),
    { url: 'https://app.example.com/login?x=1', host: 'app.example.com', scopeType: 'domain' });
  assert.strictEqual(flow.parseTarget('http://10.0.0.5:8080/').scopeType, 'ip');
  assert.strictEqual(flow.parseTarget('10.0.0.5').host, '10.0.0.5');
  assert.deepStrictEqual(flow.parseTarget('http://[::1]:5000/'), { url: 'http://[::1]:5000/', host: '::1', scopeType: 'ip' });
  assert.strictEqual(flow.parseTarget('localhost').scopeType, 'domain');
  assert.strictEqual(flow.parseTarget('example.com.').host, 'example.com');
});

test('geçersiz hedefler reddedilir', () => {
  for(const bad of ['', '   ', null, 'javascript:alert(1)', 'ftp://example.com', 'file:///etc/passwd',
    'exa mple.com', 'https://user:pw@example.com', '<script>', 'a..b', '-bad.com', '999.1.1.1', 'http://', 'x'.repeat(3000)]){
    assert.strictEqual(flow.parseTarget(bad), null, String(bad).slice(0, 40));
  }
});

test('sıradaki adım proje durumuna göre seçilir', () => {
  const base = { scope: 0, recon: 0, assets: 0, done: 0, total: 98, findings: 0, reported: false };
  const cases = [
    [{}, 'scope', 1],
    [{ scope: 1 }, 'recon', 2],
    [{ scope: 1, recon: 1 }, 'firstTest', 3],
    [{ scope: 1, done: 3 }, 'keepTesting', 3],            // keşif yapılmadan teste geçildi
    [{ scope: 1, reconSkipped: true }, 'firstTest', 3],   // keşif atlandı
    [{ scope: 1, done: 3, findings: 2 }, 'report', 5],
    [{ scope: 1, findings: 4 }, 'report', 5],             // bulgu var: keşif önerilmez
    [{ scope: 1, done: 3, findings: 2, reported: true }, 'retest', 5],
    [{ done: 5, findings: 1 }, 'scope', 1]                // kapsam her zaman önce
  ];
  for(const [st, action, step] of cases){
    const r = flow.projectSteps(Object.assign({}, base, st));
    assert.strictEqual(r.action, action, JSON.stringify(st));
    assert.strictEqual(r.currentStep, step, JSON.stringify(st));
    assert.strictEqual(r.steps.filter(s => s.current).length, 1);
  }
});

test('adım durumları', () => {
  const r = flow.projectSteps({ scope: 1, done: 98, total: 98, findings: 1 });
  assert.deepStrictEqual(r.steps.map(s => s.state), ['done', 'done', 'done', 'done', 'current']);
  const empty = flow.projectSteps(null);
  assert.deepStrictEqual(empty.steps.map(s => s.state), ['current', 'todo', 'todo', 'todo', 'todo']);
});

test('ilk tamamlanmamış test', () => {
  const cats = [{ id: 'a', tests: [{ id: 'T1', title: 'Bir' }, { id: 'T2', title: 'İki' }] }, { id: 'b', tests: [{ id: 'T3', title: 'Üç' }] }];
  assert.deepStrictEqual(flow.firstPendingTest(cats, { T1: true }), { catId: 'a', testId: 'T2', title: 'İki' });
  assert.deepStrictEqual(flow.firstPendingTest(cats, { T1: true, T2: true }).testId, 'T3');
  assert.strictEqual(flow.firstPendingTest(cats, { T1: 1, T2: 1, T3: 1 }), null);
  assert.strictEqual(flow.firstPendingTest(null, null), null);
});

test('WSTG kodları açıklanır', () => {
  assert.match(flow.explainCode('WSTG-ATHN-03', 'tr'), /ATHN = Authentication \(Kimlik Doğrulama\) · 03 = bu kategorideki 3\. test/);
  assert.match(flow.explainCode('wstg-inpv', 'en'), /^WSTG = OWASP Web Security Testing Guide · INPV = Input Validation$/);
  for(const bad of ['LLM01', 'WSTG-XXXX-01', '', null, 'WSTG-ATHN-03<script>']) assert.strictEqual(flow.explainCode(bad, 'tr'), null);
});

test('bulgular önem derecesine göre sıralanır ve filtrelenir', () => {
  const list = [
    { id: 1, title: 'Ürün aramasında XSS', severity: 'high', status: 'open', cvss_score: 7.1, endpoint: '/search' },
    { id: 2, title: 'IDOR', severity: 'critical', status: 'confirmed', cvss_score: 9.1, finding_code: 'FND-0002' },
    { id: 3, title: 'Çerez bayrağı', severity: 'low', status: 'fixed' },
    { id: 4, title: 'Başka XSS', severity: 'high', status: 'open', cvss_score: 8.2, test_id: 'WSTG-INPV-02' },
    { id: 5, title: 'Sürüm bilgisi', severity: 'info', status: 'open' }
  ];
  assert.deepStrictEqual(flow.filterFindings(list).map(f => f.id), [2, 4, 1, 3, 5]);
  assert.deepStrictEqual(flow.filterFindings(list, { sort: 'newest' }).map(f => f.id), [5, 4, 3, 2, 1]);
  assert.deepStrictEqual(flow.filterFindings(list, { severity: 'high' }).map(f => f.id), [4, 1]);
  assert.deepStrictEqual(flow.filterFindings(list, { status: 'open', severity: 'info' }).map(f => f.id), [5]);
  assert.deepStrictEqual(flow.filterFindings(list, { q: 'xss' }).map(f => f.id), [4, 1]);
  assert.deepStrictEqual(flow.filterFindings(list, { q: 'urun' }).map(f => f.id), [1]);      // aksan duyarsız
  assert.deepStrictEqual(flow.filterFindings(list, { q: 'ÇEREZ' }).map(f => f.id), [3]);
  assert.deepStrictEqual(flow.filterFindings(list, { q: 'fnd-0002' }).map(f => f.id), [2]);
  assert.deepStrictEqual(flow.filterFindings(list, { q: 'inpv' }).map(f => f.id), [4]);
  assert.deepStrictEqual(flow.filterFindings(null), []);
  assert.strictEqual(list[0].id, 1);   // girdi dizisi değişmez
});
