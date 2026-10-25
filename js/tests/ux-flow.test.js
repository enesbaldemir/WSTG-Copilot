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
