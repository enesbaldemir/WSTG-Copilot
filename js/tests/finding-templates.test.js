const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const tpl = require('../finding-templates.js');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const checklistIds = lang => {
  const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', `wstg-checklist.${lang}.json`), 'utf8'));
  return new Set(data.categories.flatMap(c => c.tests.map(t => t.id)));
};
const top10 = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'owasp-top10.en.json'), 'utf8')).top10
  .map(r => `${r.id} ${r.title}`);

test('her şablon iki dilde eksiksiz ve tutarlı', () => {
  const tr = tpl.list('tr');
  const en = tpl.list('en');
  assert.ok(tr.length >= 20);
  assert.strictEqual(tr.length, en.length);
  const ids = new Set();
  tr.forEach((t, i) => {
    assert.ok(!ids.has(t.id), 'tekrarlanan id ' + t.id); ids.add(t.id);
    assert.strictEqual(t.id, en[i].id);
    for(const key of ['title', 'description', 'impact', 'remediation']){
      assert.ok(t[key] && t[key].length > 10, `${t.id} tr.${key}`);
      assert.ok(en[i][key] && en[i][key].length > 10, `${t.id} en.${key}`);
      assert.notStrictEqual(t[key], en[i][key], `${t.id} ${key} çevrilmemiş`);
    }
    assert.ok(SEVERITIES.includes(t.severity), t.id);
    assert.match(t.cwe, /^CWE-\d+$/);
    assert.ok(tpl.GROUPS.includes(t.group), t.id);
    assert.ok(t.references.split('\n').every(u => /^https:\/\/(cheatsheetseries\.owasp\.org|cwe\.mitre\.org)\//.test(u)), t.id);
  });
});

test('test ID\'leri checklist\'te, OWASP kategorileri Top 10:2025\'te var', () => {
  const idsTr = checklistIds('tr');
  const idsEn = checklistIds('en');
  tpl.list('tr').forEach(t => {
    assert.ok(idsTr.has(t.test_id) && idsEn.has(t.test_id), `${t.id}: ${t.test_id} checklist'te yok`);
    assert.ok(top10.includes(t.owasp_category), `${t.id}: ${t.owasp_category}`);
  });
});

test('şablon yalnızca boş alanları doldurur', () => {
  const sqli = tpl.get('sqli', 'tr');
  const r = tpl.applyToForm({ title: 'Benim başlığım', description: '', endpoint: '/login', severity: null }, sqli);
  assert.strictEqual(r.values.title, 'Benim başlığım');
  assert.strictEqual(r.values.endpoint, '/login');
  assert.strictEqual(r.values.description, sqli.description);
  assert.strictEqual(r.values.severity, 'critical');
  assert.ok(r.filled.includes('description') && !r.filled.includes('title'));
  const kept = tpl.applyToForm({ severity: 'low' }, sqli);
  assert.strictEqual(kept.values.severity, 'low');
  assert.strictEqual(tpl.get('yok', 'tr'), null);
  assert.strictEqual(tpl.get('idor', 'en').title, 'Insecure direct object reference (IDOR)');
  assert.strictEqual(tpl.groupLabel('auth', 'tr'), 'Kimlik doğrulama');
});
