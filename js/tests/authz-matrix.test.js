// Çalıştırma: node --test js/tests/*.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const AZ = require('../authz-matrix.js');

function doc(){
  return {
    roles: [{ id: 'anon', name: 'Anonim' }, { id: 'user', name: 'Kullanıcı' }, { id: 'admin', name: 'Yönetici' }],
    endpoints: [
      { id: 'e1', method: 'GET', path: '/api/admin/users', note: '' },
      { id: 'e2', method: 'GET', path: '/api/orders/{id}', note: '' },
    ],
    cells: {
      'e1:anon': { expected: 'deny', observed: 'denied' },
      'e1:user': { expected: 'deny', observed: 'allowed', note: '200 OK' },
      'e1:admin': { expected: 'allow', observed: 'allowed' },
      'e2:anon': { expected: 'deny', observed: 'allowed' },
      'e2:user': { expected: 'allow', observed: 'denied' },
      'e2:admin': { expected: 'allow', observed: null },
    },
  };
}

test('cellStatus', () => {
  assert.equal(AZ.cellStatus({ expected: 'deny', observed: 'allowed' }), 'violation');
  assert.equal(AZ.cellStatus({ expected: 'allow', observed: 'denied' }), 'over');
  assert.equal(AZ.cellStatus({ expected: 'allow', observed: 'allowed' }), 'ok');
  assert.equal(AZ.cellStatus({ expected: 'deny', observed: 'denied' }), 'ok');
  assert.equal(AZ.cellStatus({ expected: 'deny', observed: null }), 'untested');
  assert.equal(AZ.cellStatus({ expected: null, observed: 'allowed' }), 'observed');
  assert.equal(AZ.cellStatus(undefined), 'unset');
});

test('summarize ve violations (backend ile aynı sayılar)', () => {
  assert.deepEqual(AZ.summarize(doc()), { cells: 6, tested: 5, violations: 2, over_restricted: 1, untested: 1 });
  assert.deepEqual(AZ.violations(doc()).map(v => v.key), ['e1:user', 'e2:anon']);
});

test('addEndpoints: normalize eder, tekrarları ve geçersizleri atlar', () => {
  const r = AZ.addEndpoints(doc(), [
    { method: 'get', path: 'api/profile' },          // başına / eklenir
    { method: 'GET', path: '/api/admin/users' },      // zaten var
    { method: 'POST', path: '/api/admin/users' },     // farklı metot -> yeni
    { method: 'BREW', path: '/x' },                   // geçersiz metot
    { method: 'GET', path: '   ' },                   // boş
    { path: 'https://api.acme.test/v1/me' },          // tam URL olduğu gibi
  ]);
  assert.equal(r.added, 3);
  assert.equal(r.skipped, 3);
  assert.deepEqual(r.doc.endpoints.slice(2).map(e => `${e.method} ${e.path}`),
    ['GET /api/profile', 'POST /api/admin/users', 'GET https://api.acme.test/v1/me']);
  assert.equal(doc().endpoints.length, 2, 'girdi belgesi değişmemeli');
});

test('findingDraft: yalnızca yönetici izinliyse ATHZ-03, değilse ATHZ-02', () => {
  const d = doc();
  const [vUser, vAnon] = AZ.violations(d);
  const f1 = AZ.findingDraft(d, vUser, 'tr');
  assert.equal(f1.test_id, 'WSTG-ATHZ-03');          // e1'e sadece Yönetici izinli
  assert.equal(f1.severity, 'high');
  assert.equal(f1.endpoint, '/api/admin/users');
  assert.match(f1.title, /"Kullanıcı" rolü GET \/api\/admin\/users/);
  assert.match(f1.description, /Test notu: 200 OK/);
  assert.match(f1.description, /- Yönetici: beklenen İzinli, gözlenen Erişti/);
  const f2 = AZ.findingDraft(d, vAnon, 'en');
  assert.equal(f2.test_id, 'WSTG-ATHZ-02');          // e2'ye Kullanıcı da izinli
  assert.match(f2.title, /^Unauthorized access: "Anonim" role on GET \/api\/orders\/\{id\}$/);
});

test('toCsv: rol sütunları, formül enjeksiyonu koruması', () => {
  const d = doc();
  d.roles[0].name = '=HYPERLINK("http://x")';
  const csv = AZ.toCsv(d, { allow: 'İzinli', deny: 'Yasak', allowed: 'Erişti', denied: 'Engellendi', none: '—' }).split('\n');
  assert.equal(csv[0], `Method,Path,"'=HYPERLINK(""http://x"")",Kullanıcı,Yönetici`);
  assert.equal(csv[1], 'GET,/api/admin/users,Yasak / Engellendi,Yasak / Erişti,İzinli / Erişti');
  assert.equal(csv[2], 'GET,/api/orders/{id},Yasak / Erişti,İzinli / Engellendi,İzinli / —');
});

test('defaultRoles ve newId', () => {
  assert.deepEqual(AZ.defaultRoles('tr').map(r => r.name), ['Anonim', 'Kullanıcı', 'Yönetici']);
  assert.deepEqual(AZ.defaultRoles('en').map(r => r.name), ['Anonymous', 'User', 'Admin']);
  const a = AZ.newId('e'), b = AZ.newId('e');
  assert.match(a, /^e[a-z0-9]{1,23}$/);
  assert.notEqual(a, b);
});
