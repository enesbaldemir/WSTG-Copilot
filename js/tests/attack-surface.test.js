// Çalıştırma: node --test js/tests/*.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const AS = require('../attack-surface.js');

// backend/models.py ReconRun.to_dict() ile aynı şekil
function run(overrides){
  return Object.assign({
    id: 1, project_id: 'p1', target: 'portal.acme.test', baseUrl: 'https://portal.acme.test',
    subdomains: ['portal.acme.test', 'api.portal.acme.test'],
    technologies: ['nginx', 'React'],
    endpoints: ['/login', '/api/v1/users', '/robots.txt'],
    apis: ['/api/v1/users'],
    interestingPaths: [{ path: '/robots.txt', status: 200 }],
    forms: [], cookiesPresent: true,
    suggestions: {
      'WSTG-ATHN-02': { level: 'high', reasons: ['Kimlik doğrulama sayfası bulundu: /login'] },
      'WSTG-APIT-01': { level: 'high', reasons: ['API endpoint bulundu: /api/v1/users'] },
      'WSTG-INFO-03': { level: 'info', reasons: ['Metafile incelenmeli: /robots.txt'] },
      'WSTG-SESS-02': { level: 'medium', reasons: ['Cookie kullanımı tespit edildi'] },
    },
    created_at: '2026-10-18T11:30:00.000000',
  }, overrides || {});
}

test('builds inventory only from recorded fields', () => {
  const s = AS.buildSurface({ runs: [run()] }, [], []);
  assert.deepEqual(s.counts, { domain: 1, subdomain: 1, endpoint: 3, api: 1, technology: 2, total: 7 });
  const robots = s.inventory.find(r => r.value === '/robots.txt');
  assert.equal(robots.record, 'http');
  assert.equal(robots.httpStatus, 200);
  assert.equal(s.inventory.find(r => r.value === '/login').record, 'link');
  assert.equal(s.inventory.find(r => r.value === 'api.portal.acme.test').record, 'resolved');
  // target itself is not duplicated as a subdomain
  assert.equal(s.inventory.filter(r => r.value === 'portal.acme.test').length, 1);
  // technologies never get a fabricated host relation or tests
  const react = s.inventory.find(r => r.value === 'React');
  assert.equal(react.target, 'portal.acme.test');
  assert.deepEqual(react.tests, []);
  assert.equal(react.scope, null);
});

test('endpoint -> WSTG relation is derived from recorded reasons and flagged', () => {
  const s = AS.buildSurface({ runs: [run()] }, [], ['WSTG-APIT-01']);
  const login = s.inventory.find(r => r.value === '/login');
  assert.deepEqual(login.tests.map(t => t.test_id), ['WSTG-ATHN-02']);
  assert.equal(login.tests[0].derived, true);
  const api = s.inventory.find(r => r.value === '/api/v1/users');
  assert.equal(api.tests[0].done, true);
  // reasons without a path (cookies) do not attach to any endpoint
  assert.ok(!s.inventory.some(r => (r.tests || []).some(t => t.test_id === 'WSTG-SESS-02')));
});

test('suggestions come from the latest run per target, done ones last', () => {
  const older = run({ id: 0, created_at: '2026-10-01T10:00:00', suggestions: { 'WSTG-CONF-04': { level: 'high', reasons: ['eski'] } } });
  const s = AS.buildSurface({ runs: [older, run()] }, [], ['WSTG-ATHN-02']);
  const ids = s.suggestions.map(x => x.test_id);
  assert.ok(!ids.includes('WSTG-CONF-04'), 'superseded run suggestions are not shown');
  assert.equal(ids[ids.length - 1], 'WSTG-ATHN-02');
  assert.equal(s.suggestions[0].level, 'high');
  assert.equal(s.lastScanAt, '2026-10-18T11:30:00.000Z');
  const login = s.inventory.find(r => r.value === '/login');
  assert.equal(login.firstSeen, '2026-10-01T10:00:00.000Z');
  assert.equal(login.lastSeen, '2026-10-18T11:30:00.000Z');
});

test('scope matching is conservative', () => {
  const items = [
    { type: 'domain', value: '*.acme.test', in_scope: true },
    { type: 'subdomain', value: 'admin.acme.test', in_scope: false },
    { type: 'cidr', value: '10.0.0.0/24', in_scope: true },
  ];
  assert.equal(AS.scopeStatus('portal.acme.test', items), 'in');
  assert.equal(AS.scopeStatus('acme.test', items), 'unknown'); // wildcard does not include apex
  assert.equal(AS.scopeStatus('admin.acme.test', items), 'out'); // out-of-scope wins
  assert.equal(AS.scopeStatus('10.0.0.9', items), 'in');
  assert.equal(AS.scopeStatus('10.0.1.9', items), 'unknown');
  assert.equal(AS.scopeStatus('x.test', []), 'undefined');
});

test('empty data and filters', () => {
  const empty = AS.buildSurface({ subdomains: [], technologies: [], endpoints: [], runs: [] }, [], []);
  assert.equal(empty.counts.total, 0);
  assert.equal(empty.lastScanAt, null);
  assert.deepEqual(empty.suggestions, []);
  const s = AS.buildSurface({ runs: [run()] }, [], []);
  assert.equal(AS.filterInventory(s.inventory, { type: 'endpoint' }).length, 3);
  assert.deepEqual(AS.filterInventory(s.inventory, { q: 'athn-02' }).map(r => r.value), ['/login']);
});
