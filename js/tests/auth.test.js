// Çalıştırma: node --test js/tests/*.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const A = require('../auth.js');

test('API host follows the page host so the session cookie is same-site', () => {
  assert.equal(A.apiBaseFor({ protocol: 'http:', hostname: '127.0.0.1' }), 'http://127.0.0.1:5000/api');
  assert.equal(A.apiBaseFor({ protocol: 'http:', hostname: 'localhost' }), 'http://localhost:5000/api');
  assert.equal(A.apiBaseFor({ protocol: 'https:', hostname: 'pentest.lan' }), 'https://pentest.lan:5000/api');
});

test('IPv6 hosts are bracketed exactly once', () => {
  assert.equal(A.apiBaseFor({ protocol: 'http:', hostname: '[::1]' }), 'http://[::1]:5000/api');
  assert.equal(A.apiBaseFor({ protocol: 'http:', hostname: '::1' }), 'http://[::1]:5000/api');
});

test('host-less pages fall back to the previous default', () => {
  assert.equal(A.apiBaseFor({ protocol: 'file:', hostname: '' }), 'http://localhost:5000/api');
  assert.equal(A.apiBaseFor(undefined), 'http://localhost:5000/api');
});

test('custom port', () => {
  assert.equal(A.apiBaseFor({ protocol: 'http:', hostname: '127.0.0.1' }, 5050), 'http://127.0.0.1:5050/api');
});

test('only the login gate 401 counts as a lost session', () => {
  assert.equal(A.isSessionLost(401, { code: 'auth_required' }), true);
  assert.equal(A.isSessionLost(401, { code: 'invalid_password' }), false);
  assert.equal(A.isSessionLost(401, null), false);
  assert.equal(A.isSessionLost(403, { code: 'auth_required' }), false);
});

test('every backend error code maps to an i18n key present in both languages', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const tr = src.slice(src.indexOf('tr: {'), src.indexOf('en: {'));
  const en = src.slice(src.indexOf('en: {'));
  for(const key of Object.values(A.ERROR_KEYS)){
    assert.match(tr, new RegExp(`\\b${key}:`), `TR missing ${key}`);
    assert.match(en, new RegExp(`\\b${key}:`), `EN missing ${key}`);
  }
  assert.equal(A.errorKey('nope'), null);
});
