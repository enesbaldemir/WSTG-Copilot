// Çalıştırma: node --test js/tests/*.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const NB = require('../notebook.js');

const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==';

test('isSafeImageDataUrl yalnızca raster base64 data-URL kabul eder', () => {
  assert.equal(NB.isSafeImageDataUrl(PNG), true);
  assert.equal(NB.isSafeImageDataUrl('data:image/jpeg;base64,/9j/4AAQ'), true);
  for (const bad of [
    'data:image/x" onerror="alert(1)',
    PNG + '" onerror="alert(1)',
    'data:image/svg+xml;base64,PHN2Zz4=',
    'data:image/png,<svg>',
    'javascript:alert(1)',
    'https://evil.test/a.png',
    ' ' + PNG,
    null, undefined, 42,
  ]) assert.equal(NB.isSafeImageDataUrl(bad), false, String(bad));
});

test('safeImages eski/güvensiz kayıtları ayıklar', () => {
  const out = NB.safeImages([{ name: 'ok', data: PNG }, { name: 'x', data: 'data:image/x" onerror=1' }, null, 'str']);
  assert.deepEqual(out.map(i => i.name), ['ok']);
  assert.deepEqual(NB.safeImages(undefined), []);
});

test('imageFileError tür ve boyutu kontrol eder', () => {
  assert.equal(NB.imageFileError({ type: 'image/png', size: 10 }), null);
  assert.equal(NB.imageFileError({ type: 'image/svg+xml', size: 10 }), 'type');
  assert.equal(NB.imageFileError({ type: 'image/webp', size: NB.MAX_IMAGE_BYTES + 1 }), 'size');
  assert.equal(NB.imageFileError(null), 'type');
});

test('filterNotes: genel/test filtresi, arama ve yeniden eskiye sıralama', () => {
  const notes = [
    { id: 1, title: 'Eski', test_id: 'WSTG-INPV-05', updated_at: '2026-10-01T10:00:00' },
    { id: 2, title: 'Genel', content: 'JWT alg none', test_id: null, updated_at: '2026-10-03T10:00:00' },
    { id: 3, title: 'Yeni', test_id: 'WSTG-INPV-05', cwe_id: 'CWE-89', updated_at: '2026-10-05T10:00:00' },
  ];
  assert.deepEqual(NB.filterNotes(notes, '').map(n => n.id), [3, 2, 1]);
  assert.deepEqual(NB.filterNotes(notes, '__general__').map(n => n.id), [2]);
  assert.deepEqual(NB.filterNotes(notes, 'WSTG-INPV-05').map(n => n.id), [3, 1]);
  assert.deepEqual(NB.filterNotes(notes, '', 'jwt').map(n => n.id), [2]);
  assert.deepEqual(NB.filterNotes(notes, '', 'cwe-89').map(n => n.id), [3]);
  assert.equal(notes[0].id, 1, 'girdi dizisi değiştirilmemeli');
});

test('false-positive seçimi ↔ değer', () => {
  assert.equal(NB.fpToSelect(true), 'fp');
  assert.equal(NB.fpToSelect(false), 'valid');
  assert.equal(NB.fpToSelect(null), '');
  assert.equal(NB.selectToFp('fp'), true);
  assert.equal(NB.selectToFp('valid'), false);
  assert.equal(NB.selectToFp(''), null);
});

test('parseCvssVector', () => {
  assert.deepEqual(NB.parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  assert.deepEqual(NB.parseCvssVector('av:n/ac:l'), { AV: 'N', AC: 'L' });
  assert.equal(NB.parseCvssVector(''), null);
  assert.equal(NB.parseCvssVector('AV:N/AV:L'), null);
  assert.equal(NB.parseCvssVector('AV=N'), null);
});

test('studyRows: fark yönü metrik türüne göre iyi/kötü', () => {
  const rows = NB.studyRows({
    ai_assisted: { n: 2, avg_completion_minutes: 30, avg_total_findings: 5, avg_ai_calls_total: 4, avg_false_positive_rate_pct: null },
    control: { n: 2, avg_completion_minutes: 60, avg_total_findings: 4, avg_ai_calls_total: 1, avg_false_positive_rate_pct: 10 },
    diff_pct: { completion_minutes: -50, total_findings: 25, ai_calls_total: 300, false_positive_rate_pct: null },
  });
  const by = Object.fromEntries(rows.map(r => [r.field, r]));
  assert.deepEqual([by.completion_minutes.diff, by.completion_minutes.tone], ['-50%', 'good']);  // daha hızlı
  assert.deepEqual([by.total_findings.diff, by.total_findings.tone], ['+25%', 'good']);
  assert.equal(by.ai_calls_total.tone, 'neutral');
  assert.deepEqual([by.false_positive_rate_pct.ai, by.false_positive_rate_pct.diff], ['–', null]);
  assert.equal(by.completion_minutes.ai, '30');
  assert.equal(NB.formatStudyValue(12.345), '12.3');
});
