/*
 * Not Defteri ve Çalışma Metrikleri için DOM'suz yardımcılar.
 * Tarayıcıda window.WSTGNotebook, Node'da module.exports (js/tests/notebook.test.js).
 */
(function(root, factory){
  const api = factory();
  if(typeof module === 'object' && module.exports) module.exports = api;
  else root.WSTGNotebook = api;
})(typeof self !== 'undefined' ? self : this, function(){
  'use strict';

  const MAX_IMAGES = 8;
  const MAX_IMAGE_BYTES = 3 * 1024 * 1024;           // backend/notes.py ile aynı
  const MAX_PAYLOAD_CHARS = 14 * 1024 * 1024;        // istek gövdesi sınırı 16 MB
  const IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

  // Sunucudaki kalıbın aynısı. Sunucu ayrıca magic byte kontrolü yapar; bu
  // kontrol, veritabanında eski sürümden kalmış güvensiz bir değerin
  // <img src> içine hiç basılmaması içindir.
  const DATA_URL_RE = /^data:image\/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

  function isSafeImageDataUrl(value){
    return typeof value === 'string' && DATA_URL_RE.test(value);
  }

  function safeImages(images){
    return (Array.isArray(images) ? images : []).filter(img => img && isSafeImageDataUrl(img.data));
  }

  function imageFileError(file){
    if(!file || IMAGE_TYPES.indexOf(file.type) === -1) return 'type';
    if(file.size > MAX_IMAGE_BYTES) return 'size';
    return null;
  }

  function payloadChars(images){
    return safeImages(images).reduce((n, img) => n + img.data.length, 0);
  }

  function noteTime(n){
    const v = n && (n.updated_at || n.created_at);
    if(!v) return 0;
    const s = String(v);
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s + 'Z');
    return isNaN(d) ? 0 : d.getTime();
  }

  // filter: '' (tümü) | '__general__' (teste bağlı olmayanlar) | test id
  function filterNotes(notes, filter, query){
    const q = String(query || '').trim().toLocaleLowerCase('tr');
    return (notes || [])
      .filter(n => !filter ? true : filter === '__general__' ? !n.test_id : n.test_id === filter)
      .filter(n => !q || [n.title, n.content, n.test_id, n.cwe_id, n.cwe_name]
        .some(v => v && String(v).toLocaleLowerCase('tr').indexOf(q) !== -1))
      .slice()
      .sort((a, b) => noteTime(b) - noteTime(a) || (b.id || 0) - (a.id || 0));
  }

  function fpToSelect(value){
    return value === true ? 'fp' : value === false ? 'valid' : '';
  }
  function selectToFp(value){
    return value === 'fp' ? true : value === 'valid' ? false : null;
  }

  // "CVSS:3.1/AV:N/..." -> {AV:'N', ...}; bozuksa null (sunucu yine doğrular).
  function parseCvssVector(vector){
    const parts = String(vector || '').trim().split('/').filter(Boolean);
    if(parts.length && /^CVSS:/i.test(parts[0])) parts.shift();
    const out = {};
    for(const p of parts){
      const kv = p.split(':');
      if(kv.length !== 2 || !kv[0] || !kv[1]) return null;
      const k = kv[0].trim().toUpperCase();
      if(out[k] !== undefined) return null;
      out[k] = kv[1].trim().toUpperCase();
    }
    return Object.keys(out).length ? out : null;
  }

  // [alan, i18n anahtarı, düşük olan mı daha iyi]
  const STUDY_METRIC_ROWS = [
    ['completion_minutes', 'studyMetricMinutes', true],
    ['completed_tests', 'studyMetricCompletedTests', false],
    ['completion_pct', 'studyMetricCompletionPct', false],
    ['total_findings', 'studyMetricFindings', false],
    ['false_positive_rate_pct', 'studyMetricFpRate', true],
    ['ai_calls_total', 'studyMetricAiCalls', null],
    ['avg_ai_latency_ms', 'studyMetricAiLatency', true],
  ];

  function formatStudyValue(v){
    if(v === null || v === undefined || Number.isNaN(v)) return '–';
    return Number.isInteger(v) ? String(v) : Number(v).toFixed(1);
  }

  // Karşılaştırma tablosu satırları. tone: 'good' | 'bad' | 'neutral' | null
  function studyRows(comparison){
    const ai = (comparison && comparison.ai_assisted) || {};
    const ctrl = (comparison && comparison.control) || {};
    const diff = (comparison && comparison.diff_pct) || {};
    return STUDY_METRIC_ROWS.map(([field, labelKey, lowerIsBetter]) => {
      const d = diff[field];
      let tone = null;
      if(d !== null && d !== undefined){
        if(lowerIsBetter === null || d === 0) tone = 'neutral';
        else tone = (lowerIsBetter ? d < 0 : d > 0) ? 'good' : 'bad';
      }
      return {
        field, labelKey,
        ai: formatStudyValue(ai['avg_' + field]),
        control: formatStudyValue(ctrl['avg_' + field]),
        diff: d === null || d === undefined ? null : (d > 0 ? '+' : '') + d + '%',
        tone,
      };
    });
  }

  return {
    MAX_IMAGES, MAX_IMAGE_BYTES, MAX_PAYLOAD_CHARS, IMAGE_TYPES, STUDY_METRIC_ROWS,
    isSafeImageDataUrl, safeImages, imageFileError, payloadChars,
    filterNotes, fpToSelect, selectToFp, parseCvssVector,
    formatStudyValue, studyRows,
  };
});
