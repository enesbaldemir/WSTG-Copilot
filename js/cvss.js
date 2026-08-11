/**
 * CVSS v3.1 Taban (Base) Skor Hesaplayıcı — istemci tarafı.
 * backend/cvss.py ile birebir aynı resmi FIRST.org formülünü kullanır,
 * böylece hem anlık UI geri bildirimi hem de yerel (oturumsuz) modda
 * backend olmadan doğru skor hesaplanabilir.
 * https://www.first.org/cvss/v3-1/specification-document
 */
(function (global) {
  'use strict';

  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
  const AC = { L: 0.77, H: 0.44 };
  const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.50 };
  const UI = { N: 0.85, R: 0.62 };
  const CIA = { N: 0.0, L: 0.22, H: 0.56 };
  const REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

  function roundup(value) {
    const intValue = Math.round(value * 100000);
    if (intValue % 10000 === 0) return intValue / 100000;
    return (Math.floor(intValue / 10000) + 1) / 10;
  }

  function parseVector(vector) {
    if (!vector || typeof vector !== 'string') throw new Error('CVSS vektörü boş olamaz');
    let parts = vector.trim().split('/');
    if (parts.length && /^cvss:/i.test(parts[0])) parts = parts.slice(1);

    const m = {};
    for (const part of parts) {
      if (!part) continue;
      const idx = part.indexOf(':');
      if (idx === -1) throw new Error(`Geçersiz vektör parçası: '${part}'`);
      m[part.slice(0, idx).toUpperCase()] = part.slice(idx + 1).toUpperCase();
    }
    const missing = REQUIRED.filter(k => !(k in m));
    if (missing.length) throw new Error(`Vektörde eksik metrik(ler): ${missing.join(', ')}`);
    if (!(m.AV in AV)) throw new Error(`Geçersiz AV değeri: ${m.AV}`);
    if (!(m.AC in AC)) throw new Error(`Geçersiz AC değeri: ${m.AC}`);
    if (m.S !== 'U' && m.S !== 'C') throw new Error(`Geçersiz S (Scope) değeri: ${m.S}`);
    const prTable = m.S === 'C' ? PR_CHANGED : PR_UNCHANGED;
    if (!(m.PR in prTable)) throw new Error(`Geçersiz PR değeri: ${m.PR}`);
    if (!(m.UI in UI)) throw new Error(`Geçersiz UI değeri: ${m.UI}`);
    for (const k of ['C', 'I', 'A']) {
      if (!(m[k] in CIA)) throw new Error(`Geçersiz ${k} değeri: ${m[k]}`);
    }
    return m;
  }

  function ratingForScore(score) {
    if (score <= 0) return 'none';
    if (score < 4.0) return 'low';
    if (score < 7.0) return 'medium';
    if (score < 9.0) return 'high';
    return 'critical';
  }

  function calculate(vector) {
    const m = parseVector(vector);
    const av = AV[m.AV], ac = AC[m.AC];
    const prTable = m.S === 'C' ? PR_CHANGED : PR_UNCHANGED;
    const pr = prTable[m.PR], ui = UI[m.UI];
    const c = CIA[m.C], i = CIA[m.I], a = CIA[m.A];

    const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
    const impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    const exploitability = 8.22 * av * ac * pr * ui;

    let baseScore;
    if (impact <= 0) {
      baseScore = 0.0;
    } else if (m.S === 'U') {
      baseScore = roundup(Math.min(impact + exploitability, 10));
    } else {
      baseScore = roundup(Math.min(1.08 * (impact + exploitability), 10));
    }

    const normalizedVector = 'CVSS:3.1/' + REQUIRED.map(k => `${k}:${m[k]}`).join('/');
    const score = Math.round(baseScore * 10) / 10;
    return { vector: normalizedVector, score, rating: ratingForScore(score), metrics: m };
  }

  function metricsToVector(m) {
    return REQUIRED.map(k => `${k}:${m[k]}`).join('/');
  }

  global.CVSS = { calculate, parseVector, ratingForScore, metricsToVector, REQUIRED };
})(typeof window !== 'undefined' ? window : this);
