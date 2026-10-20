"""
Yeniden test (retest) akışı: sınıflandırma, durum geçişi ve özet.

Finding alanları (models.py): status, retest_result ('not_tested' |
'fixed' | 'not_fixed'), retest_notes, retested_at. Ayrı bir tablo yoktur;
her yeniden test zaman çizelgesine 'finding_retested' olayı olarak da
yazılır (app.py).

Bir bulgunun yeniden test durumu (classify):
  pending     müşteri düzelttiğini bildirmiş, doğrulanmayı bekliyor
              (status 'fixed' ya da 'retest_pending'; önceki tur sonucu ne
              olursa olsun yeni tur başlamıştır)
  verified    yeniden testte düzeldiği doğrulandı (retest_result 'fixed',
              status 'resolved')
  still_open  yeniden testte hâlâ açık bulundu ve yeniden açıldı
              (retest_result 'not_fixed', status 'open' ya da 'confirmed')
  None        yeniden test kapsamında değil (hiç düzeltilmemiş açık bulgu,
              kabul edilen risk vb.)
"""

RESULTS = ('fixed', 'not_fixed')
STATES = ('pending', 'still_open', 'verified')
MAX_NOTES = 5000


class RetestError(ValueError):
    pass


def classify(finding):
    status = finding.get('status')
    result = finding.get('retest_result')
    if status in ('fixed', 'retest_pending'):
        return 'pending'
    if result == 'fixed' and status == 'resolved':
        return 'verified'
    if result == 'not_fixed' and status in ('open', 'confirmed'):
        return 'still_open'
    return None


def transition(result, notes):
    """Yeniden test sonucunu doğrular; Finding'e uygulanacak alanları döndürür.

    fixed     -> status 'resolved'  (düzeldiği doğrulandı)
    not_fixed -> status 'open'      (yeniden açıldı)"""
    if result not in RESULTS:
        raise RetestError("result 'fixed' ya da 'not_fixed' olmalı")
    if notes is None:
        notes = ''
    if not isinstance(notes, str):
        raise RetestError('notes metin olmalı')
    notes = notes.strip()
    if len(notes) > MAX_NOTES:
        raise RetestError(f'Not en fazla {MAX_NOTES} karakter olabilir')
    return {
        'retest_result': result,
        'retest_notes': notes,
        'status': 'resolved' if result == 'fixed' else 'open',
    }


def summarize(findings):
    counts = {k: 0 for k in STATES}
    for f in findings:
        st = classify(f)
        if st:
            counts[st] += 1
    counts['total'] = sum(counts[k] for k in STATES)
    return counts
