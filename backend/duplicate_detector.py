"""
Duplicate Finding Detection.

Bir bulgu olusturulurken/duzenlenirken projedeki mevcut bulgularla
karsilastirip olasi kopyalari yakalar. Bilincli tasarim karari: harici bir
kutuphane (fuzzywuzzy/python-Levenshtein) yerine standart kutuphanedeki
difflib kullanilir -- python-Levenshtein bir C-extension oldugu icin
Windows'ta derleme/kurulum sorunlarina yol acabilir, difflib ise bu olcekte
(proje basina onlarca-yuzlerce bulgu) yeterince hizli ve bagimliliksizdir.

Skor 0-100 araliginda, birden fazla sinyalin agirlikli toplamidir:
  - baslik benzerligi (agirlik en yuksek)
  - aciklama benzerligi
  - ayni endpoint (path normalize edilip sayisal ID'ler/query string atilir)
  - ayni CWE

Bu bir AI/semantik anlama katmani DEGILDIR -- deterministik, aciklanabilir
bir skor uretir ("neden benzer" sorusuna 'reasons' listesiyle cevap verir).
"""

import re
from difflib import SequenceMatcher

SIMILARITY_THRESHOLD = 55  # bu skorun altindakiler "olasi kopya" olarak gosterilmez
MAX_RESULTS = 5

# Endpoint'leri karsilastirilabilir hale getirmek icin: sayisal path
# segmentlerini ({id} gibi) ve query string'i at, boylece
# /api/users/5 ile /api/users/9 "ayni endpoint" sayilir.
_NUMERIC_SEGMENT_RE = re.compile(r'/\d+(?=/|$)')
_UUID_SEGMENT_RE = re.compile(
    r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)'
)


def _normalize_endpoint(endpoint):
    if not endpoint:
        return ''
    ep = endpoint.strip().lower().split('?', 1)[0]
    ep = _UUID_SEGMENT_RE.sub('/{id}', ep)
    ep = _NUMERIC_SEGMENT_RE.sub('/{id}', ep)
    return ep.rstrip('/')


def _text_ratio(a, b):
    a = (a or '').strip().lower()
    b = (b or '').strip().lower()
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _score_pair(draft, candidate):
    """draft/candidate: dict ile 'title','description','endpoint','cwe','test_id'.
    Doner: (score 0-100, reasons: list[str])

    Agirliklandirma bilincli: sadece metin benzerligine (title/description)
    guvenmiyoruz -- ayni endpoint + ayni CWE, farkli kelimelerle yazilmis
    olsa bile GUCLU bir "muhtemelen ayni kok neden" sinyalidir (bkz. kullanicinin
    kendi ornegi: 'IDOR - Unauthorized Object Access' vs 'IDOR on /api/users' --
    difflib'e gore metinsel benzerlikleri dusuk ama ayni zafiyet). Bu yuzden
    ikisi birden eslesirse ayrica bir sinerji bonusu eklenir."""
    reasons = []
    score = 0.0

    title_ratio = _text_ratio(draft.get('title'), candidate.get('title'))
    score += title_ratio * 45
    if title_ratio >= 0.6:
        reasons.append('similar_title')

    desc_ratio = _text_ratio(draft.get('description'), candidate.get('description'))
    score += desc_ratio * 20
    if desc_ratio >= 0.5:
        reasons.append('similar_description')

    draft_ep = _normalize_endpoint(draft.get('endpoint'))
    cand_ep = _normalize_endpoint(candidate.get('endpoint'))
    same_endpoint = bool(draft_ep and cand_ep and draft_ep == cand_ep)
    if same_endpoint:
        score += 15
        reasons.append('same_endpoint')

    draft_cwe = (draft.get('cwe') or '').strip().upper()
    cand_cwe = (candidate.get('cwe') or '').strip().upper()
    same_cwe = bool(draft_cwe and cand_cwe and draft_cwe == cand_cwe)
    if same_cwe:
        score += 10
        reasons.append('same_cwe')

    draft_test = (draft.get('test_id') or '').strip().upper()
    cand_test = (candidate.get('test_id') or '').strip().upper()
    if draft_test and cand_test and draft_test == cand_test:
        score += 5
        reasons.append('same_test_id')

    if same_endpoint and same_cwe:
        score += 15
        reasons.append('likely_same_root_cause')

    return min(100.0, round(score, 1)), reasons


def find_similar_findings(candidates, draft, exclude_id=None):
    """
    candidates: [Finding.to_dict(), ...] -- cagiran taraf (app.py) DB sorgusunu yapar,
                bu fonksiyon saf hesaplama katmanidir (test edilebilirlik icin).
    draft: {'title':.., 'description':.., 'endpoint':.., 'cwe':.., 'test_id':..}
    exclude_id: duzenlenen bulgunun kendisiyle karsilastirilmamasi icin (int veya None)

    Doner: [{'finding': <dict>, 'score': float, 'reasons': [str,...]}, ...]
           skora gore azalan sirali, en fazla MAX_RESULTS eleman, skor < SIMILARITY_THRESHOLD elenir.
    """
    results = []
    for candidate in candidates:
        if exclude_id is not None and candidate.get('id') == exclude_id:
            continue
        score, reasons = _score_pair(draft, candidate)
        if score >= SIMILARITY_THRESHOLD:
            results.append({'finding': candidate, 'score': score, 'reasons': reasons})

    results.sort(key=lambda r: r['score'], reverse=True)
    return results[:MAX_RESULTS]
