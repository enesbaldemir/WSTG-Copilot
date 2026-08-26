"""
Evidence Intelligence -- yuklenen ekran goruntulerini WSTG testleriyle
otomatik iliskilendirmeye calisan opsiyonel bir yardimci.

DURUSTLUK NOTU: Bu modul, WSTG-Copilot'taki diger "AI" adli ozelliklerden
(Test Plani, Attack Chains) FARKLIDIR -- onlar sabit kurallardi, bu ise
GERCEK bir model cagrisi yapar (Anthropic Claude, vision destegiyle).
Ama bu cagri TAMAMEN OPSIYONELDIR:
  - backend/.env dosyasinda ANTHROPIC_API_KEY ayarlanmadiysa, bu modul
    hicbir agi istegi atmaz ve is_configured() False doner.
  - Model bir seyler "uydurmasin" diye, prompt'ta ona SADECE gercek WSTG
    test ID'lerinden secim yapmasi soyleniyor ve verdigi ID'ler backend
    tarafinda WSTG veri setine karsi DOGRULANIYOR -- gecersiz/uydurma bir
    ID varsa o oneri sessizce elenir.
  - Sonuc her zaman bir "oneri"dir; kullanici Accept/Reject ile onaylamadan
    hicbir finding'e otomatik baglanmaz (roadmap'teki akisla birebir).
"""

import base64
import json

import requests

ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages'
ANTHROPIC_MODEL = 'claude-sonnet-5'
REQUEST_TIMEOUT = 30

SUPPORTED_MIME_TYPES = {'image/png', 'image/jpeg', 'image/webp', 'image/gif'}


def is_configured(api_key):
    return bool(api_key and api_key.strip())


def _build_prompt(valid_test_ids_sample):
    ids_hint = ', '.join(valid_test_ids_sample)
    return (
        "Bu bir yetkili penetrasyon testi calismasindan alinmis bir ekran goruntusudur. "
        "Gorseli inceleyip SADECE gordugun teknik icerigi (ornegin: hata mesaji, HTTP yaniti, "
        "acik bir yonetim paneli, ifsa olan veri alanlari, cookie/header degerleri vb.) 1-3 "
        "cumleyle objektif olarak tanimla. Yorum katma, saldiri onerisi verme.\n\n"
        "Sonra bu goruntunun hangi OWASP WSTG (Web Security Testing Guide) test kategorileriyle "
        "ilgili olabilecegini SADECE asagidaki gecerli ID listesinden secerek belirt (listede "
        "olmayan bir ID UYDURMA):\n" + ids_hint + "\n\n"
        "Yanitini SADECE su JSON formatinda ver, baska hicbir metin ekleme:\n"
        '{"description": "...", "suggested_test_ids": ["WSTG-XXX-NN", ...], "confidence": 0-100}'
    )


def analyze_screenshot(api_key, image_bytes, mime_type, valid_test_ids):
    """Doner: (analysis_dict | None, error_str | None)
    analysis_dict: {'description':str, 'suggested_test_ids':[...], 'confidence':float}
    Gecersiz/uydurma test ID'leri valid_test_ids ile karsilastirilarak elenir."""
    if not is_configured(api_key):
        return None, 'ANTHROPIC_API_KEY yapilandirilmamis'
    if mime_type not in SUPPORTED_MIME_TYPES:
        return None, 'Desteklenmeyen dosya turu: ' + str(mime_type)

    b64_data = base64.b64encode(image_bytes).decode('ascii')
    prompt = _build_prompt(sorted(valid_test_ids))

    try:
        resp = requests.post(
            ANTHROPIC_API_URL,
            headers={
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
            },
            json={
                'model': ANTHROPIC_MODEL,
                'max_tokens': 500,
                'messages': [{
                    'role': 'user',
                    'content': [
                        {'type': 'image', 'source': {'type': 'base64', 'media_type': mime_type, 'data': b64_data}},
                        {'type': 'text', 'text': prompt},
                    ]
                }]
            },
            timeout=REQUEST_TIMEOUT
        )
    except requests.exceptions.RequestException as e:
        return None, 'API istegi basarisiz: ' + str(e)

    if not resp.ok:
        return None, 'API hatasi (' + str(resp.status_code) + '): ' + resp.text[:300]

    try:
        data = resp.json()
        text_blocks = [b['text'] for b in data.get('content', []) if b.get('type') == 'text']
        raw_text = '\n'.join(text_blocks).strip()
        raw_text = raw_text.replace('```json', '').replace('```', '').strip()
        parsed = json.loads(raw_text)
    except Exception as e:
        return None, 'Model yaniti parse edilemedi: ' + str(e)

    suggested = parsed.get('suggested_test_ids', [])
    if not isinstance(suggested, list):
        suggested = []
    validated_ids = [tid for tid in suggested if tid in valid_test_ids]

    confidence = parsed.get('confidence', 0)
    try:
        confidence = float(confidence)
    except Exception:
        confidence = 0.0
    confidence = max(0.0, min(100.0, confidence))

    return {
        'description': str(parsed.get('description', ''))[:2000],
        'suggested_test_ids': validated_ids,
        'confidence': confidence,
    }, None
