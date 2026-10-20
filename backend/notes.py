"""
Not Defteri girdilerinin doğrulanması (Flask'tan bağımsız; rotalar app.py'de).

Notlardaki görseller veritabanında data-URL olarak saklanır ve arayüzde
<img src="..."> içine basılır. Eski sürüm yalnızca değerin 'data:image/' ile
başlamasına bakıyordu; bu, attribute'tan kaçan bir değerle (ör.
'data:image/x" onerror="...') kalıcı XSS'e açıktı ve SVG gibi etkin içerikli
türlere de izin veriyordu. Burada:

  - yalnızca png / jpeg / gif / webp kabul edilir,
  - data-URL sıkı bir kalıpla eşleşmeli (yalnızca base64 karakterleri),
  - base64 çözülür ve dosyanın ilk baytları (magic bytes) beyan edilen türle
    eşleşmelidir,
  - görsel sayısı ve boyutu sınırlıdır.
"""

import base64
import binascii
import json
import re

import cvss

MAX_NOTE_IMAGES = 8
MAX_NOTE_IMAGE_BYTES = 3 * 1024 * 1024        # çözülmüş tek görsel
MAX_TITLE_LENGTH = 200
MAX_NAME_LENGTH = 120
SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')

_DATA_URL_RE = re.compile(r'^data:image/(png|jpeg|jpg|gif|webp);base64,([A-Za-z0-9+/]+={0,2})$')
_CWE_RE = re.compile(r'^(?:CWE-)?(\d{1,5})$', re.IGNORECASE)
_TEST_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$')
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f]')


class NoteValidationError(ValueError):
    pass


def detect_image_type(raw):
    """İlk baytlara göre 'png' | 'jpeg' | 'gif' | 'webp' | None."""
    if raw.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if raw.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if raw.startswith((b'GIF87a', b'GIF89a')):
        return 'gif'
    if len(raw) >= 12 and raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'webp'
    return None


def validate_image_data_url(value):
    """Geçerliyse normalize edilmiş data-URL'yi döndürür, değilse hata fırlatır."""
    if not isinstance(value, str):
        raise NoteValidationError('Geçersiz görsel verisi')
    m = _DATA_URL_RE.match(value.strip())
    if not m:
        raise NoteValidationError('Görsel yalnızca PNG, JPEG, GIF veya WebP (base64 data-URL) olabilir')
    declared = 'jpeg' if m.group(1) == 'jpg' else m.group(1)
    payload = m.group(2)
    if len(payload) > (MAX_NOTE_IMAGE_BYTES * 4) // 3 + 4:
        raise NoteValidationError(f'Görsel çok büyük (en fazla {MAX_NOTE_IMAGE_BYTES // (1024 * 1024)} MB)')
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        raise NoteValidationError('Görsel verisi bozuk (base64 çözülemedi)')
    if len(raw) > MAX_NOTE_IMAGE_BYTES:
        raise NoteValidationError(f'Görsel çok büyük (en fazla {MAX_NOTE_IMAGE_BYTES // (1024 * 1024)} MB)')
    actual = detect_image_type(raw)
    if actual != declared:
        raise NoteValidationError('Görsel içeriği beyan edilen türle uyuşmuyor')
    return f'data:image/{declared};base64,{payload}'


def sanitize_images(raw_images):
    """İstemciden gelen görsel listesini doğrular, JSON string döndürür."""
    if raw_images in (None, ''):
        return json.dumps([])
    if not isinstance(raw_images, list):
        raise NoteValidationError('images bir liste olmalıdır')
    if len(raw_images) > MAX_NOTE_IMAGES:
        raise NoteValidationError(f'En fazla {MAX_NOTE_IMAGES} görsel eklenebilir')
    cleaned = []
    for img in raw_images:
        if not isinstance(img, dict):
            raise NoteValidationError('Geçersiz görsel kaydı')
        name = _CONTROL_CHARS_RE.sub('', str(img.get('name') or 'kanit')).strip()[:MAX_NAME_LENGTH] or 'kanit'
        cleaned.append({'name': name, 'data': validate_image_data_url(img.get('data'))})
    return json.dumps(cleaned)


def clean_severity(value):
    v = (value or 'info')
    if not isinstance(v, str) or v.lower() not in SEVERITIES:
        raise NoteValidationError(f"severity şunlardan biri olmalı: {', '.join(SEVERITIES)}")
    return v.lower()


def clean_test_id(value):
    if value in (None, ''):
        return None
    if not isinstance(value, str) or not _TEST_ID_RE.match(value.strip()):
        raise NoteValidationError('Geçersiz test_id')
    return value.strip()


def clean_cwe_id(value):
    if value in (None, ''):
        return None
    m = _CWE_RE.match(str(value).strip())
    if not m:
        raise NoteValidationError("CWE 'CWE-89' biçiminde olmalı")
    return f'CWE-{int(m.group(1))}'


def clean_text(value, limit=None):
    if value is None:
        return ''
    if not isinstance(value, str):
        raise NoteValidationError('Metin alanı bekleniyordu')
    return value[:limit] if limit else value


def clean_false_positive(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise NoteValidationError('is_false_positive true, false veya null olmalıdır')


def cvss_fields(vector):
    """Vektörden (cvss_vector, cvss_score, cvss_rating). Boşsa üçü de None.

    Skor HER ZAMAN sunucuda hesaplanır; istemciden gelen skora güvenilmez."""
    if vector in (None, '') or (isinstance(vector, str) and not vector.strip()):
        return None, None, None
    try:
        result = cvss.compute(cvss.parse_vector(vector))
    except cvss.CvssError as e:
        raise NoteValidationError(f'Geçersiz CVSS vektörü: {e}')
    return result['vector'], result['base_score'], result['severity']


def apply_fields(note, data, creating=False):
    """İstekteki alanları Note nesnesine uygular (yalnızca gönderilenleri)."""
    if creating or 'title' in data:
        note.title = clean_text(data.get('title'), MAX_TITLE_LENGTH)
    if creating or 'content' in data:
        note.content = clean_text(data.get('content'))
    if creating or 'severity' in data:
        note.severity = clean_severity(data.get('severity'))
    if creating or 'test_id' in data:
        note.test_id = clean_test_id(data.get('test_id'))
    if creating or 'category_id' in data:
        note.category_id = clean_test_id(data.get('category_id'))
    if creating or 'images' in data:
        note.images = sanitize_images(data.get('images'))
    if 'is_false_positive' in data:
        note.is_false_positive = clean_false_positive(data['is_false_positive'])
    if 'cvss_vector' in data:
        note.cvss_vector, note.cvss_score, note.cvss_rating = cvss_fields(data.get('cvss_vector'))
    if 'cwe_id' in data:
        note.cwe_id = clean_cwe_id(data.get('cwe_id'))
    if 'cwe_name' in data:
        note.cwe_name = clean_text(data.get('cwe_name'), 200).strip() or None
    if not (note.content or '').strip() and note.images in (None, '', '[]'):
        raise NoteValidationError('Not içeriği veya en az bir görsel gereklidir')
