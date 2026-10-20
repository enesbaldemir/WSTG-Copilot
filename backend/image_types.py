"""
Görsel türünü dosyanın İÇERİĞİNDEN (ilk baytlar / magic bytes) belirler.

İstemcinin gönderdiği Content-Type ya da dosya uzantısı saldırganın
kontrolündedir; bu yüzden kanıt yükleme (app.py) ve not görselleri
(notes.py) türü buradan alır. Yalnızca etkin içerik taşımayan raster
türler desteklenir (SVG bilinçli olarak yok).
"""

MIME_BY_TYPE = {
    'png': 'image/png',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'webp': 'image/webp',
}
EXT_BY_TYPE = {'png': '.png', 'jpeg': '.jpg', 'gif': '.gif', 'webp': '.webp'}
SNIFF_BYTES = 16


def detect_image_type(raw):
    """İlk baytlara göre 'png' | 'jpeg' | 'gif' | 'webp' | None."""
    if not raw:
        return None
    if raw.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if raw.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if raw.startswith((b'GIF87a', b'GIF89a')):
        return 'gif'
    if len(raw) >= 12 and raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        return 'webp'
    return None


def detect_image_mime(raw):
    t = detect_image_type(raw)
    return MIME_BY_TYPE.get(t) if t else None


def sniff_file(path):
    """Diskteki dosyanın gerçek görsel MIME türü (yoksa None)."""
    try:
        with open(path, 'rb') as f:
            return detect_image_mime(f.read(SNIFF_BYTES))
    except OSError:
        return None
