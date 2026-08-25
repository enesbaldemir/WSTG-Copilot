"""
Secrets / PII Redaction -- HTTP Request/Response Evidence icin.

Tasarim ilkesi: HAM (raw) metin her zaman veritabaninda saklanir (pentester
gercek kanitina ihtiyac duyar), ama goruntuleme/rapor/export akislari
VARSAYILAN OLARAK redakte edilmis versiyonu kullanir. Ham metni gormek
kullanicinin acikca "Ham metni goster" demesini gerektirir -- yanlislikla
sizma riskini azaltmak icin.

Kurallar regex tabanlidir ve KAPSAMLI DEGIL, iyi bilinen/yaygin kaliplari
kapsar (Authorization header, cookie, JWT, yaygin API key formatlari,
private key bloklari, e-posta, kredi karti benzeri sayilar). Yeni kalip
eklemek REDACTION_RULES listesine yeni bir girdi eklemek kadar basittir.
"""

import re

REDACTION_RULES = [
    # (isim, regex, replacement)
    ('authorization_header',
     re.compile(r'(Authorization:\s*)(Bearer|Basic|Digest|Token)\s+\S+', re.I),
     r'\1\2 [REDACTED]'),
    ('cookie_header',
     re.compile(r'^(Cookie:\s*).+$', re.I | re.M),
     r'\1[REDACTED]'),
    ('set_cookie_header',
     re.compile(r'^(Set-Cookie:\s*)[^;]+', re.I | re.M),
     r'\1[REDACTED]'),
    ('x_api_key_header',
     re.compile(r'^(X-API-Key:\s*).+$', re.I | re.M),
     r'\1[REDACTED]'),
    ('jwt_token',
     re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
     '[REDACTED-JWT]'),
    ('aws_access_key',
     re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
     '[REDACTED-AWS-KEY]'),
    ('generic_api_key_field',
     re.compile(r'("(?:api[_-]?key|apikey|secret|access[_-]?token|client[_-]?secret)"\s*:\s*")[^"]+(")', re.I),
     r'\1[REDACTED]\2'),
    ('generic_password_field',
     re.compile(r'("password"\s*:\s*")[^"]+(")', re.I),
     r'\1[REDACTED]\2'),
    ('private_key_block',
     re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S),
     '[REDACTED-PRIVATE-KEY]'),
    ('email_address',
     re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
     '[REDACTED-EMAIL]'),
    ('credit_card_like',
     re.compile(r'\b(?:\d[ -]?){13,16}\b'),
     '[REDACTED-CC]'),
]


def redact(text):
    """text icindeki bilinen hassas kaliplari [REDACTED...] ile degistirir.
    Orijinal metni degistirmez, redakte edilmis YENI bir string doner."""
    if not text:
        return text
    result = text
    for _name, pattern, replacement in REDACTION_RULES:
        result = pattern.sub(replacement, result)
    return result
