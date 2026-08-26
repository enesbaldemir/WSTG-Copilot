"""
AI API key sifreleme + maskeleme yardimcilari.

Tasarim ilkesi: API key'ler DB'de HICBIR ZAMAN duz metin saklanmaz.
Fernet (simetrik, AES128-CBC + HMAC) kullanilir -- anahtar SECRET_KEY'den
turetilir (ayrica bir ENCRYPTION_KEY .env degiskeni verilirse o tercih
edilir, orn. SECRET_KEY rotasyonundan bagimsiz sabit bir sifreleme anahtari
istenirse). Maskeleme (mask_key) ise API response/log/hata mesajlarinda
key'in TAMAMININ asla gorunmemesini saglar -- sadece ilk/son 4 karakter.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _derive_fernet_key(secret: str) -> bytes:
    digest = hashlib.sha256((secret or 'dev-secret-key-change-in-production').encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet(app_config) -> Fernet:
    def cfg(key, default=None):
        try:
            return app_config[key]
        except (TypeError, KeyError):
            return getattr(app_config, key, default)

    explicit_key = cfg('ENCRYPTION_KEY', '') or ''
    if explicit_key.strip():
        # Kullanici kendi Fernet key'ini saglamis olabilir (urlsafe-base64,
        # 32 byte) ya da rastgele bir passphrase -- ikisini de destekle.
        try:
            return Fernet(explicit_key.strip().encode('utf-8'))
        except Exception:
            return Fernet(_derive_fernet_key(explicit_key.strip()))

    secret_key = cfg('SECRET_KEY', 'dev-secret-key-change-in-production')
    return Fernet(_derive_fernet_key(secret_key))


def encrypt(app_config, plaintext: str) -> str:
    if not plaintext:
        return ''
    fernet = get_fernet(app_config)
    return fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')


def decrypt(app_config, ciphertext: str) -> str:
    if not ciphertext:
        return ''
    fernet = get_fernet(app_config)
    try:
        return fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        # SECRET_KEY degistiyse eski sifreli key'ler artik cozulemez --
        # sessizce bos donup yeniden girilmesini istemek, 500 patlatmaktan iyidir.
        return ''


def mask_key(raw: str) -> str:
    """'AIzaSyD-abc123xyz789' -> 'AIza...z789'. Kisa/bos key'ler tamamen maskelenir."""
    if not raw:
        return ''
    if len(raw) <= 8:
        return '*' * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"
