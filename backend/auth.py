"""
Tek kullanıcılı yerel kimlik doğrulama.

- Parola yalnızca tuzlanmış hash olarak saklanır (werkzeug.security).
- Oturum, Flask'ın imzalı session çerezidir (SECRET_KEY ile imzalanır):
  HttpOnly, SameSite=Strict, varsayılan 12 saat. Çerezde yalnızca
  {"auth": True, "v": <session_version>} tutulur.
- İlk parola (setup) yalnızca bu bilgisayardan (loopback) belirlenebilir;
  böylece ağdan gelen biri parolayı sahibinden önce belirleyemez. Uzak
  kurulumlarda ve parola unutulduğunda: `python app.py set-password`.
- Kaba kuvvet koruması: istemci adresi başına 5 hatalı denemeden sonra artan
  bekleme süresi (30 sn'den başlayıp 15 dk'ya kadar).

Flask'a bağımlı yardımcılar burada; rotalar app.py içinde.
"""

import ipaddress
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

FREE_ATTEMPTS = 5
BASE_LOCK_SECONDS = 30
MAX_LOCK_SECONDS = 15 * 60


class PasswordPolicyError(ValueError):
    """`code` frontend'in çeviri anahtarı olarak kullandığı makine-okunur sebeptir."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def validate_password(password):
    if not isinstance(password, str) or not password:
        raise PasswordPolicyError('Parola zorunludur.', 'password_required')
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f'Parola en az {MIN_PASSWORD_LENGTH} karakter olmalıdır.', 'password_too_short')
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f'Parola en fazla {MAX_PASSWORD_LENGTH} karakter olabilir.', 'password_too_long')
    if password.strip() != password:
        raise PasswordPolicyError('Parola başında/sonunda boşluk içeremez.', 'password_whitespace')


def hash_password(password):
    validate_password(password)
    return generate_password_hash(password)


def verify_password(password_hash, password):
    # Aşırı uzun girdi hash'lenmeden reddedilir (scrypt'i boşuna yormasın).
    if not password_hash or not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


def is_loopback_addr(addr):
    """İstemcinin TCP adresi (request.remote_addr) bu bilgisayar mı?

    ProxyFix kullanılmadığı için remote_addr başlıklarla taklit edilemez.
    '::ffff:127.0.0.1' gibi IPv4-mapped adresler de loopback sayılır."""
    try:
        ip = ipaddress.ip_address(str(addr or '').strip().strip('[]'))
    except ValueError:
        return False
    mapped = getattr(ip, 'ipv4_mapped', None)
    return ip.is_loopback or bool(mapped and mapped.is_loopback)


class LoginThrottle:
    """İstemci başına hatalı deneme sayacı (bellekte; süreç yeniden başlarsa sıfırlanır)."""

    def __init__(self, free_attempts=FREE_ATTEMPTS, base=BASE_LOCK_SECONDS, maximum=MAX_LOCK_SECONDS, clock=time.monotonic):
        self.free_attempts = free_attempts
        self.base = base
        self.maximum = maximum
        self.clock = clock
        self._state = {}   # key -> [failures, locked_until]
        self._lock = threading.Lock()

    def retry_after(self, key):
        """Kilitliyse kalan saniye, değilse 0."""
        with self._lock:
            st = self._state.get(key)
            if not st:
                return 0
            remaining = st[1] - self.clock()
            return int(remaining) + 1 if remaining > 0 else 0

    def failure(self, key):
        with self._lock:
            st = self._state.setdefault(key, [0, 0.0])
            st[0] += 1
            extra = st[0] - self.free_attempts
            if extra > 0:
                st[1] = self.clock() + min(self.base * (2 ** (extra - 1)), self.maximum)
            return st[0]

    def success(self, key):
        with self._lock:
            self._state.pop(key, None)

    def reset(self):
        with self._lock:
            self._state.clear()
