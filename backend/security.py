"""
Yerel (localhost) kullanım için güvenli varsayılanlar.

Bu araç müşteri bulgularını, ham HTTP kayıtlarını ve şifreli AI anahtarlarını
saklar. Parola ile giriş auth.py'dedir; bu modüldeki kontroller ondan önce,
her istekte çalışır. Varsayılan davranış:

  - API yalnızca 127.0.0.1'de dinler. Ağa açmak için WSTG_HOST açıkça
    verilmelidir.
  - Werkzeug debugger'ı yalnızca FLASK_DEBUG=1 ile açılır ve loopback dışı bir
    adreste ASLA açılmaz (ağdan erişilebilen debugger kod çalıştırmaya izin verir).
  - CORS yalnızca CORS_ORIGINS'teki frontend adreslerine izin verir.
  - Durum değiştiren istekler (POST/PUT/PATCH/DELETE) izin verilmeyen bir
    Origin'den gelirse reddedilir (CORS yanıtın okunmasını engeller ama
    isteğin gönderilmesini engellemez; bu kontrol onu kapatır).
  - Host başlığı ALLOWED_HOSTS ile sınırlanır (DNS rebinding koruması: başka
    bir alan adının 127.0.0.1'e çözülüp API'ye "aynı origin" gibi erişmesini
    engeller).
  - SECRET_KEY tanımlı değilse koddaki sabit değer yerine rastgele bir anahtar
    üretilip backend/instance/secret_key dosyasına (0600) kaydedilir.

Bu modül Flask'a bağımlı değildir; birim testleri backend/test_security_defaults.py.
"""

import os
import secrets

LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1'})
TRUE_VALUES = frozenset({'1', 'true', 'yes', 'on'})

# Eski sürümlerin SECRET_KEY tanımlı değilken kullandığı sabit değer. Yalnızca
# eski şifreli AI anahtarlarını yeni anahtara taşımak (migrate) için tutulur.
LEGACY_DEFAULT_SECRET = 'dev-secret-key-change-in-production'

DEFAULT_CORS_ORIGINS = ('http://localhost:8000,http://127.0.0.1:8000,'
                        'http://localhost:3000,http://127.0.0.1:3000')
DEFAULT_ALLOWED_HOSTS = 'localhost,127.0.0.1,::1'


def parse_list(value):
    return [v.strip() for v in str(value or '').split(',') if v.strip()]


def is_loopback(host):
    h = str(host or '').strip().strip('[]').lower()
    return h in LOOPBACK_HOSTS or h.startswith('127.')


def run_settings(env=None):
    """`python app.py` için host/port/debug değerleri.

    Debug + loopback dışı host birlikte istenirse ValueError fırlatır."""
    env = os.environ if env is None else env
    host = (env.get('WSTG_HOST') or env.get('FLASK_RUN_HOST') or '127.0.0.1').strip()
    port_raw = (env.get('WSTG_PORT') or env.get('FLASK_RUN_PORT') or '5000').strip()
    try:
        port = int(port_raw)
    except ValueError:
        raise ValueError(f'Geçersiz port: {port_raw!r}')
    debug = str(env.get('FLASK_DEBUG', '')).strip().lower() in TRUE_VALUES
    if debug and not is_loopback(host):
        raise ValueError(
            f"FLASK_DEBUG açıkken API yalnızca localhost'ta çalıştırılabilir (istenen host: {host}). "
            "Ağdan erişilebilen Werkzeug debugger'ı uzaktan kod çalıştırmaya izin verir."
        )
    return {'host': host, 'port': port, 'debug': debug}


def host_header_allowed(host_header, allowed_hosts):
    """'localhost:5000', '[::1]:5000', '127.0.0.1' gibi Host başlıklarını kontrol eder."""
    if not host_header:
        return False
    h = str(host_header).strip().lower()
    if h.startswith('['):                      # [::1]:5000
        h = h[1:].split(']', 1)[0]
    elif h.count(':') == 1:                     # localhost:5000
        h = h.rsplit(':', 1)[0]
    allowed = {a.strip().strip('[]').lower() for a in allowed_hosts}
    return h in allowed


def origin_allowed(origin, allowed_origins):
    """Origin yoksa (curl, sunucu tarafı) True; 'null' veya listede olmayan origin False."""
    if origin is None or origin == '':
        return True
    return origin.rstrip('/') in {o.rstrip('/') for o in allowed_origins}


def load_or_create_secret_key(path):
    """Dosyadaki anahtarı döndürür; yoksa üretip 0600 izinle kaydeder.

    Döndürür: (anahtar, yeni_olusturuldu_mu)"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            existing = f.read().strip()
        if existing:
            return existing, False
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    key = secrets.token_urlsafe(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(key + '\n')
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows'ta chmod kısıtlı; dosya yine de kullanıcı dizininde
    return key, True
