"""
Yerel kullanım için güvenli varsayılanların testleri (bkz. security.py).

Bu ayarlar daha önce bir kez düzeltilip sonradan farkında olmadan geri
alınmıştı (debug=True, host=0.0.0.0, CORS "*"). Bu testler aynı şeyin tekrar
olmasını engeller.
"""
import sys, os, stat, re
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest
import app as app_module
import security
import crypto_utils
from cryptography.fernet import Fernet

ALLOWED = 'http://localhost:8000'
EVIL = 'https://evil.example'


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


# --- python app.py ayarları -------------------------------------------------

def test_run_defaults_are_local_and_without_debugger():
    assert security.run_settings({}) == {'host': '127.0.0.1', 'port': 5000, 'debug': False}


def test_debug_is_opt_in_and_only_on_loopback():
    assert security.run_settings({'FLASK_DEBUG': '1'})['debug'] is True
    assert security.run_settings({'FLASK_DEBUG': '0'})['debug'] is False
    with pytest.raises(ValueError):
        security.run_settings({'FLASK_DEBUG': '1', 'WSTG_HOST': '0.0.0.0'})
    # ağa açmak açıkça istenebilir, ama debugger olmadan
    assert security.run_settings({'WSTG_HOST': '0.0.0.0'}) == {'host': '0.0.0.0', 'port': 5000, 'debug': False}
    with pytest.raises(ValueError):
        security.run_settings({'WSTG_PORT': 'abc'})


def test_source_has_no_hardcoded_insecure_run_or_cors():
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py'), encoding='utf-8').read()
    assert not re.search(r"app\.run\([^)]*host\s*=\s*['\"]0\.0\.0\.0", src)
    assert not re.search(r"app\.run\([^)]*debug\s*=\s*True", src)
    assert not re.search(r"origins['\"]?\s*:\s*['\"]\*['\"]", src)


def test_development_config_debug_off_by_default():
    assert app_module.app.config['DEBUG'] is False


# --- CORS ------------------------------------------------------------------

def test_cors_allows_only_configured_frontend():
    c = _client()
    ok = c.get('/api/projects', headers={'Origin': ALLOWED})
    assert ok.headers.get('Access-Control-Allow-Origin') == ALLOWED
    bad = c.get('/api/projects', headers={'Origin': EVIL})
    assert 'Access-Control-Allow-Origin' not in bad.headers
    pre = c.options('/api/projects', headers={'Origin': EVIL, 'Access-Control-Request-Method': 'POST',
                                              'Access-Control-Request-Headers': 'content-type'})
    assert 'Access-Control-Allow-Origin' not in pre.headers
    assert '127.0.0.1:8000' in app_module.app.config['CORS_ORIGINS']


# --- Origin kontrolü (durum değiştiren istekler) ---------------------------

def test_state_changing_request_from_foreign_origin_is_rejected():
    c = _client()
    before = len(c.get('/api/projects').get_json())
    r = c.post('/api/projects', json={'name': 'cross-site'}, headers={'Origin': EVIL})
    assert r.status_code == 403
    r = c.post('/api/projects', json={'name': 'sandboxed'}, headers={'Origin': 'null'})
    assert r.status_code == 403
    assert len(c.get('/api/projects').get_json()) == before   # hiçbir şey oluşmadı


def test_state_changing_request_from_frontend_or_cli_is_allowed():
    c = _client()
    r = c.post('/api/projects', json={'name': 'from frontend'}, headers={'Origin': ALLOWED})
    assert r.status_code in (200, 201)
    pid = r.get_json()['id']
    assert c.post('/api/projects', json={'name': 'from curl'}).status_code in (200, 201)  # Origin yok
    assert c.delete(f'/api/projects/{pid}', headers={'Origin': EVIL}).status_code == 403
    assert c.delete(f'/api/projects/{pid}', headers={'Origin': ALLOWED}).status_code == 200


# --- Host başlığı (DNS rebinding) -------------------------------------------

def test_foreign_host_header_is_rejected():
    c = _client()
    assert c.get('/api/projects', headers={'Host': 'attacker.example:5000'}).status_code == 400
    assert c.get('/api/projects', headers={'Host': 'localhost:5000'}).status_code == 200
    assert c.get('/api/projects', headers={'Host': '127.0.0.1:5000'}).status_code == 200
    assert c.get('/api/projects', headers={'Host': '[::1]:5000'}).status_code == 200


def test_host_header_parser():
    allowed = security.parse_list(security.DEFAULT_ALLOWED_HOSTS)
    assert security.host_header_allowed('LOCALHOST', allowed)
    assert not security.host_header_allowed('localhost.attacker.example', allowed)
    assert not security.host_header_allowed('', allowed)
    assert security.host_header_allowed('10.0.0.5:5000', allowed + ['10.0.0.5'])


# --- SECRET_KEY ---------------------------------------------------------------

def test_secret_key_is_generated_once_with_private_permissions(tmp_path):
    path = tmp_path / 'instance' / 'secret_key'
    key1, created1 = security.load_or_create_secret_key(str(path))
    key2, created2 = security.load_or_create_secret_key(str(path))
    assert created1 is True and created2 is False and key1 == key2
    assert len(key1) >= 40 and key1 != security.LEGACY_DEFAULT_SECRET
    if os.name == 'posix':
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_no_hardcoded_secret_in_effect():
    assert app_module.app.config['SECRET_KEY'] != security.LEGACY_DEFAULT_SECRET


def test_ai_keys_encrypted_with_legacy_default_are_migrated():
    legacy_cfg = {'SECRET_KEY': '', 'ENCRYPTION_KEY': ''}             # eski sürüm davranışı
    old_token = crypto_utils.encrypt(legacy_cfg, 'sk-test-1234567890')
    new_cfg = {'SECRET_KEY': 'new-random-secret', 'ENCRYPTION_KEY': ''}
    assert crypto_utils.decrypt(new_cfg, old_token) == ''              # taşınmadan çözülemez
    new_token = crypto_utils.reencrypt_from_legacy(new_cfg, old_token, [security.LEGACY_DEFAULT_SECRET])
    assert crypto_utils.decrypt(new_cfg, new_token) == 'sk-test-1234567890'
    # zaten güncel olan veya ENCRYPTION_KEY kullanan kayıtlara dokunulmaz
    assert crypto_utils.reencrypt_from_legacy(new_cfg, new_token, [security.LEGACY_DEFAULT_SECRET]) is None
    enc_cfg = {'SECRET_KEY': 'x', 'ENCRYPTION_KEY': Fernet.generate_key().decode()}
    assert crypto_utils.reencrypt_from_legacy(enc_cfg, old_token, [security.LEGACY_DEFAULT_SECRET]) is None
