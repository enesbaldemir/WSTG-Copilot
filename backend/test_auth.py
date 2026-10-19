"""Tek kullanıcılı kimlik doğrulama (auth.py + app.py /api/auth/*).

Bu modül conftest'teki giriş atlama fixture'ından çıkar (real_auth); yani
buradaki istekler gerçek oturum kontrolünden geçer. Veritabanı conftest'in
geçici SQLite dosyasıdır.
"""
import pytest
from werkzeug.security import check_password_hash

import app as app_module
import auth
from models import db, AuthSettings

pytestmark = pytest.mark.real_auth

PASSWORD = 'dogru-parola-123'
NEW_PASSWORD = 'yeni-parola-4567'
FRONTEND_ORIGIN = 'http://127.0.0.1:8000'


@pytest.fixture(autouse=True)
def clean_auth_state():
    with app_module.app.app_context():
        AuthSettings.query.delete()
        db.session.commit()
    app_module.login_throttle.reset()
    yield
    app_module.login_throttle.reset()


def make_client(remote_addr='127.0.0.1'):
    client = app_module.app.test_client()
    client.environ_base['REMOTE_ADDR'] = remote_addr
    return client


@pytest.fixture
def client():
    return make_client()


def setup_password(client, password=PASSWORD):
    return client.post('/api/auth/setup', json={'password': password})


def login(client, password=PASSWORD):
    return client.post('/api/auth/login', json={'password': password})


def stored_settings():
    with app_module.app.app_context():
        s = db.session.get(AuthSettings, 1)
        return None if s is None else {'hash': s.password_hash, 'version': s.session_version}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# --- ilk kurulum ---------------------------------------------------------

def test_status_before_setup(client):
    body = client.get('/api/auth/status').get_json()
    assert body == {'configured': False, 'authenticated': False, 'setup_allowed': True,
                    'min_password_length': 12}


def test_status_from_remote_does_not_offer_setup():
    body = make_client('192.168.1.50').get('/api/auth/status').get_json()
    assert body['setup_allowed'] is False


def test_setup_rejected_from_non_loopback_address():
    res = setup_password(make_client('192.168.1.50'))
    assert res.status_code == 403
    assert res.get_json()['code'] == 'setup_loopback_only'
    assert stored_settings() is None


@pytest.mark.parametrize('addr', ['127.0.0.1', '127.0.0.2', '::1', '::ffff:127.0.0.1'])
def test_setup_allowed_from_loopback_variants(addr):
    assert setup_password(make_client(addr)).status_code == 201


@pytest.mark.parametrize('addr', ['10.0.0.1', '::ffff:10.0.0.1', 'localhost', '', None, 'garbage'])
def test_is_loopback_addr_rejects_others(addr):
    assert auth.is_loopback_addr(addr) is False


def test_setup_logs_in_and_stores_only_salted_hash(client):
    res = setup_password(client)
    assert res.status_code == 201
    assert client.get('/api/projects').status_code == 200
    assert client.get('/api/auth/status').get_json()['authenticated'] is True

    stored = stored_settings()
    assert PASSWORD not in stored['hash']
    assert stored['hash'].split(':', 1)[0] in ('scrypt', 'pbkdf2')
    assert check_password_hash(stored['hash'], PASSWORD)
    # Tuzlu: aynı parola iki kez farklı hash üretir.
    assert auth.hash_password(PASSWORD) != auth.hash_password(PASSWORD)


def test_setup_only_once(client):
    setup_password(client)
    res = setup_password(make_client(), 'saldirgan-parolasi-99')
    assert res.status_code == 409
    assert res.get_json()['code'] == 'already_configured'
    assert login(make_client()).status_code == 200
    assert login(make_client(), 'saldirgan-parolasi-99').status_code == 401


def test_login_before_setup_asks_for_setup(client):
    res = login(client)
    assert res.status_code == 409
    assert res.get_json()['code'] == 'setup_required'


# --- parola kuralı -------------------------------------------------------

@pytest.mark.parametrize('password,code', [
    ('a' * 11, 'password_too_short'),
    ('', 'password_required'),
    (None, 'password_required'),
    (123456789012, 'password_required'),
    (' boşluklu-parola', 'password_whitespace'),
    ('boşluklu-parola ', 'password_whitespace'),
    ('a' * 257, 'password_too_long'),
])
def test_password_policy_rejected(client, password, code):
    res = client.post('/api/auth/setup', json={'password': password})
    assert res.status_code == 400
    assert res.get_json()['code'] == code
    assert stored_settings() is None


def test_password_of_exactly_twelve_chars_accepted(client):
    assert setup_password(client, 'a' * 12).status_code == 201


# --- giriş / çıkış -------------------------------------------------------

def test_login_logout_flow(client):
    setup_password(make_client())
    assert client.get('/api/projects').status_code == 401

    res = login(client, 'yanlis-parola-000')
    assert res.status_code == 401
    assert res.get_json()['code'] == 'invalid_password'
    assert client.get('/api/projects').status_code == 401

    assert login(client).status_code == 200
    assert client.get('/api/projects').status_code == 200

    assert client.post('/api/auth/logout').status_code == 200
    assert client.get('/api/projects').status_code == 401
    assert client.get('/api/auth/status').get_json()['authenticated'] is False


def test_session_cookie_holds_no_secret(client):
    setup_password(client)
    with client.session_transaction() as sess:
        assert set(sess.keys()) == {'_permanent', 'auth', 'v', 'iat'}


def test_tampered_cookie_rejected(client):
    setup_password(make_client())
    client.set_cookie('wstg_session', 'eyJhdXRoIjp0cnVlLCJ2IjoxfQ.forged.signature')
    assert client.get('/api/projects').status_code == 401


def test_session_expires_after_lifetime(client, monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(app_module, '_now', clock)
    setup_password(client)
    assert client.get('/api/projects').status_code == 200
    clock.now += 12 * 3600 - 5
    assert client.get('/api/projects').status_code == 200
    clock.now += 10
    assert client.get('/api/projects').status_code == 401


# --- korunan rotalar ----------------------------------------------------

PROTECTED = [
    ('GET', '/api/sessions'),
    ('GET', '/api/projects'),
    ('POST', '/api/projects'),
    ('GET', '/api/projects/x/findings'),
    ('GET', '/api/projects/x/reports/technical'),
    ('POST', '/api/projects/x/reports/pdf'),
    ('GET', '/api/evidence/1/file'),
    ('POST', '/api/projects/x/evidence'),
    ('GET', '/api/ai/settings'),
    ('POST', '/api/ai/settings'),
    ('POST', '/api/recon'),
    ('POST', '/api/auth/change-password'),
    ('GET', '/api/does-not-exist'),
]


@pytest.mark.parametrize('method,path', PROTECTED)
def test_protected_routes_return_401_without_login(client, method, path):
    setup_password(make_client())
    res = client.open(path, method=method, json={})
    assert res.status_code == 401
    assert res.get_json()['code'] == 'auth_required'


@pytest.mark.parametrize('method,path', [
    ('GET', '/api/auth/status'), ('POST', '/api/auth/login'), ('POST', '/api/auth/logout'),
])
def test_open_endpoints_need_no_login(client, method, path):
    setup_password(make_client())
    res = client.open(path, method=method, json={})
    assert (res.get_json() or {}).get('code') != 'auth_required'


def test_401_is_readable_cross_origin(client):
    """Frontend 401'i okuyabilmeli; CORS başlıkları yoksa fetch ağ hatası verir
    ve 'backend yok' ile 'oturum düştü' ayırt edilemez."""
    setup_password(make_client())
    res = client.get('/api/projects', headers={'Origin': FRONTEND_ORIGIN})
    assert res.status_code == 401
    assert res.headers['Access-Control-Allow-Origin'] == FRONTEND_ORIGIN
    assert res.headers['Access-Control-Allow-Credentials'] == 'true'


def test_cors_preflight_needs_no_login(client):
    setup_password(make_client())
    res = client.options('/api/projects', headers={
        'Origin': FRONTEND_ORIGIN, 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type'})
    assert res.status_code == 200
    assert res.headers['Access-Control-Allow-Origin'] == FRONTEND_ORIGIN
    assert res.headers['Access-Control-Allow-Credentials'] == 'true'


def test_unlisted_origin_not_granted_credentials(client):
    res = client.get('/api/auth/status', headers={'Origin': 'https://evil.example'})
    assert 'Access-Control-Allow-Origin' not in res.headers


def test_host_and_origin_checks_still_run_before_auth(client):
    setup_password(make_client())
    assert client.get('/api/projects', headers={'Host': 'evil.example'}).status_code == 400
    assert client.get('/api/auth/status', headers={'Host': 'evil.example'}).status_code == 400
    res = client.post('/api/auth/login', json={'password': PASSWORD}, headers={'Origin': 'https://evil.example'})
    assert res.status_code == 403
    res = client.post('/api/auth/setup', json={'password': PASSWORD}, headers={'Origin': 'null'})
    assert res.status_code == 403


# --- deneme sınırı ------------------------------------------------------

def test_login_throttle(client, monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(app_module.login_throttle, 'clock', clock)
    setup_password(make_client())

    for _ in range(auth.FREE_ATTEMPTS):
        assert login(client, 'yanlis-parola-000').status_code == 401
    res = login(client, 'yanlis-parola-000')
    assert res.status_code == 429
    assert res.get_json()['code'] == 'too_many_attempts'
    assert int(res.headers['Retry-After']) == auth.BASE_LOCK_SECONDS + 1

    # Kilitliyken doğru parola da denenmez.
    assert login(client).status_code == 429

    # Başka bir istemci etkilenmez.
    assert login(make_client('10.0.0.7')).status_code == 200

    clock.now += auth.BASE_LOCK_SECONDS + 1
    # Bir hata daha: bekleme süresi ikiye katlanır.
    res = login(client, 'yanlis-parola-000')
    assert res.status_code == 429
    assert int(res.headers['Retry-After']) == 2 * auth.BASE_LOCK_SECONDS + 1

    clock.now += 2 * auth.BASE_LOCK_SECONDS + 1
    assert login(client).status_code == 200
    # Başarılı giriş sayacı sıfırlar.
    assert login(client, 'yanlis-parola-000').status_code == 401


def test_throttle_lock_is_capped():
    clock = FakeClock()
    throttle = auth.LoginThrottle(clock=clock)
    for _ in range(50):
        throttle.failure('k')
    assert throttle.retry_after('k') == auth.MAX_LOCK_SECONDS + 1


def test_wrong_current_password_counts_towards_throttle(client, monkeypatch):
    monkeypatch.setattr(app_module.login_throttle, 'clock', FakeClock())
    setup_password(client)
    for _ in range(auth.FREE_ATTEMPTS):
        res = client.post('/api/auth/change-password',
                          json={'current_password': 'yanlis-parola-000', 'new_password': NEW_PASSWORD})
        assert res.status_code == 403
    res = client.post('/api/auth/change-password',
                      json={'current_password': 'yanlis-parola-000', 'new_password': NEW_PASSWORD})
    assert res.status_code == 429


# --- parola değiştirme ---------------------------------------------------

def test_change_password_invalidates_other_sessions(client):
    setup_password(client)
    other = make_client()
    assert login(other).status_code == 200
    assert other.get('/api/projects').status_code == 200

    res = client.post('/api/auth/change-password',
                      json={'current_password': PASSWORD, 'new_password': NEW_PASSWORD})
    assert res.status_code == 200
    assert stored_settings()['version'] == 2

    assert client.get('/api/projects').status_code == 200   # bu oturum devam eder
    assert other.get('/api/projects').status_code == 401    # diğeri düşer

    assert login(make_client()).status_code == 401
    assert login(make_client(), NEW_PASSWORD).status_code == 200


def test_old_cookie_replay_rejected_after_password_change(client):
    setup_password(client)
    old_cookie = client.get_cookie('wstg_session').value
    client.post('/api/auth/change-password', json={'current_password': PASSWORD, 'new_password': NEW_PASSWORD})
    replay = make_client()
    replay.set_cookie('wstg_session', old_cookie)
    assert replay.get('/api/projects').status_code == 401


@pytest.mark.parametrize('payload,status,code', [
    ({'current_password': 'yanlis-parola-000', 'new_password': NEW_PASSWORD}, 403, 'invalid_current_password'),
    ({'current_password': PASSWORD, 'new_password': 'kisa'}, 400, 'password_too_short'),
    ({'current_password': PASSWORD, 'new_password': PASSWORD}, 400, 'password_unchanged'),
])
def test_change_password_rejections(client, payload, status, code):
    setup_password(client)
    res = client.post('/api/auth/change-password', json=payload)
    assert res.status_code == status
    assert res.get_json()['code'] == code
    assert stored_settings()['version'] == 1
    assert client.get('/api/projects').status_code == 200


# --- çerez bayrakları ----------------------------------------------------

def test_session_cookie_flags(client):
    res = setup_password(client)
    cookie = res.headers['Set-Cookie']
    parts = [p.strip().lower() for p in cookie.split(';')]
    assert parts[0].startswith('wstg_session=')
    assert 'httponly' in parts
    assert 'samesite=strict' in parts
    assert 'path=/' in parts
    assert 'secure' not in parts          # düz HTTP localhost; SESSION_COOKIE_SECURE ile açılır
    assert any(p.startswith('expires=') for p in parts)
    assert app_module.app.permanent_session_lifetime.total_seconds() == 12 * 3600


def test_session_not_refreshed_on_each_request(client):
    setup_password(client)
    assert 'Set-Cookie' not in client.get('/api/projects').headers


# --- set-password komutu -------------------------------------------------

def fake_prompt(*answers):
    it = iter(answers)
    return lambda _label='': next(it)


def test_set_password_command_creates_password(capsys, client):
    assert app_module.set_password_command(prompt=fake_prompt(PASSWORD, PASSWORD)) == 0
    assert stored_settings()['version'] == 1
    assert login(client).status_code == 200
    assert PASSWORD not in capsys.readouterr().out


def test_set_password_command_resets_and_logs_everyone_out(client):
    setup_password(client)
    assert client.get('/api/projects').status_code == 200
    assert app_module.set_password_command(prompt=fake_prompt(NEW_PASSWORD, NEW_PASSWORD)) == 0
    assert stored_settings()['version'] == 2
    assert client.get('/api/projects').status_code == 401
    assert login(make_client()).status_code == 401
    assert login(make_client(), NEW_PASSWORD).status_code == 200


@pytest.mark.parametrize('answers', [
    (PASSWORD, NEW_PASSWORD),     # eşleşmiyor
    ('kisa', 'kisa'),             # kural
])
def test_set_password_command_rejects(answers, capsys):
    assert app_module.set_password_command(prompt=fake_prompt(*answers)) == 1
    assert stored_settings() is None


def test_set_password_command_handles_ctrl_c():
    def interrupted(_label=''):
        raise KeyboardInterrupt
    assert app_module.set_password_command(prompt=interrupted) == 1
    assert stored_settings() is None


def test_main_dispatches_set_password(monkeypatch, client):
    monkeypatch.setattr(app_module.getpass, 'getpass', fake_prompt(PASSWORD, PASSWORD))
    assert app_module.main(['set-password']) == 0
    assert login(client).status_code == 200


def test_main_rejects_unknown_command(monkeypatch):
    monkeypatch.setattr(app_module.app, 'run', lambda *a, **k: pytest.fail('sunucu başlatılmamalı'))
    assert app_module.main(['bilinmeyen']) == 2
