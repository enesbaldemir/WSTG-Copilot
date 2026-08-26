"""
AI Ayarlari (uygulama arayuzunden API key yonetimi) icin uctan uca testler.
Gercek saglayicilara aglanilmiyor -- provider._call mocklaniyor.
"""

import sys, os
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

from unittest.mock import patch
import app as app_module
from ai.base import AIResult


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_settings_list_returns_masked_shape():
    client = _client()
    resp = client.get('/api/ai/settings')
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)
    print("OK: /api/ai/settings maskeli bir liste donuyor")


def test_settings_upsert_masks_key_and_never_returns_raw():
    client = _client()
    resp = client.post('/api/ai/settings', json={
        'provider': 'gemini', 'api_key': 'AIzaSyD-abcdef123456', 'model': 'gemini-3.7-flash'
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['api_key_masked'] == 'AIza...3456'
    assert 'AIzaSyD-abcdef123456' not in resp.get_data(as_text=True)
    assert body['has_key'] is True
    assert body['is_active'] is False

    listed = client.get('/api/ai/settings').get_json()
    assert len(listed) == 1
    assert listed[0]['api_key_masked'] == 'AIza...3456'
    print("OK: key hicbir zaman duz metin donmuyor, sadece maskelenmis hali")


def test_settings_upsert_without_key_keeps_existing_key():
    client = _client()
    client.post('/api/ai/settings', json={'provider': 'openai', 'api_key': 'sk-original-key-value', 'model': 'gpt-5.6-terra'})
    resp = client.post('/api/ai/settings', json={'provider': 'openai', 'model': 'gpt-5.6-luna'})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['model'] == 'gpt-5.6-luna'
    assert body['api_key_masked'] == 'sk-o...alue'  # eski key hala orada
    print("OK: api_key gonderilmezse mevcut key korunuyor, sadece model guncelleniyor")


def test_settings_activate_and_deactivate_others():
    # NOT: bu test dosyasindaki diger testler ayni sqlite dosyasini paylasiyor
    # (mevcut test dosyalarinin (test_new_features.py vb.) hepsinde oldugu
    # gibi per-test izolasyon yok) -- bu yuzden "tum liste" yerine SADECE bu
    # testin ilgilendigi saglayicilarin durumunu kontrol ediyoruz.
    client = _client()
    client.post('/api/ai/settings', json={'provider': 'gemini', 'api_key': 'key-a'})
    client.post('/api/ai/settings', json={'provider': 'anthropic', 'api_key': 'key-b'})
    client.post('/api/ai/settings/activate', json={'provider': 'gemini'})
    resp = client.post('/api/ai/settings/activate', json={'provider': 'anthropic'})
    assert resp.status_code == 200
    assert resp.get_json()['is_active'] is True

    listed = {s['provider']: s['is_active'] for s in client.get('/api/ai/settings').get_json()}
    assert listed['gemini'] is False
    assert listed['anthropic'] is True
    print("OK: bir saglayici aktif edilince digerleri otomatik pasife duser")


def test_activate_without_saved_settings_404():
    client = _client()
    resp = client.post('/api/ai/settings/activate', json={'provider': 'ollama'})
    assert resp.status_code == 404
    print("OK: kayitli ayari olmayan saglayici aktive edilemiyor")


def test_delete_setting():
    client = _client()
    client.post('/api/ai/settings', json={'provider': 'ollama', 'model': 'llama3.1'})
    resp = client.delete('/api/ai/settings/ollama')
    assert resp.status_code == 200
    providers = [s['provider'] for s in client.get('/api/ai/settings').get_json()]
    assert 'ollama' not in providers
    print("OK: ayar silinebiliyor")


def test_factory_prefers_active_db_setting_over_env():
    client = _client()
    client.post('/api/ai/settings', json={'provider': 'gemini', 'api_key': 'db-key', 'model': 'gemini-3.7-flash'})
    client.post('/api/ai/settings/activate', json={'provider': 'gemini'})

    with app_module.app.app_context():
        provider = app_module.get_ai_provider(app_module.app.config)
        assert provider.name == 'gemini'
        assert provider.api_key == 'db-key'
    print("OK: DB'de aktif ayar varsa .env yerine o kullaniliyor")


def test_settings_test_endpoint_reports_failure_without_leaking_key():
    client = _client()
    with patch.object(app_module, '_ping_provider', return_value={'ok': False, 'provider': 'gemini', 'error': 'boom (401)', 'error_type': 'auth_error'}):
        resp = client.post('/api/ai/settings/test', json={'provider': 'gemini', 'api_key': 'super-secret-value'})
    assert resp.status_code == 503
    body = resp.get_json()
    assert body['error_type'] == 'auth_error'
    assert 'super-secret-value' not in resp.get_data(as_text=True)
    print("OK: /settings/test hatasi acik ama key'i asla iceriyor")
