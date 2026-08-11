import sys, os
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

from unittest.mock import patch
import app as app_module
from ai.base import BaseAIProvider, AIResult


class FakeProvider(BaseAIProvider):
    name = "fake"
    model = "fake-model-1"
    def __init__(self, canned_text, configured=True):
        self.canned_text = canned_text
        self.configured = configured
    def is_configured(self):
        return self.configured
    def _call(self, system_prompt, user_prompt, max_tokens):
        return AIResult(text=self.canned_text, provider=self.name, model=self.model, latency_ms=0)


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_happy_path_via_route():
    client = _client()
    sess_resp = client.post('/api/sessions', json={'name': 'Next-Test Route Test'})
    session_id = sess_resp.get_json()['id']

    canned = ('{"suggested_test_id": "WSTG-SESS-01", '
              '"reasoning": "Kimlik dogrulama zafiyeti bulundu, oturum yonetimi test edilmeli.", '
              '"priority": "high", "alternative_test_ids": ["WSTG-SESS-02"]}')
    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider(canned)):
        resp = client.post('/api/ai/suggest-next-test', json={
            'completed_test_ids': ['WSTG-ATHN-01'],
            'findings': [{'title': 'Login SQLi', 'severity': 'critical', 'test_id': 'WSTG-ATHN-01', 'cwe_id': 'CWE-89'}],
            'session_id': session_id
        })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['suggested_test_id'] == 'WSTG-SESS-01'
    assert body['suggestion_grounded'] is True
    assert body['suggested_test_title']
    assert body['provider'] == 'fake'

    logs = client.get(f'/api/ai/logs?session_id={session_id}&purpose=next_test_suggestion').get_json()
    assert len(logs) == 1 and logs[0]['success'] is True
    print("OK: /api/ai/suggest-next-test mutlu senaryo uçtan uca çalışıyor ve loglanıyor")


def test_all_done_short_circuits_via_route():
    client = _client()
    from mapping import get_all_tests
    all_ids = [t['id'] for t in get_all_tests('tr')]

    def boom(*a, **k):
        raise AssertionError("AI cagrilmamali!")
    fake = FakeProvider('irrelevant')
    with patch.object(app_module, 'get_ai_provider', return_value=fake):
        with patch.object(fake, 'chat', side_effect=boom):
            resp = client.post('/api/ai/suggest-next-test', json={'completed_test_ids': all_ids})
    assert resp.status_code == 200
    assert resp.get_json()['all_done'] is True
    print("OK: tüm testler tamamlanmışsa route AI'ı hiç çağırmadan 'all_done' döner")


def test_not_configured_via_route():
    client = _client()
    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider('{}', configured=False)):
        resp = client.post('/api/ai/suggest-next-test', json={})
    assert resp.status_code == 200
    assert 'error' in resp.get_json()
    print("OK: sağlayıcı yapılandırılmamışsa zarif hata mesajı döner")


if __name__ == '__main__':
    test_happy_path_via_route()
    test_all_done_short_circuits_via_route()
    test_not_configured_via_route()
    print("\nTüm /api/ai/suggest-next-test entegrasyon testleri geçti.")
