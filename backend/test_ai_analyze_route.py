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


def test_full_happy_path_via_route():
    client = _client()
    sess_resp = client.post('/api/sessions', json={'name': 'AI Route Test'})
    session_id = sess_resp.get_json()['id']

    canned = ('{"suggested_cwe_id": "CWE-89", "suggested_cwe_name": "SQL Injection", '
              '"suggested_severity": "critical", "suggested_cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", '
              '"false_positive_likelihood": "low", "false_positive_reasoning": "Somut payload var.", '
              '"rationale": "Klasik SQLi."}')
    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider(canned)):
        resp = client.post('/api/ai/analyze-finding', json={
            'title': 'Login SQLi',
            'content': "' OR 1=1-- ile giris yapildi",
            'test_id': 'WSTG-INPV-05',
            'session_id': session_id
        })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body['suggested_cwe_id'] == 'CWE-89'
    assert body['suggested_cvss_score'] == 9.8
    assert body['provider'] == 'fake'
    assert body['cwe_grounded'] is True  # WSTG-INPV-05 -> Injection kategorisi -> CWE-89 aday listesinde

    # AIInteractionLog'a dogru sekilde yazilmis mi kontrol et
    logs_resp = client.get(f'/api/ai/logs?session_id={session_id}&purpose=finding_analysis')
    logs = logs_resp.get_json()
    assert len(logs) == 1
    assert logs[0]['success'] is True
    assert logs[0]['provider'] == 'fake'
    print("OK: /api/ai/analyze-finding mutlu senaryo uctan uca calisiyor ve loglaniyor")


def test_not_configured_via_route():
    client = _client()
    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider('{}', configured=False)):
        resp = client.post('/api/ai/analyze-finding', json={'content': 'bir bulgu'})
    assert resp.status_code == 200
    assert 'error' in resp.get_json()
    print("OK: sağlayıcı yapılandırılmamışsa route zarif bir hata mesajıyla 200 dönüyor")


def test_invalid_ai_response_via_route():
    client = _client()
    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider('duz metin, json degil')):
        resp = client.post('/api/ai/analyze-finding', json={'content': 'bir bulgu'})
    assert resp.status_code == 502
    assert 'error' in resp.get_json()

    logs_resp = client.get('/api/ai/logs?purpose=finding_analysis')
    logs = logs_resp.get_json()
    assert any(l['success'] is False for l in logs)
    print("OK: geçersiz AI yanıtı 502 döner ve başarısız çağrı olarak loglanır")


def test_empty_content_via_route():
    client = _client()
    resp = client.post('/api/ai/analyze-finding', json={'content': '  '})
    assert resp.status_code == 400
    print("OK: boş içerik route seviyesinde 400 ile reddediliyor (AI'a hiç gitmiyor)")


if __name__ == '__main__':
    test_full_happy_path_via_route()
    test_not_configured_via_route()
    test_invalid_ai_response_via_route()
    test_empty_content_via_route()
    print("\nTüm /api/ai/analyze-finding entegrasyon testleri geçti.")
