"""
Hata yanıtları: beklenmeyen istisnaların metni istemciye gitmez.

- 500: genel mesaj + kısa hata kimliği; tam traceback aynı kimlikle
  app.logger'a (backend terminali) yazılır.
- try/except içindeki get_or_404 / bozuk JSON artık 404 / 400 döner
  (eskiden 500 + werkzeug metni).
- Kasıtlı, kullanıcıya yönelik mesajlar (doğrulama, AI yapılandırması)
  değişmeden gösterilir.
"""
import logging
import os
import re
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest

import app as app_module
import report_pdf

SECRET = r"sqlite3.OperationalError: no such table: findings_x  C:\Users\Attar\WSTG-Copilot\backend\database\wstg.db"


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def project_id(client):
    return client.post('/api/projects', json={'name': 'Hata testi'}).get_json()['id']


def boom(*_a, **_k):
    raise RuntimeError(SECRET)


def test_unexpected_error_hides_details_and_logs_them(client, project_id, monkeypatch, caplog):
    monkeypatch.setattr(report_pdf, 'build_pdf_report', boom)
    with caplog.at_level(logging.ERROR, logger=app_module.app.logger.name):
        r = client.post(f'/api/projects/{project_id}/reports/pdf', json={})
    assert r.status_code == 500
    body = r.get_json()
    assert 'OperationalError' not in body['error'] and 'Attar' not in body['error'] and 'wstg.db' not in body['error']
    assert re.fullmatch(r'[0-9a-f]{8}', body['error_id'])
    assert body['error_id'] in body['error']
    # Ayrıntı kaybolmaz: aynı kimlikle sunucu günlüğünde.
    logged = '\n'.join(rec.getMessage() + (rec.exc_text or '') for rec in caplog.records)
    assert body['error_id'] in logged
    assert any(rec.exc_info and 'no such table' in str(rec.exc_info[1]) for rec in caplog.records)


def test_pdf_report_error_uses_public_message(client, project_id, monkeypatch):
    def fail(*_a, **_k):
        raise report_pdf.PdfReportError(r'PDF fontu yüklenemedi: [Errno 2] C:\Python313\Lib\reportlab\fonts\Vera.ttf')
    monkeypatch.setattr(report_pdf, 'build_pdf_report', fail)
    r = client.post(f'/api/projects/{project_id}/reports/pdf', json={})
    assert r.status_code == 500
    assert r.get_json()['error'].startswith('PDF oluşturulamadı.')
    assert 'Python313' not in r.get_json()['error']


@pytest.mark.parametrize('method,path', [
    ('GET', '/api/sessions/yok'),
    ('PUT', '/api/sessions/yok'),
    ('DELETE', '/api/sessions/yok'),
    ('GET', '/api/sessions/yok/results/WSTG-INFO-01'),
    ('PUT', '/api/sessions/yok/results/WSTG-INFO-01'),
])
def test_missing_records_are_404_not_500(client, method, path):
    r = client.open(path, method=method, json={'name': 'x'})
    assert r.status_code == 404, r.get_json()
    assert 'error_id' not in r.get_json()


def test_malformed_json_is_400_not_500(client):
    r = client.post('/api/sessions', data='{"name": ', content_type='application/json')
    assert r.status_code == 400
    assert 'Geçersiz istek' in r.get_json()['error']


def test_validation_messages_still_reach_the_user(client):
    r = client.post('/api/sessions', json={'name': ''})
    assert r.status_code == 400 and r.get_json()['error'] == 'Oturum adı zorunludur'


def test_ping_provider_hides_unexpected_errors():
    class Broken:
        name = 'gemini'
        def chat(self, **_k):
            raise RuntimeError(SECRET)
    with app_module.app.test_request_context('/api/ai/settings/test', method='POST'):
        out = app_module._ping_provider(Broken())
    assert out['ok'] is False and out['error_type'] == 'unknown'
    assert 'OperationalError' not in out['error'] and 'hata kimliği' in out['error']


def test_no_raw_exception_text_in_500_responses():
    """Gerileme koruması: app.py'de str(e) ile 500 dönen satır kalmasın."""
    src = open(os.path.join(os.path.dirname(__file__), 'app.py'), encoding='utf-8').read()
    assert not re.search(r"jsonify\(\{'error': str\(e\)[^\n]*\), 500", src)
