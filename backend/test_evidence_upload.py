"""
Kanıt (ekran görüntüsü) yükleme ve sunma güvenliği.

- Tür, istemcinin gönderdiği Content-Type'tan değil içerikten belirlenir.
- Görsel olmayan içerik reddedilir; diske yazılmaz, kayıt oluşmaz.
- Sunulurken disk içeriği yeniden kontrol edilir; doğrulama gelmeden önce
  yüklenmiş görsel olmayan dosyalar tarayıcıda açılmaz, indirilir.
- Tüm yanıtlarda nosniff / X-Frame-Options; dosyalarda sandbox CSP.
"""
import io
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest

import app as app_module
import image_types
from conftest import TEST_UPLOAD_DIR
from models import db, Evidence

PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
    '0000000d4944415478da63f8cfc0f01f0005000201a8e3a0860000000049454e44ae426082')
JPEG = b'\xff\xd8\xff\xe0' + b'\x00' * 32
HTML = b'<html><script>alert(document.cookie)</script></html>'
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def project_id(client):
    return client.post('/api/projects', json={'name': 'Kanıt testi'}).get_json()['id']


def upload(client, pid, data, name='shot.png', content_type='image/png'):
    return client.post(f'/api/projects/{pid}/evidence', content_type='multipart/form-data',
                       data={'file': (io.BytesIO(data), name, content_type)})


def stored_files(pid):
    d = os.path.join(TEST_UPLOAD_DIR, 'evidence', pid)
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def test_detect_image_type():
    assert image_types.detect_image_type(PNG) == 'png'
    assert image_types.detect_image_type(JPEG) == 'jpeg'
    assert image_types.detect_image_type(b'GIF89a....') == 'gif'
    assert image_types.detect_image_type(b'RIFF\x00\x00\x00\x00WEBPVP8 ') == 'webp'
    for bad in (b'', None, HTML, SVG, b'%PDF-1.7', b'PK\x03\x04', b'\x89PNG'):
        assert image_types.detect_image_type(bad) is None


def test_valid_png_upload_and_serve(client, project_id):
    r = upload(client, project_id, PNG)
    assert r.status_code == 201, r.get_json()
    ev = r.get_json()
    assert ev['mime_type'] == 'image/png'
    assert stored_files(project_id)[0].endswith('.png')

    f = client.get(f'/api/evidence/{ev["id"]}/file')
    assert f.status_code == 200 and f.data == PNG
    assert f.mimetype == 'image/png'
    assert f.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'sandbox' in f.headers['Content-Security-Policy']
    assert 'attachment' not in f.headers.get('Content-Disposition', '')


@pytest.mark.parametrize('data,declared', [
    (HTML, 'image/png'),          # HTML'i görsel diye yüklemek
    (SVG, 'image/svg+xml'),       # SVG (script çalıştırabilir)
    (SVG, 'image/png'),
    (b'%PDF-1.7 ...', 'image/jpeg'),
    (b'\x89PNG', 'image/png'),    # yarım başlık
])
def test_non_image_content_rejected_and_not_stored(client, project_id, data, declared):
    r = upload(client, project_id, data, content_type=declared)
    assert r.status_code == 400
    assert stored_files(project_id) == []
    with app_module.app.app_context():
        assert Evidence.query.filter_by(project_id=project_id).count() == 0


def test_type_comes_from_content_not_from_client(client, project_id):
    # Tarayıcı yanlış tür bildirse de içerik geçerli bir görselse kabul edilir,
    # ama saklanan tür/uzantı içeriğe göredir.
    r = upload(client, project_id, JPEG, name='a.png', content_type='text/html')
    assert r.status_code == 201
    assert r.get_json()['mime_type'] == 'image/jpeg'
    assert stored_files(project_id)[0].endswith('.jpg')


def test_empty_and_missing_file(client, project_id):
    assert upload(client, project_id, b'').status_code == 400
    r = client.post(f'/api/projects/{project_id}/evidence', content_type='multipart/form-data', data={})
    assert r.status_code == 400


def test_legacy_non_image_file_is_downloaded_not_rendered(client, project_id):
    """Doğrulama gelmeden önce 'image/png' diye kaydedilmiş bir HTML dosyası."""
    d = os.path.join(TEST_UPLOAD_DIR, 'evidence', project_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'legacy.png'), 'wb') as fh:
        fh.write(HTML)
    with app_module.app.app_context():
        ev = Evidence(project_id=project_id, evidence_type='image', filename='screen<x>.png',
                      stored_filename='legacy.png', mime_type='image/png', size_bytes=len(HTML))
        db.session.add(ev)
        db.session.commit()
        eid = ev.id
    f = client.get(f'/api/evidence/{eid}/file')
    assert f.status_code == 200
    assert f.mimetype == 'application/octet-stream'
    assert f.headers['Content-Disposition'].startswith('attachment')
    assert f.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'sandbox' in f.headers['Content-Security-Policy']


def test_stored_filename_cannot_escape_evidence_dir(client, project_id):
    secret = os.path.join(TEST_UPLOAD_DIR, 'evidence', 'secret.png')
    os.makedirs(os.path.dirname(secret), exist_ok=True)
    with open(secret, 'wb') as fh:
        fh.write(PNG)
    with app_module.app.app_context():
        ev = Evidence(project_id=project_id, evidence_type='image', filename='x.png',
                      stored_filename='../secret.png', mime_type='image/png', size_bytes=1)
        db.session.add(ev)
        db.session.commit()
        eid = ev.id
    assert client.get(f'/api/evidence/{eid}/file').status_code == 404


def test_security_headers_on_every_response(client):
    for path in ('/api/auth/status', '/api/projects', '/api/does-not-exist'):
        r = client.get(path)
        assert r.headers['X-Content-Type-Options'] == 'nosniff', path
        assert r.headers['X-Frame-Options'] == 'DENY', path
        assert r.headers['Referrer-Policy'] == 'no-referrer', path


def test_oversized_upload_returns_json_413(client, project_id, monkeypatch):
    monkeypatch.setitem(app_module.app.config, 'MAX_CONTENT_LENGTH', 1024)
    r = upload(client, project_id, PNG + b'\x00' * 4096)
    assert r.status_code == 413
    assert 'MB' in r.get_json()['error'] or 'büyük' in r.get_json()['error']
    assert stored_files(project_id) == []
