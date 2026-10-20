"""
Not Defteri, WSTG eşleme ve çalışma metrikleri rotaları (260eeb6 ile
kaldırılıp geri getirilen özellikler) + notes.py doğrulaması.
"""
import base64
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest
from sqlalchemy import text

import app as app_module
import notes as notes_lib
from models import db, AIInteractionLog

# 1x1 piksel gerçek PNG / GIF; JPEG ve WebP için yalnızca başlık baytları yeter.
PNG = base64.b64encode(bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
    '0000000d4944415478da63f8cfc0f01f0005000201a8e3a0860000000049454e44ae426082')).decode()
GIF = base64.b64encode(b'GIF89a\x01\x00\x01\x00\x00\x00\x00;').decode()
JPEG = base64.b64encode(b'\xff\xd8\xff\xe0' + b'\x00' * 16).decode()
WEBP = base64.b64encode(b'RIFF\x10\x00\x00\x00WEBPVP8 ' + b'\x00' * 8).decode()


def png_url():
    return f'data:image/png;base64,{PNG}'


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def sid(client):
    return client.post('/api/sessions', json={'name': 'Not testi'}).get_json()['id']


# --- notes.py: görsel doğrulama -------------------------------------------

@pytest.mark.parametrize('url', [
    f'data:image/png;base64,{PNG}', f'data:image/gif;base64,{GIF}',
    f'data:image/jpeg;base64,{JPEG}', f'data:image/jpg;base64,{JPEG}', f'data:image/webp;base64,{WEBP}',
])
def test_valid_images_accepted(url):
    assert notes_lib.validate_image_data_url(url).startswith('data:image/')


@pytest.mark.parametrize('url,why', [
    ('data:image/x" onerror="alert(1)', 'attribute dışına taşma'),
    (f'data:image/png;base64,{PNG}" onerror="alert(1)', 'geçerli önek + taşma'),
    ('data:image/svg+xml;base64,' + base64.b64encode(b'<svg onload=alert(1)>').decode(), 'SVG'),
    (f'data:image/png;base64,{JPEG}', 'png diyor, içerik jpeg'),
    ('data:image/png;base64,' + base64.b64encode(b'<html>').decode(), 'png diyor, içerik html'),
    ('data:image/png;base64,@@@@', 'base64 değil'),
    (f'DATA:image/png;base64,{PNG}', 'büyük harf şema'),
    ('javascript:alert(1)', 'javascript: şeması'),
    (None, 'boş'),
])
def test_unsafe_images_rejected(url, why):
    with pytest.raises(notes_lib.NoteValidationError):
        notes_lib.validate_image_data_url(url)


def test_image_limits():
    big = base64.b64encode(b'\x89PNG\r\n\x1a\n' + b'\x00' * notes_lib.MAX_NOTE_IMAGE_BYTES).decode()
    with pytest.raises(notes_lib.NoteValidationError):
        notes_lib.validate_image_data_url(f'data:image/png;base64,{big}')
    too_many = [{'name': 'a', 'data': png_url()}] * (notes_lib.MAX_NOTE_IMAGES + 1)
    with pytest.raises(notes_lib.NoteValidationError):
        notes_lib.sanitize_images(too_many)


def test_image_name_control_chars_stripped():
    import json
    out = json.loads(notes_lib.sanitize_images([{'name': 'a\x00b\nc' + 'x' * 500, 'data': png_url()}]))
    assert out[0]['name'].startswith('abc') and len(out[0]['name']) == notes_lib.MAX_NAME_LENGTH


# --- rotalar --------------------------------------------------------------

def test_note_crud_roundtrip(client, sid):
    r = client.post(f'/api/sessions/{sid}/notes', json={
        'title': 'Login SQLi', 'content': "' OR 1=1--", 'severity': 'high',
        'test_id': 'WSTG-INPV-05', 'images': [{'name': 'kanit.png', 'data': png_url()}],
    })
    assert r.status_code == 201, r.get_json()
    note = r.get_json()
    assert note['images'][0]['data'] == png_url() and note['is_false_positive'] is None

    listed = client.get(f'/api/sessions/{sid}/notes').get_json()
    assert [n['id'] for n in listed] == [note['id']]
    assert client.get(f'/api/sessions/{sid}/notes?test_id=WSTG-INPV-05').get_json()
    assert client.get(f'/api/sessions/{sid}/notes?test_id=WSTG-ATHN-01').get_json() == []

    up = client.put(f'/api/sessions/{sid}/notes/{note["id"]}', json={'title': 'Yeni', 'images': []})
    assert up.status_code == 200 and up.get_json()['title'] == 'Yeni' and up.get_json()['images'] == []
    assert up.get_json()['content'] == "' OR 1=1--"   # gönderilmeyen alan korunur

    assert client.delete(f'/api/sessions/{sid}/notes/{note["id"]}').status_code == 200
    assert client.get(f'/api/sessions/{sid}/notes').get_json() == []


def test_xss_image_rejected_by_route_and_not_stored(client, sid):
    r = client.post(f'/api/sessions/{sid}/notes', json={
        'content': 'x', 'images': [{'name': 'a', 'data': 'data:image/x" onerror="alert(1)'}]})
    assert r.status_code == 400
    assert client.get(f'/api/sessions/{sid}/notes').get_json() == []


def test_cvss_computed_on_server(client, sid):
    r = client.post(f'/api/sessions/{sid}/notes', json={
        'content': 'x', 'cvss_vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'cvss_score': 1.0, 'cvss_rating': 'low'})   # istemci skoru yok sayılır
    n = r.get_json()
    assert (n['cvss_score'], n['cvss_rating'], n['cvss_vector']) == \
        (9.8, 'critical', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    bad = client.put(f'/api/sessions/{sid}/notes/{n["id"]}', json={'cvss_vector': 'AV:X/AC:L'})
    assert bad.status_code == 400
    cleared = client.put(f'/api/sessions/{sid}/notes/{n["id"]}', json={'cvss_vector': ''}).get_json()
    assert cleared['cvss_score'] is None and cleared['cvss_vector'] is None


@pytest.mark.parametrize('payload', [
    {'content': ''},                                   # içerik de görsel de yok
    {'content': 'x', 'severity': 'urgent'},
    {'content': 'x', 'cwe_id': 'SQLi'},
    {'content': 'x', 'test_id': '<script>'},
    {'content': 'x', 'is_false_positive': 'yes'},
    {'content': 'x', 'images': 'not-a-list'},
])
def test_invalid_payloads_rejected(client, sid, payload):
    assert client.post(f'/api/sessions/{sid}/notes', json=payload).status_code == 400


def test_cwe_normalized(client, sid):
    n = client.post(f'/api/sessions/{sid}/notes', json={'content': 'x', 'cwe_id': '89', 'cwe_name': ' SQL Injection '}).get_json()
    assert (n['cwe_id'], n['cwe_name']) == ('CWE-89', 'SQL Injection')


def test_failed_update_changes_nothing(client, sid):
    n = client.post(f'/api/sessions/{sid}/notes', json={'title': 'Eski', 'content': 'x'}).get_json()
    r = client.put(f'/api/sessions/{sid}/notes/{n["id"]}', json={'title': 'Yeni', 'severity': 'urgent'})
    assert r.status_code == 400
    assert client.get(f'/api/sessions/{sid}/notes').get_json()[0]['title'] == 'Eski'


def test_notes_scoped_to_session(client, sid):
    other = client.post('/api/sessions', json={'name': 'Başka'}).get_json()['id']
    n = client.post(f'/api/sessions/{sid}/notes', json={'content': 'x'}).get_json()
    assert client.put(f'/api/sessions/{other}/notes/{n["id"]}', json={'title': 'y'}).status_code == 404
    assert client.delete(f'/api/sessions/{other}/notes/{n["id"]}').status_code == 404
    assert client.get('/api/sessions/yok/notes').status_code == 404
    assert client.post('/api/sessions/yok/notes', json={'content': 'x'}).status_code == 404


def test_deleting_session_deletes_its_notes(client, sid):
    client.post(f'/api/sessions/{sid}/notes', json={'content': 'x'})
    assert client.delete(f'/api/sessions/{sid}').status_code == 200
    with app_module.app.app_context():
        left = db.session.execute(text('SELECT COUNT(*) FROM notes WHERE session_id = :s'), {'s': sid}).scalar()
    assert left == 0


def test_mapping_route():
    c = app_module.app.test_client()
    body = c.get('/api/mapping/wstg/WSTG-INPV-05').get_json()
    assert body['test_id'] == 'WSTG-INPV-05'
    assert isinstance(body['owasp_matches'], list) and isinstance(body['suggested_cwes'], list)
    assert any(c_['id'] == 'CWE-89' for c_ in body['suggested_cwes']), body['suggested_cwes']


def test_session_complete_and_reopen(client, sid):
    done = client.put(f'/api/sessions/{sid}', json={'status': 'completed'}).get_json()
    assert done['completed_at']
    reopened = client.put(f'/api/sessions/{sid}', json={'status': 'active'}).get_json()
    assert reopened['completed_at'] is None


def test_invalid_study_group_update_changes_nothing(client, sid):
    r = client.put(f'/api/sessions/{sid}', json={'name': 'Değişmemeli', 'study_group': 'bogus'})
    assert r.status_code == 400
    assert client.get(f'/api/sessions/{sid}').get_json()['name'] == 'Not testi'


def test_study_metrics_counts_findings_and_finding_ai_calls(client):
    project = client.post('/api/projects', json={'name': 'Çalışma'}).get_json()
    s = client.post('/api/sessions', json={'name': 'AI S', 'study_group': 'ai_assisted', 'project_id': project['id']}).get_json()
    client.post(f'/api/sessions/{s["id"]}/notes', json={'content': 'not', 'severity': 'low', 'is_false_positive': True})
    f = client.post(f'/api/projects/{project["id"]}/findings', json={
        'title': 'IDOR', 'severity': 'high', 'session_id': s['id']}).get_json()
    with app_module.app.app_context():
        db.session.add(AIInteractionLog(project_id=project['id'], finding_id=f['id'], purpose='finding_analysis', success=True, latency_ms=100))
        db.session.add(AIInteractionLog(session_id=s['id'], purpose='next_test_suggestion', success=False))
        db.session.commit()
    body = client.get('/api/study/metrics').get_json()
    m = next(x for x in body['sessions'] if x['session_id'] == s['id'])
    assert m['total_findings'] == 2
    assert m['severity_counts'] == {'low': 1, 'high': 1}
    assert m['confirmed_false_positives'] == 1 and m['undetermined_findings'] == 1
    assert m['ai_calls_total'] == 2 and m['ai_success_rate_pct'] == 50.0


def test_legacy_database_compatibility(client):
    """260eeb6 öncesinden kalan bir veritabanı: notes tablosunda eski satırlar
    var; araya giren sürümlerde oluşturulmuş bir DB'de study_group sütunu yok."""
    sid = client.post('/api/sessions', json={'name': 'Eski oturum'}).get_json()['id']
    with app_module.app.app_context():
        db.session.execute(text(
            "INSERT INTO notes (session_id, title, content, severity, images, cwe_id, is_false_positive, created_at, updated_at) "
            "VALUES (:s, 'Eski not', 'eski içerik', 'medium', '[]', 'CWE-79', 0, '2026-08-01 10:00:00', '2026-08-01 10:00:00')"),
            {'s': sid})
        db.session.execute(text('ALTER TABLE sessions DROP COLUMN study_group'))
        db.session.commit()
        cols = [r[1] for r in db.session.execute(text('PRAGMA table_info(sessions)'))]
        assert 'study_group' not in cols
        app_module.ensure_schema()
        cols = [r[1] for r in db.session.execute(text('PRAGMA table_info(sessions)'))]
        assert 'study_group' in cols
    notes = client.get(f'/api/sessions/{sid}/notes').get_json()
    assert notes[0]['title'] == 'Eski not' and notes[0]['is_false_positive'] is False
    assert client.get(f'/api/sessions/{sid}').get_json()['study_group'] is None
