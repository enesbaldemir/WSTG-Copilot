"""Proje yedekleme: dışa aktarma ve yeni proje olarak geri yükleme."""
import base64
import io
import json
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest

import app as app_module
from models import Evidence, Project

PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
    '0000000d4944415478da63f8cfc0f01f0005000201a8e3a0860000000049454e44ae426082')
PNG_URL = 'data:image/png;base64,' + base64.b64encode(PNG).decode()


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def full_project(client):
    pid = client.post('/api/projects', json={'name': 'Yedek Kaynağı', 'client': 'Acme', 'status': 'active',
                                             'start_date': '2026-10-01'}).get_json()['id']
    client.post(f'/api/projects/{pid}/scope', json={'type': 'domain', 'value': 'shop.acme.example'})
    client.post(f'/api/projects/{pid}/custom-tests', json={'title': 'Özel test', 'description': 'd'})
    sid = client.post('/api/sessions', json={'name': 'Oturum', 'project_id': pid, 'target_url': 'https://shop.acme.example'}).get_json()['id']
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-ATHZ-04', 'status': 'failed', 'finding': 'not', 'severity': 'high'})
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-CRYP-01', 'status': 'skipped'})
    r = client.post(f'/api/sessions/{sid}/notes', json={'title': 'Not', 'content': 'içerik', 'images': [{'name': 'a.png', 'data': PNG_URL}],
                                                       'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'})
    assert r.status_code == 201, r.get_json()
    f = client.post(f'/api/projects/{pid}/findings', json={'title': 'IDOR', 'severity': 'high', 'session_id': sid,
                                                         'steps_to_reproduce': '1. adım', 'test_id': 'WSTG-ATHZ-04'}).get_json()
    up = client.post(f'/api/projects/{pid}/evidence', content_type='multipart/form-data',
                     data={'file': (io.BytesIO(PNG), 'kanit.png', 'image/png'), 'linked_finding_id': str(f['id'])})
    assert up.status_code == 201
    client.put(f'/api/projects/{pid}/authz-matrix', json={'roles': [{'id': 'u', 'name': 'Kullanıcı'}],
                                                          'endpoints': [{'id': 'e', 'method': 'GET', 'path': '/a'}],
                                                          'cells': {'e:u': {'expected': 'deny', 'observed': 'allowed'}}})
    return pid, sid, f['id']


def _export(client, pid):
    r = client.get(f'/api/projects/{pid}/export')
    assert r.status_code == 200 and r.mimetype == 'application/json'
    assert 'attachment' in r.headers['Content-Disposition'] and '-yedek-' in r.headers['Content-Disposition']
    return json.loads(r.data)


def test_export_contents(client, full_project):
    pid, _, _ = full_project
    data = _export(client, pid)
    assert data['format'] == 'wstg-copilot-project' and data['version'] == 1
    assert data['project']['name'] == 'Yedek Kaynağı' and 'id' not in data['project']
    assert len(data['scope_items']) == 1 and len(data['custom_tests']) == 1
    assert len(data['sessions']) == 1 and len(data['sessions'][0]['results']) == 2 and len(data['sessions'][0]['notes']) == 1
    assert data['findings'][0]['steps_to_reproduce'] == '1. adım'
    ev = data['evidence'][0]
    assert base64.b64decode(ev['file_base64']) == PNG and 'stored_filename' not in ev
    assert data['authz_matrix']['roles'][0]['name'] == 'Kullanıcı'
    assert data['timeline']


def test_round_trip_creates_new_linked_project(client, full_project):
    pid, sid, fid = full_project
    data = _export(client, pid)
    r = client.post('/api/projects/import', json=data)
    assert r.status_code == 201, r.get_json()
    new = r.get_json()
    assert new['id'] != pid and new['name'] == 'Yedek Kaynağı (yedek)' and new['client'] == 'Acme' and new['start_date'] == '2026-10-01'
    nid = new['id']
    assert [s['value'] for s in client.get(f'/api/projects/{nid}/scope').get_json()] == ['shop.acme.example']
    sessions = client.get(f'/api/sessions?project_id={nid}').get_json()
    assert len(sessions) == 1 and sessions[0]['id'] != sid and sessions[0]['target_url'] == 'https://shop.acme.example'
    results = {x['test_id']: x['status'] for x in client.get(f'/api/sessions/{sessions[0]["id"]}/results').get_json()}
    assert results == {'WSTG-ATHZ-04': 'failed', 'WSTG-CRYP-01': 'skipped'}
    notes = client.get(f'/api/sessions/{sessions[0]["id"]}/notes').get_json()
    notes = notes if isinstance(notes, list) else notes.get('notes', [])
    assert notes[0]['images'][0]['data'] == PNG_URL and notes[0]['cvss_score'] == 9.8
    findings = client.get(f'/api/projects/{nid}/findings').get_json()
    assert len(findings) == 1 and findings[0]['id'] != fid and findings[0]['session_id'] == sessions[0]['id']
    evidence = client.get(f'/api/projects/{nid}/evidence').get_json()
    assert evidence[0]['linked_finding_id'] == findings[0]['id']
    file_resp = client.get(f'/api/evidence/{evidence[0]["id"]}/file')
    assert file_resp.status_code == 200 and file_resp.data == PNG
    assert client.get(f'/api/projects/{nid}/authz-matrix').get_json()['roles'][0]['name'] == 'Kullanıcı'
    assert any(e.get('event_type') == 'project_imported' for e in client.get(f'/api/projects/{nid}/timeline').get_json())
    # Kaynak proje değişmedi; ikinci içe aktarma yeni bir ad alır
    assert len(client.get(f'/api/projects/{pid}/findings').get_json()) == 1
    assert client.post('/api/projects/import', json=data).get_json()['name'] == 'Yedek Kaynağı (yedek 3)'


def _count_projects():
    with app_module.app.app_context():
        return Project.query.count(), Evidence.query.count()


@pytest.mark.parametrize('mutate,needle', [
    (lambda d: d.update(format='baska'), 'yedeği değil'),
    (lambda d: d.update(version=2), 'sürümü'),
    (lambda d: d['findings'][0].update(severity='High'), 'severity'),
    (lambda d: d['findings'][0].update(status='hacked'), 'status'),
    (lambda d: d['sessions'][0]['results'][0].update(status='done'), 'status'),
    (lambda d: d['scope_items'][0].update(type='url'), 'type'),
    (lambda d: d['project'].update(name='x' * 201), 'çok uzun'),
    (lambda d: d['project'].update(start_date=12), 'start_date'),
    (lambda d: d['evidence'][0].update(file_base64=base64.b64encode(b'<svg onload=alert(1)>').decode()), 'PNG'),
    (lambda d: d['evidence'][0].update(file_base64='@@@'), 'bozuk'),
    (lambda d: d['sessions'][0]['notes'][0].update(images=json.dumps([{'name': 'x', 'data': 'data:image/png;base64,PHN2Zz4="'}])), 'images'),
    (lambda d: d['sessions'][0]['notes'][0].update(cvss_vector='CVSS:3.1/AV:X'), 'cvss'),
    (lambda d: d.update(authz_matrix={'roles': 'x'}), 'authz_matrix'),
    (lambda d: d.update(findings={'a': 1}), 'liste'),
])
def test_tampered_backups_rejected_without_side_effects(client, full_project, mutate, needle):
    pid, _, _ = full_project
    data = _export(client, pid)
    before = _count_projects()
    mutate(data)
    r = client.post('/api/projects/import', json=data)
    assert r.status_code == 400, r.get_json()
    assert needle in r.get_json()['error']
    assert _count_projects() == before


def test_ids_from_file_are_ignored(client, full_project):
    pid, _, _ = full_project
    data = _export(client, pid)
    data['project']['id'] = pid
    data['findings'][0]['id'] = 1
    data['findings'][0]['project_id'] = pid
    data['evidence'][0]['stored_filename'] = '../../app.py'
    new = client.post('/api/projects/import', json=data).get_json()
    assert new['id'] != pid
    assert len(client.get(f'/api/projects/{pid}/findings').get_json()) == 1      # kaynağa bulgu eklenmedi
    ev = client.get(f'/api/projects/{new["id"]}/evidence').get_json()[0]
    assert ev['stored_filename'] != '../../app.py' and ev['stored_filename'].endswith('.png')


def test_import_rejects_non_json(client):
    assert client.post('/api/projects/import', data='nope', content_type='text/plain').status_code == 400
    assert client.get('/api/projects/yok/export').status_code == 404
