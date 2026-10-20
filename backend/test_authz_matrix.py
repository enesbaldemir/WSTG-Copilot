"""Yetkilendirme matrisi: doğrulama (authz_matrix.py) ve rotalar."""
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest

import app as app_module
import authz_matrix as am
from models import db, AuthzMatrix

DOC = {
    'roles': [{'id': 'anon', 'name': 'Anonim'}, {'id': 'user', 'name': 'Kullanıcı'}, {'id': 'admin', 'name': 'Yönetici'}],
    'endpoints': [
        {'id': 'e1', 'method': 'get', 'path': ' /api/admin/users ', 'note': 'kullanıcı listesi'},
        {'id': 'e2', 'method': 'DELETE', 'path': '/api/users/{id}'},
    ],
    'cells': {
        'e1:anon': {'expected': 'deny', 'observed': 'denied'},
        'e1:user': {'expected': 'deny', 'observed': 'allowed', 'note': '200 OK, tüm liste döndü'},
        'e1:admin': {'expected': 'allow', 'observed': 'allowed'},
        'e2:user': {'expected': 'allow', 'observed': 'denied'},
        'e2:admin': {'expected': 'allow', 'observed': None},
        'e2:anon': {'expected': None, 'observed': None, 'note': ''},     # boş -> saklanmaz
        'gone:anon': {'expected': 'deny', 'observed': 'allowed'},        # silinmiş satır -> düşer
    },
}


def test_validate_normalizes_and_drops_orphans():
    doc = am.validate(DOC)
    assert doc['endpoints'][0] == {'id': 'e1', 'method': 'GET', 'path': '/api/admin/users', 'note': 'kullanıcı listesi'}
    assert set(doc['cells']) == {'e1:anon', 'e1:user', 'e1:admin', 'e2:user', 'e2:admin'}
    assert doc['cells']['e1:user']['finding_id'] is None
    assert am.summarize(doc) == {'cells': 6, 'tested': 4, 'violations': 1, 'over_restricted': 1, 'untested': 2}


@pytest.mark.parametrize('mutate,msg', [
    (lambda d: d['roles'].append({'id': 'x', 'name': 'anonim'}), 'iki kez'),
    (lambda d: d['roles'].append({'id': 'anon', 'name': 'Başka'}), 'tekrar'),
    (lambda d: d['roles'].append({'id': 'bad id!', 'name': 'X'}), 'kimliği'),
    (lambda d: d['roles'].append({'id': 'x', 'name': '  '}), 'boş'),
    (lambda d: d['endpoints'].append({'id': 'e3', 'method': 'GET', 'path': '/api/admin/users'}), 'iki kez'),
    (lambda d: d['endpoints'].append({'id': 'e3', 'method': 'BREW', 'path': '/x'}), 'metodu'),
    (lambda d: d['endpoints'].append({'id': 'e3', 'method': 'GET', 'path': 'x' * 501}), 'en fazla'),
    (lambda d: d['cells'].update({'e1:anon': {'expected': 'maybe'}}), 'expected'),
    (lambda d: d['cells'].update({'e1:anon': {'observed': 'yes'}}), 'observed'),
    (lambda d: d['cells'].update({'e1:anon': {'expected': 'deny', 'finding_id': 'x'}}), 'finding_id'),
    (lambda d: d['cells'].update({'e1:anon': {'expected': 'deny', 'finding_id': True}}), 'finding_id'),
    (lambda d: d.update({'roles': [{'id': f'r{i}', 'name': f'R{i}'} for i in range(am.MAX_ROLES + 1)]}), 'En fazla'),
])
def test_validate_rejects(mutate, msg):
    import copy
    d = copy.deepcopy(DOC)
    mutate(d)
    with pytest.raises(am.MatrixValidationError, match=msg):
        am.validate(d)


def test_control_chars_stripped_and_names_single_line():
    d = am.validate({'roles': [{'id': 'r', 'name': 'Ad\x00min\nX'}], 'endpoints': [], 'cells': {}})
    assert d['roles'][0]['name'] == 'Admin X'


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_routes_roundtrip(client):
    pid = client.post('/api/projects', json={'name': 'Matris'}).get_json()['id']
    empty = client.get(f'/api/projects/{pid}/authz-matrix').get_json()
    assert empty['roles'] == [] and empty['summary']['cells'] == 0 and empty['updated_at'] is None

    r = client.put(f'/api/projects/{pid}/authz-matrix', json=DOC)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['summary']['violations'] == 1 and body['updated_at']
    again = client.get(f'/api/projects/{pid}/authz-matrix').get_json()
    assert again['cells'] == body['cells'] and len(again['endpoints']) == 2

    bad = client.put(f'/api/projects/{pid}/authz-matrix', json={'roles': 'x'})
    assert bad.status_code == 400
    assert client.get(f'/api/projects/{pid}/authz-matrix').get_json()['cells'] == body['cells']   # değişmedi

    assert client.get('/api/projects/yok/authz-matrix').status_code == 404
    assert client.put('/api/projects/yok/authz-matrix', json=DOC).status_code == 404


def test_matrix_deleted_with_project(client):
    pid = client.post('/api/projects', json={'name': 'Silinecek'}).get_json()['id']
    client.put(f'/api/projects/{pid}/authz-matrix', json=DOC)
    assert client.delete(f'/api/projects/{pid}').status_code == 200
    with app_module.app.app_context():
        assert AuthzMatrix.query.filter_by(project_id=pid).count() == 0


def test_corrupt_stored_document_reads_as_empty(client):
    pid = client.post('/api/projects', json={'name': 'Bozuk'}).get_json()['id']
    with app_module.app.app_context():
        db.session.add(AuthzMatrix(project_id=pid, data='{bozuk json'))
        db.session.commit()
    assert client.get(f'/api/projects/{pid}/authz-matrix').get_json()['roles'] == []
