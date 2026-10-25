"""Kullanıcı bulgu şablonları API'si."""
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest

import app as app_module


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_create_list_delete(client):
    r = client.post('/api/finding-templates', json={
        'title': '  Bizim IDOR metnimiz ', 'severity': 'high', 'test_id': 'WSTG-ATHZ-04', 'cwe': 'CWE-639',
        'description': 'Açıklama', 'remediation': 'Çözüm', 'endpoint': '/gizli', 'steps_to_reproduce': '1. hedefe özel'})
    assert r.status_code == 201
    t = r.get_json()
    assert t['title'] == 'Bizim IDOR metnimiz' and t['severity'] == 'high'
    assert 'endpoint' not in t and 'steps_to_reproduce' not in t     # hedefe özel alanlar saklanmaz
    assert any(x['id'] == t['id'] for x in client.get('/api/finding-templates').get_json())
    assert client.delete(f'/api/finding-templates/{t["id"]}').status_code == 200
    assert client.delete(f'/api/finding-templates/{t["id"]}').status_code == 404
    assert all(x['id'] != t['id'] for x in client.get('/api/finding-templates').get_json())


@pytest.mark.parametrize('body', [
    {}, {'title': '   '}, {'title': 'A', 'severity': 'High'}, {'title': 'A', 'description': 42},
    {'title': 'x' * 301}, {'title': 'A', 'description': 'y' * 20001},
])
def test_validation(client, body):
    assert client.post('/api/finding-templates', json=body).status_code == 400


def test_default_severity(client):
    t = client.post('/api/finding-templates', json={'title': 'Varsayılan'}).get_json()
    assert t['severity'] == 'medium'
    client.delete(f'/api/finding-templates/{t["id"]}')
