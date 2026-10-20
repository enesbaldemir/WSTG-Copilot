"""
Bulgular sekmesindeki durum sayaçları (/api/projects/<id>/lifecycle).

Eskiden yalnızca checklist notları sayılıyordu; profesyonel bulgular
(Finding) listede görünürken sayaçlar 0 kalıyordu.
"""
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest

import app as app_module
import finding_lifecycle as fl


def test_pro_statuses_map_to_lifecycle_groups():
    pro = [{'status': s, 'severity': 'high'} for s in
           ('open', 'confirmed', 'retest_pending', 'fixed', 'resolved', 'wont_fix', 'accepted_risk', 'bilinmeyen')]
    out = fl.summarize([], pro)
    assert out['status_counts'] == {'open': 3, 'retesting': 1, 'fixed': 1, 'resolved': 1, 'wont_fix': 1, 'accepted_risk': 1}
    assert out['active_severity_counts']['high'] == 4          # open(3) + retesting(1)
    assert out['total_findings'] == 8 and out['remediation_rate'] == 12.5


def test_quick_note_superseded_by_finding_for_same_session_and_test():
    quick = [
        {'session_id': 's1', 'test_id': 'WSTG-INPV-05', 'finding': 'not', 'finding_status': 'open', 'severity': 'high'},
        {'session_id': 's1', 'test_id': 'WSTG-SESS-02', 'finding': 'cookie', 'finding_status': 'fixed', 'severity': 'low'},
        {'session_id': 's1', 'test_id': 'WSTG-INFO-02', 'finding': '   ', 'finding_status': 'open', 'severity': 'info'},
    ]
    pro = [{'session_id': 's1', 'test_id': 'WSTG-INPV-05', 'status': 'resolved', 'severity': 'high'}]
    out = fl.summarize(quick, pro)
    assert (out['total_findings'], out['professional_findings'], out['quick_findings']) == (2, 1, 1)
    assert out['status_counts']['resolved'] == 1 and out['status_counts']['fixed'] == 1
    assert out['status_counts']['open'] == 0       # INPV-05 notu bulguyla değiştirildi
    assert out['remediation_rate'] == 50.0


def test_finding_without_session_does_not_hide_notes():
    quick = [{'session_id': 's1', 'test_id': 'WSTG-INPV-05', 'finding': 'not', 'finding_status': 'open', 'severity': 'high'}]
    pro = [{'session_id': None, 'test_id': 'WSTG-INPV-05', 'status': 'open', 'severity': 'high'}]
    assert fl.summarize(quick, pro)['total_findings'] == 2


def test_empty():
    out = fl.summarize([], [])
    assert out['total_findings'] == 0 and out['remediation_rate'] == 0


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_lifecycle_route_counts_professional_findings(client):
    pid = client.post('/api/projects', json={'name': 'Sayaç'}).get_json()['id']
    sid = client.post('/api/sessions', json={'name': 'S', 'project_id': pid}).get_json()['id']
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-SESS-02', 'status': 'passed',
                                                      'finding': 'HttpOnly yok', 'severity': 'low'})
    for title, status in (('SQLi', 'open'), ('XSS', 'confirmed'), ('CSRF', 'resolved')):
        r = client.post(f'/api/projects/{pid}/findings', json={'title': title, 'severity': 'high', 'status': status})
        assert r.status_code == 201
    body = client.get(f'/api/projects/{pid}/lifecycle').get_json()
    assert body['total_findings'] == 4
    assert body['professional_findings'] == 3 and body['quick_findings'] == 1
    assert body['status_counts']['open'] == 3     # SQLi + XSS(confirmed) + not
    assert body['status_counts']['resolved'] == 1
    assert body['remediation_rate'] == 25.0
    assert 'recent_transitions' in body
    assert client.get('/api/projects/yok/lifecycle').status_code == 404
