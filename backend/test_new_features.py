"""
Duplicate Detection + AI Report Assistant + HTML Report + Kanban icin
uctan uca testler. Mevcut test_ai_analyze_route.py'deki FakeProvider /
Flask test_client desenini izler.
"""

import sys, os
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

from unittest.mock import patch
import app as app_module
from ai.base import BaseAIProvider, AIResult
from models import db, Evidence
import duplicate_detector


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


def _make_project(client, name="Test Project"):
    resp = client.post('/api/projects', json={'name': name})
    assert resp.status_code in (200, 201), resp.get_data(as_text=True)
    return resp.get_json()['id']


def _make_finding(client, project_id, **overrides):
    payload = {'title': 'IDOR - Unauthorized Object Access', 'endpoint': '/api/users/5', 'cwe': 'CWE-639'}
    payload.update(overrides)
    resp = client.post(f'/api/projects/{project_id}/findings', json=payload)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()


# ---------------------------------------------------------------------------
# Duplicate detection (pure function)
# ---------------------------------------------------------------------------

def test_duplicate_detector_scores_similar_titles_high():
    candidates = [{'id': 1, 'title': 'IDOR on /api/users', 'description': '', 'endpoint': '/api/users/9', 'cwe': 'CWE-639', 'test_id': None}]
    draft = {'title': 'IDOR - Unauthorized Object Access', 'description': '', 'endpoint': '/api/users/5', 'cwe': 'CWE-639', 'test_id': None}
    matches = duplicate_detector.find_similar_findings(candidates, draft)
    assert len(matches) == 1
    assert matches[0]['score'] > 55
    assert 'same_endpoint' in matches[0]['reasons']
    assert 'same_cwe' in matches[0]['reasons']
    print("OK: benzer baslik + ayni normalize endpoint + ayni CWE yuksek skor uretiyor")


def test_duplicate_detector_excludes_self_and_filters_low_scores():
    candidates = [
        {'id': 1, 'title': 'IDOR - Unauthorized Object Access', 'description': '', 'endpoint': '/api/users/5', 'cwe': 'CWE-639'},
        {'id': 2, 'title': 'Completely unrelated SQL injection in login', 'description': '', 'endpoint': '/login', 'cwe': 'CWE-89'},
    ]
    draft = {'title': 'IDOR - Unauthorized Object Access', 'description': '', 'endpoint': '/api/users/5', 'cwe': 'CWE-639'}
    matches = duplicate_detector.find_similar_findings(candidates, draft, exclude_id=1)
    assert all(m['finding']['id'] != 1 for m in matches)
    assert len(matches) == 0  # id=2 alakasiz, esik altinda kalmali
    print("OK: exclude_id kendisini eler, alakasiz bulgu esigin altinda kalir")


# ---------------------------------------------------------------------------
# check-duplicates / merge routes
# ---------------------------------------------------------------------------

def test_check_duplicates_route_finds_similar_finding():
    client = _client()
    project_id = _make_project(client)
    _make_finding(client, project_id)

    resp = client.post(f'/api/projects/{project_id}/findings/check-duplicates', json={
        'title': 'IDOR - Unauthorized Object Access', 'endpoint': '/api/users/9', 'cwe': 'CWE-639'
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    matches = resp.get_json()['matches']
    assert len(matches) == 1
    print("OK: /findings/check-duplicates rotasi mevcut bulguyu yakaliyor")


def test_merge_findings_route_unions_evidence_and_deletes_secondary():
    client = _client()
    project_id = _make_project(client)
    primary = _make_finding(client, project_id, title='IDOR primary', description='short desc')
    secondary = _make_finding(client, project_id, title='IDOR secondary', description='a much longer and more complete description of the bug')

    resp = client.post(f'/api/projects/{project_id}/findings/merge', json={
        'primary_id': primary['id'], 'merge_ids': [secondary['id']]
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)
    merged = resp.get_json()
    assert merged['description'] == 'a much longer and more complete description of the bug'
    assert secondary['id'] in merged['merged_finding_ids']

    # secondary artik silinmis olmali
    get_resp = client.get(f'/api/projects/{project_id}/findings/{secondary["id"]}')
    assert get_resp.status_code == 404
    print("OK: /findings/merge en uzun aciklamayi koruyor ve ikincil bulguyu siliyor")


def test_merge_findings_relinks_evidence_to_primary():
    client = _client()
    project_id = _make_project(client)
    primary = _make_finding(client, project_id, title='XSS primary')
    secondary = _make_finding(client, project_id, title='XSS secondary')

    with app_module.app.app_context():
        ev = Evidence(project_id=project_id, evidence_type='image', linked_finding_id=secondary['id'])
        db.session.add(ev)
        db.session.commit()
        evidence_id = ev.id

    resp = client.post(f'/api/projects/{project_id}/findings/merge', json={
        'primary_id': primary['id'], 'merge_ids': [secondary['id']]
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)

    with app_module.app.app_context():
        ev = db.session.get(Evidence, evidence_id)
        assert ev.linked_finding_id == primary['id']
    print("OK: merge sonrasi ikincil bulguya bagli Evidence, primary'ye yeniden baglaniyor")


# ---------------------------------------------------------------------------
# AI assistant routes
# ---------------------------------------------------------------------------

def test_ai_description_route_happy_path():
    client = _client()
    project_id = _make_project(client)
    finding = _make_finding(client, project_id)

    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider("The application fails to validate object ownership.")):
        resp = client.post(f'/api/projects/{project_id}/findings/{finding["id"]}/ai/description', json={'lang': 'tr'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert 'object ownership' in body['description']
    assert body['provider'] == 'fake'
    print("OK: AI description rotasi calisiyor ve loglaniyor")


def test_ai_route_returns_503_when_not_configured():
    client = _client()
    project_id = _make_project(client)
    finding = _make_finding(client, project_id)

    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider("", configured=False)):
        resp = client.post(f'/api/projects/{project_id}/findings/{finding["id"]}/ai/description', json={})
    assert resp.status_code == 503
    assert resp.get_json()['ai_configured'] is False
    print("OK: yapilandirilmamis saglayici 503 + net hata donuyor (sessiz basarisizlik yok)")


def test_ai_executive_summary_route():
    client = _client()
    project_id = _make_project(client)
    _make_finding(client, project_id)

    with patch.object(app_module, 'get_ai_provider', return_value=FakeProvider("Overall the assessment found moderate risk.")):
        resp = client.post(f'/api/projects/{project_id}/ai/executive-summary', json={'lang': 'en'})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'moderate risk' in resp.get_json()['summary']
    print("OK: proje bazli executive summary rotasi calisiyor")


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def test_html_report_route_renders_findings():
    client = _client()
    project_id = _make_project(client)
    _make_finding(client, project_id, title='Critical Auth Bypass', severity='critical')

    resp = client.get(f'/api/projects/{project_id}/reports/html?lang=en')
    assert resp.status_code == 200
    assert resp.content_type.startswith('text/html')
    html = resp.get_data(as_text=True)
    assert 'Critical Auth Bypass' in html
    assert 'window.print()' in html
    print("OK: HTML rapor bulguyu iceriyor ve print-to-pdf butonu var")


# ---------------------------------------------------------------------------
# Kanban
# ---------------------------------------------------------------------------

def test_kanban_board_and_move():
    client = _client()
    project_id = _make_project(client)
    sess_resp = client.post('/api/sessions', json={'name': 'Kanban Session', 'project_id': project_id})
    session_id = sess_resp.get_json()['id']
    tr_resp = client.post(f'/api/sessions/{session_id}/results', json={'test_id': 'WSTG-ATHZ-04', 'category_id': 'WSTG-ATHZ'})
    assert tr_resp.status_code in (200, 201), tr_resp.get_data(as_text=True)
    test_result_id = tr_resp.get_json()['id']

    board_resp = client.get(f'/api/projects/{project_id}/kanban/board')
    assert board_resp.status_code == 200, board_resp.get_data(as_text=True)
    columns = board_resp.get_json()['columns']
    assert any(c['id'] == test_result_id for c in columns['todo'])

    move_resp = client.put(f'/api/kanban/card/{test_result_id}/move', json={'kanban_status': 'testing'})
    assert move_resp.status_code == 200, move_resp.get_data(as_text=True)
    assert move_resp.get_json()['kanban_status'] == 'testing'

    board_resp2 = client.get(f'/api/projects/{project_id}/kanban/board')
    columns2 = board_resp2.get_json()['columns']
    assert any(c['id'] == test_result_id for c in columns2['testing'])
    assert not any(c['id'] == test_result_id for c in columns2['todo'])
    print("OK: kanban board test sonucunu 'todo'da gosteriyor, move ile 'testing'e tasiniyor")


def test_kanban_move_rejects_invalid_status():
    client = _client()
    project_id = _make_project(client)
    sess_resp = client.post('/api/sessions', json={'name': 'Kanban Session 2', 'project_id': project_id})
    session_id = sess_resp.get_json()['id']
    tr_resp = client.post(f'/api/sessions/{session_id}/results', json={'test_id': 'WSTG-ATHZ-05'})
    test_result_id = tr_resp.get_json()['id']

    resp = client.put(f'/api/kanban/card/{test_result_id}/move', json={'kanban_status': 'not_a_real_status'})
    assert resp.status_code == 400
    print("OK: gecersiz kanban_status 400 donuyor")
