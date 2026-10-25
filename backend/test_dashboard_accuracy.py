"""Proje özeti doğruluğu ve test sonucu durumları."""
import io
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import docx
import pytest

import app as app_module


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def project(client):
    pid = client.post('/api/projects', json={'name': 'Doğruluk'}).get_json()['id']
    sid = client.post('/api/sessions', json={'name': 'S', 'project_id': pid}).get_json()['id']
    return pid, sid


def test_severity_distribution_counts_real_findings(client, project):
    pid, sid = project
    # Checklist notu (rapora girmez) gerçek bulgu dağılımını etkilememeli
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-INFO-01', 'status': 'passed', 'finding': 'not', 'severity': 'critical'})
    for sev, tid, cat in (('high', 'WSTG-ATHZ-04', ''), ('high', 'WSTG-ATHZ-02', ''), ('low', 'WSTG-SESS-02', ''),
                          ('medium', '', 'A01:2025 Broken Access Control'), ('info', '', '')):
        assert client.post(f'/api/projects/{pid}/findings', json={'title': 'B', 'severity': sev, 'test_id': tid, 'owasp_category': cat}).status_code == 201
    d = client.get(f'/api/projects/{pid}/dashboard').get_json()
    assert d['pro_severity_counts'] == {'critical': 0, 'high': 2, 'medium': 1, 'low': 1, 'info': 1}
    assert d['severity_counts']['critical'] == 1          # eski alan geriye uyumlu kalır
    groups = d['findings_by_wstg_category']
    assert groups[0] == {'code': 'WSTG-ATHZ', 'label': None, 'count': 2}
    assert {'code': 'WSTG-SESS', 'label': None, 'count': 1} in groups
    assert {'code': None, 'label': 'A01:2025 Broken Access Control', 'count': 1} in groups
    assert {'code': None, 'label': None, 'count': 1} in groups


@pytest.mark.parametrize('status', ['done', 'PASSED', '', None, 'completed'])
def test_invalid_result_status_rejected(client, project, status):
    _, sid = project
    assert client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-INFO-02', 'status': status}).status_code == 400
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-INFO-03'})
    assert client.put(f'/api/sessions/{sid}/results/WSTG-INFO-03', json={'status': status}).status_code == 400


def test_failed_and_skipped_count_as_covered_and_show_in_report(client, project):
    pid, sid = project
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-INFO-01', 'status': 'passed'})
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-ATHN-01', 'status': 'failed'})
    client.post(f'/api/sessions/{sid}/results', json={'test_id': 'WSTG-CRYP-01'})
    assert client.put(f'/api/sessions/{sid}/results/WSTG-CRYP-01', json={'status': 'skipped'}).status_code == 200
    d = client.get(f'/api/projects/{pid}/dashboard').get_json()
    assert d['coverage']['wstg']['completed'] == 3
    r = client.get(f'/api/projects/{pid}/reports/technical')
    assert r.status_code == 200
    cells = [c.text for t in docx.Document(io.BytesIO(r.data)).tables for row in t.rows for c in row.cells]
    assert 'Acik yok' in cells and 'Acik bulundu' in cells and 'Uygulanamaz' in cells
    assert 'passed' not in cells and 'failed' not in cells
