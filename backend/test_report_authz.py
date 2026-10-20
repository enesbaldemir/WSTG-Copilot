"""Raporlarda "Yetkilendirme Testleri" bölümü (report_authz.py + rotalar)."""
import io
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pypdf
import pytest

import app as app_module
import authz_matrix
import report_authz

DOC = authz_matrix.validate({
    'roles': [{'id': 'anon', 'name': 'Anonim'}, {'id': 'user', 'name': 'Kullanıcı'}, {'id': 'admin', 'name': 'Yönetici'}],
    'endpoints': [
        {'id': 'e1', 'method': 'GET', 'path': '/api/admin/users'},
        {'id': 'e2', 'method': 'GET', 'path': '/api/orders/{id}'},
        {'id': 'e3', 'method': 'GET', 'path': '/hiç-denenmedi'},
    ],
    'cells': {
        'e1:anon': {'expected': 'deny', 'observed': 'denied'},
        'e1:user': {'expected': 'deny', 'observed': 'allowed', 'note': '200 OK, tüm liste', 'finding_id': 7},
        'e1:admin': {'expected': 'allow', 'observed': 'allowed'},
        'e2:user': {'expected': 'allow', 'observed': 'denied'},
        'e2:admin': {'expected': 'allow'},
    },
})


def test_prepare_summary_violations_and_rows():
    vm = report_authz.prepare(DOC)
    assert vm['summary'] == {'cells': 9, 'tested': 4, 'violations': 1, 'over': 1, 'untested': 5}
    assert vm['violations'] == [{'role': 'Kullanıcı', 'method': 'GET', 'path': '/api/admin/users',
                                 'note': '200 OK, tüm liste', 'finding_id': 7}]
    assert [r['path'] for r in vm['rows']] == ['/api/admin/users', '/api/orders/{id}']
    assert vm['empty_rows'] == 1
    assert [c['status'] for c in vm['rows'][1]['cells']] == ['unset', 'over', 'untested']


@pytest.mark.parametrize('doc', [
    None, authz_matrix.empty(),
    {'roles': [{'id': 'r', 'name': 'R'}], 'endpoints': [], 'cells': {}},
    {'roles': [{'id': 'r', 'name': 'R'}], 'endpoints': [{'id': 'e', 'method': 'GET', 'path': '/'}], 'cells': {}},
])
def test_prepare_returns_none_without_results(doc):
    assert report_authz.prepare(doc) is None
    assert report_authz.render_html(report_authz.prepare(doc)) == ''


def test_render_html_escapes_and_shows_matrix():
    doc = authz_matrix.validate({
        'roles': [{'id': 'r', 'name': '<img src=x onerror=alert(1)>'}],
        'endpoints': [{'id': 'e', 'method': 'GET', 'path': '/a"><script>alert(2)</script>'}],
        'cells': {'e:r': {'expected': 'deny', 'observed': 'allowed', 'note': '<b>not</b>'}},
    })
    out = report_authz.render_html(report_authz.prepare(doc), 'tr')
    assert '<script>' not in out and '<img' not in out and '<b>not' not in out
    assert '&lt;script&gt;' in out and 'Yasak → Erişti' in out and 'authz-violation' in out


def test_executive_template_omits_full_matrix():
    vm = report_authz.prepare(DOC)
    assert 'Matris' in report_authz.render_html(vm, 'tr', 'standard')
    exec_html = report_authz.render_html(vm, 'tr', 'executive')
    assert 'Matris' not in exec_html and 'İzinsiz erişimler' in exec_html and 'FND-0007' in exec_html
    assert 'Authorization Testing' in report_authz.render_html(vm, 'en')


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def project_with_matrix(client):
    pid = client.post('/api/projects', json={'name': 'Rapor Matris'}).get_json()['id']
    assert client.put(f'/api/projects/{pid}/authz-matrix', json=DOC).status_code == 200
    return pid


def test_html_report_includes_section_by_default(client, project_with_matrix):
    html = client.post(f'/api/projects/{project_with_matrix}/reports/html', json={'lang': 'tr'}).get_data(as_text=True)
    assert 'Yetkilendirme Testleri' in html and '/api/admin/users' in html and 'FND-0007' in html
    off = client.post(f'/api/projects/{project_with_matrix}/reports/html', json={'lang': 'tr', 'include_authz': False}).get_data(as_text=True)
    assert 'Yetkilendirme Testleri' not in off
    get_off = client.get(f'/api/projects/{project_with_matrix}/reports/html?include_authz=false').get_data(as_text=True)
    assert 'Yetkilendirme Testleri' not in get_off


def test_html_report_without_matrix_has_no_section(client):
    pid = client.post('/api/projects', json={'name': 'Matrissiz'}).get_json()['id']
    html = client.post(f'/api/projects/{pid}/reports/html', json={}).get_data(as_text=True)
    assert 'Yetkilendirme Testleri' not in html


def test_pdf_report_includes_section(client, project_with_matrix):
    r = client.post(f'/api/projects/{project_with_matrix}/reports/pdf', json={'lang': 'tr'})
    assert r.status_code == 200 and r.data.startswith(b'%PDF-')
    text = ''.join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r.data)).pages)
    for needle in ('Yetkilendirme Testleri', 'İzinsiz erişimler', 'Kullanıcı', '/api/admin/users', 'FND-0007'):
        assert needle in text, needle
    r_en = client.post(f'/api/projects/{project_with_matrix}/reports/pdf', json={'lang': 'en', 'template': 'executive'})
    text_en = ''.join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r_en.data)).pages)
    assert 'Authorization Testing' in text_en and 'Matrix (expected' not in text_en
