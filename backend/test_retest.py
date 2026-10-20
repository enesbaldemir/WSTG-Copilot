"""Yeniden test akışı (retest.py), rotalar ve Yeniden Test Raporu."""
import io
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pypdf
import pytest

import app as app_module
import report_retest
import retest

PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
    '0000000d4944415478da63f8cfc0f01f0005000201a8e3a0860000000049454e44ae426082')


@pytest.mark.parametrize('status,result,state', [
    ('fixed', None, 'pending'),
    ('retest_pending', 'not_fixed', 'pending'),     # yeni tur başladı
    ('resolved', 'fixed', 'verified'),
    ('open', 'not_fixed', 'still_open'),
    ('confirmed', 'not_fixed', 'still_open'),
    ('open', None, None),                           # hiç düzeltilmemiş
    ('open', 'not_tested', None),
    ('resolved', None, None),                       # yeniden test edilmeden kapatılmış
    ('accepted_risk', 'not_fixed', None),
    ('wont_fix', None, None),
])
def test_classify(status, result, state):
    assert retest.classify({'status': status, 'retest_result': result}) == state


def test_transition_and_validation():
    assert retest.transition('fixed', '  Yama doğrulandı ') == {'retest_result': 'fixed', 'retest_notes': 'Yama doğrulandı', 'status': 'resolved'}
    assert retest.transition('not_fixed', None)['status'] == 'open'
    for bad in ('maybe', None, 'not_tested'):
        with pytest.raises(retest.RetestError):
            retest.transition(bad, '')
    with pytest.raises(retest.RetestError):
        retest.transition('fixed', 'x' * (retest.MAX_NOTES + 1))
    with pytest.raises(retest.RetestError):
        retest.transition('fixed', 42)


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def project(client):
    pid = client.post('/api/projects', json={'name': 'ACME Portal', 'client': 'ACME A.Ş.'}).get_json()['id']
    ids = {}
    for title, sev, status in (('SQL enjeksiyonu', 'critical', 'fixed'), ('Kalıcı XSS', 'high', 'retest_pending'),
                               ('Çerez bayrakları', 'low', 'fixed'), ('Açık bulgu', 'medium', 'open')):
        f = client.post(f'/api/projects/{pid}/findings', json={'title': title, 'severity': sev, 'status': status,
                                                               'endpoint': '/api/v1/very/long/path/' + 'x' * 40,
                                                               'remediation': 'Parametreli sorgu kullanın.'}).get_json()
        ids[title] = f['id']
    return pid, ids


def test_retest_route_transitions_and_logs(client, project):
    pid, ids = project
    r = client.post(f'/api/projects/{pid}/findings/{ids["SQL enjeksiyonu"]}/retest', json={'result': 'fixed', 'notes': 'Payload artık 400 dönüyor.'})
    assert r.status_code == 200
    f = r.get_json()
    assert (f['status'], f['retest_result'], f['retest_notes']) == ('resolved', 'fixed', 'Payload artık 400 dönüyor.')
    assert f['retested_at']
    r2 = client.post(f'/api/projects/{pid}/findings/{ids["Kalıcı XSS"]}/retest', json={'result': 'not_fixed', 'notes': 'Hâlâ çalışıyor.'})
    assert r2.get_json()['status'] == 'open'
    events = client.get(f'/api/projects/{pid}/timeline').get_json()
    msgs = [e.get('message') or e.get('description') or '' for e in (events if isinstance(events, list) else events.get('events', []))]
    assert any('yeniden test: düzeldi' in m for m in msgs) and any('yeniden test: hâlâ açık' in m for m in msgs)

    assert client.post(f'/api/projects/{pid}/findings/{ids["Açık bulgu"]}/retest', json={'result': 'maybe'}).status_code == 400
    assert client.post(f'/api/projects/{pid}/findings/999999/retest', json={'result': 'fixed'}).status_code == 404
    other = client.post('/api/projects', json={'name': 'Başka'}).get_json()['id']
    assert client.post(f'/api/projects/{other}/findings/{ids["Açık bulgu"]}/retest', json={'result': 'fixed'}).status_code == 404


def test_overview_states_summary_and_evidence(client, project):
    pid, ids = project
    client.post(f'/api/projects/{pid}/findings/{ids["SQL enjeksiyonu"]}/retest', json={'result': 'fixed'})
    client.post(f'/api/projects/{pid}/findings/{ids["Kalıcı XSS"]}/retest', json={'result': 'not_fixed'})
    up = client.post(f'/api/projects/{pid}/evidence', content_type='multipart/form-data',
                     data={'file': (io.BytesIO(PNG), 'yeniden-test.png', 'image/png'), 'linked_finding_id': str(ids['Kalıcı XSS'])})
    assert up.status_code == 201 and up.get_json()['linked_finding_id'] == ids['Kalıcı XSS']
    body = client.get(f'/api/projects/{pid}/retest').get_json()
    assert body['summary'] == {'pending': 1, 'still_open': 1, 'verified': 1, 'total': 3}
    by_title = {f['title']: f for f in body['findings']}
    assert by_title['Çerez bayrakları']['retest_state'] == 'pending'
    assert by_title['Açık bulgu']['retest_state'] is None
    assert [e['filename'] for e in by_title['Kalıcı XSS']['evidence']] == ['yeniden-test.png']


def test_evidence_link_must_belong_to_project(client, project):
    pid, ids = project
    other = client.post('/api/projects', json={'name': 'Başka'}).get_json()['id']
    r = client.post(f'/api/projects/{other}/evidence', content_type='multipart/form-data',
                    data={'file': (io.BytesIO(PNG), 'a.png', 'image/png'), 'linked_finding_id': str(ids['Açık bulgu'])})
    assert r.status_code == 400
    r = client.post(f'/api/projects/{pid}/evidence', content_type='multipart/form-data',
                    data={'file': (io.BytesIO(PNG), 'a.png', 'image/png'), 'linked_finding_id': 'x'})
    assert r.status_code == 400


def test_retest_report_html_and_pdf(client, project):
    pid, ids = project
    client.post(f'/api/projects/{pid}/findings/{ids["SQL enjeksiyonu"]}/retest', json={'result': 'fixed', 'notes': 'Doğrulandı <b>ok</b>'})
    client.post(f'/api/projects/{pid}/findings/{ids["Kalıcı XSS"]}/retest', json={'result': 'not_fixed', 'notes': 'Hâlâ çalışıyor.'})
    html = client.post(f'/api/projects/{pid}/reports/retest/html', json={'pentester_name': 'Enes'}).get_data(as_text=True)
    assert 'Yeniden Test Raporu' in html and 'Düzeldi (doğrulandı)' in html and 'Hâlâ açık' in html
    assert 'Doğrulandı &lt;b&gt;ok&lt;/b&gt;' in html and '<b>ok</b>' not in html
    assert 'Açık bulgu' not in html                     # kapsam dışı
    assert html.index('SQL enjeksiyonu') < html.index('Kalıcı XSS') < html.index('Çerez bayrakları')
    no_pending = client.get(f'/api/projects/{pid}/reports/retest/html?include_pending=false').get_data(as_text=True)
    assert 'Çerez bayrakları' not in no_pending

    r = client.post(f'/api/projects/{pid}/reports/retest/pdf', json={'lang': 'tr'})
    assert r.status_code == 200 and r.mimetype == 'application/pdf' and r.data.startswith(b'%PDF-')
    text = ''.join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r.data)).pages)
    for needle in ('Yeniden Test Raporu', 'ACME A.Ş.', 'SQL enjeksiyonu', 'Hâlâ çalışıyor.', 'Yeniden test edilmedi'):
        assert needle in text, needle
    en = client.get(f'/api/projects/{pid}/reports/retest/html?lang=en').get_data(as_text=True)
    assert 'Retest Report' in en and 'Still open' in en
    assert client.get(f'/api/projects/{pid}/reports/retest/docx').status_code == 404
    assert client.get('/api/projects/yok/reports/retest/html').status_code == 404


def test_report_prepare_empty():
    items, counts = report_retest.prepare([{'status': 'open'}])
    assert items == [] and counts['total'] == 0
    assert 'Yeniden test kapsamında bulgu yok.' in report_retest.build_html({'name': 'X'}, [])
