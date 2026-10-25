"""Bulgu: tekrarlama adımları (PoC), önem derecesi doğrulaması ve raporlar."""
import io
import os
import sys

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pypdf
import pytest
from sqlalchemy import text

import app as app_module

STEPS = "1. /login sayfasını aç\n2. Kullanıcı adına <script>alert(1)</script> yaz\n3. Yanıtta betiğin çalıştığını gör"


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


@pytest.fixture
def pid(client):
    return client.post('/api/projects', json={'name': 'PoC'}).get_json()['id']


def test_steps_saved_and_updated(client, pid):
    f = client.post(f'/api/projects/{pid}/findings', json={'title': 'XSS', 'severity': 'high', 'steps_to_reproduce': STEPS}).get_json()
    assert f['steps_to_reproduce'] == STEPS and f['severity'] == 'high'
    r = client.put(f'/api/projects/{pid}/findings/{f["id"]}', json={'steps_to_reproduce': '1. Tek adım'})
    assert r.get_json()['steps_to_reproduce'] == '1. Tek adım'


def test_severity_without_cvss_and_cvss_wins(client, pid):
    f = client.post(f'/api/projects/{pid}/findings', json={'title': 'A', 'severity': 'medium'}).get_json()
    assert f['severity'] == 'medium'
    r = client.put(f'/api/projects/{pid}/findings/{f["id"]}', json={'severity': 'low', 'cvss_score': None})
    assert r.get_json()['severity'] == 'low'
    r = client.put(f'/api/projects/{pid}/findings/{f["id"]}', json={'severity': 'low', 'cvss_score': 9.8,
                                                                 'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'})
    assert r.get_json()['severity'] == 'critical'      # CVSS varsa önem derecesi ondan gelir
    g = client.post(f'/api/projects/{pid}/findings', json={'title': 'B'}).get_json()
    assert g['severity'] == 'info'


@pytest.mark.parametrize('bad', ['High', 'severe', 'kritik', 42])
def test_invalid_severity_rejected(client, pid, bad):
    assert client.post(f'/api/projects/{pid}/findings', json={'title': 'X', 'severity': bad}).status_code == 400
    f = client.post(f'/api/projects/{pid}/findings', json={'title': 'Y', 'severity': 'low'}).get_json()
    assert client.put(f'/api/projects/{pid}/findings/{f["id"]}', json={'severity': bad}).status_code == 400


def test_reports_show_escaped_steps(client, pid):
    client.post(f'/api/projects/{pid}/findings', json={'title': 'XSS', 'severity': 'high', 'description': 'Açıklama', 'steps_to_reproduce': STEPS})
    html = client.post(f'/api/projects/{pid}/reports/html', json={'lang': 'tr'}).get_data(as_text=True)
    assert 'Tekrarlama adımları' in html
    assert '1. /login sayfasını aç<br/>2. Kullanıcı adına &lt;script&gt;alert(1)&lt;/script&gt; yaz' in html
    assert '<script>alert(1)</script>' not in html
    assert 'Steps to reproduce' in client.post(f'/api/projects/{pid}/reports/html', json={'lang': 'en'}).get_data(as_text=True)
    executive = client.post(f'/api/projects/{pid}/reports/html', json={'lang': 'tr', 'template': 'executive'}).get_data(as_text=True)
    assert 'Tekrarlama adımları' not in executive
    pdf = client.post(f'/api/projects/{pid}/reports/pdf', json={'lang': 'tr'})
    assert pdf.status_code == 200
    textout = ''.join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf.data)).pages)
    assert 'Tekrarlama adımları' in textout and '/login sayfasını aç' in textout


def test_merge_keeps_longest_steps(client, pid):
    a = client.post(f'/api/projects/{pid}/findings', json={'title': 'Aynı', 'severity': 'low', 'steps_to_reproduce': '1. kısa'}).get_json()
    b = client.post(f'/api/projects/{pid}/findings', json={'title': 'Aynı', 'severity': 'low', 'steps_to_reproduce': STEPS}).get_json()
    r = client.post(f'/api/projects/{pid}/findings/merge', json={'primary_id': a['id'], 'merge_ids': [b['id']]})
    assert r.status_code == 200
    assert client.get(f'/api/projects/{pid}/findings/{a["id"]}').get_json()['steps_to_reproduce'] == STEPS


def test_schema_adds_column_to_old_database():
    with app_module.app.app_context():
        db = app_module.db
        db.session.execute(text('ALTER TABLE findings DROP COLUMN steps_to_reproduce'))
        db.session.commit()
        app_module.ensure_schema()
        cols = [row[1] for row in db.session.execute(text('PRAGMA table_info(findings)')).fetchall()]
        assert 'steps_to_reproduce' in cols
