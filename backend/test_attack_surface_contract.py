"""
Saldırı Yüzeyi ekranının dayandığı salt-okunur rotaların sözleşme testi.

Ekran (js/attack-surface.js) yalnızca şu yanıtları okur; buradaki alanlar
değişirse ekran bozulur:
  GET /api/projects/<id>/assets  -> subdomains/technologies/endpoints + runs[ReconRun.to_dict()]
  GET /api/projects/<id>/scope
Ayrıca bu rotaların hiçbir ağ isteği / tarama başlatmadığını doğrular.
"""
import sys, os, json
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

from unittest.mock import patch
import app as app_module
from models import db, ReconRun

RUN_FIELDS = {'id', 'project_id', 'target', 'baseUrl', 'subdomains', 'technologies', 'endpoints', 'apis',
              'interestingPaths', 'forms', 'cookiesPresent', 'suggestions', 'created_at'}


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def _project_with_run(client):
    pid = client.post('/api/projects', json={'name': 'AS contract'}).get_json()['id']
    with app_module.app.app_context():
        db.session.add(ReconRun(
            project_id=pid, target='portal.acme.test', base_url='https://portal.acme.test',
            subdomains=json.dumps(['portal.acme.test', 'api.portal.acme.test']),
            technologies=json.dumps(['nginx']),
            endpoints=json.dumps(['/login', '/robots.txt']),
            apis=json.dumps([]), interesting_paths=json.dumps([{'path': '/robots.txt', 'status': 200}]),
            forms=json.dumps([]), cookies_present=False,
            suggestions=json.dumps({'WSTG-ATHN-02': {'level': 'high', 'reasons': ['Kimlik doğrulama sayfası bulundu: /login']}}),
        ))
        db.session.commit()
    return pid


def test_assets_route_returns_fields_used_by_attack_surface_view():
    c = _client()
    pid = _project_with_run(c)
    with patch('recon.requests.get') as net, patch('recon.run_discovery') as scan:
        r = c.get(f'/api/projects/{pid}/assets')
        assert not net.called and not scan.called, 'assets route must not trigger network/recon'
    assert r.status_code == 200
    d = r.get_json()
    assert d['subdomains'] == ['api.portal.acme.test', 'portal.acme.test']
    assert d['endpoints'] == ['/login', '/robots.txt']
    run = d['runs'][0]
    assert RUN_FIELDS.issubset(run.keys())
    assert run['interestingPaths'] == [{'path': '/robots.txt', 'status': 200}]
    assert run['suggestions']['WSTG-ATHN-02']['level'] == 'high'
    assert run['created_at']


def test_scope_route_shape():
    c = _client()
    pid = _project_with_run(c)
    c.post(f'/api/projects/{pid}/scope', json={'type': 'domain', 'value': '*.acme.test', 'in_scope': True})
    items = c.get(f'/api/projects/{pid}/scope').get_json()
    assert {'type', 'value', 'in_scope'}.issubset(items[0].keys())


def test_empty_project_and_missing_project():
    c = _client()
    pid = c.post('/api/projects', json={'name': 'AS empty'}).get_json()['id']
    d = c.get(f'/api/projects/{pid}/assets').get_json()
    assert d == {'subdomains': [], 'technologies': [], 'endpoints': [], 'runs': []}
    assert c.get('/api/projects/does-not-exist/assets').status_code == 404


def test_recon_still_requires_authorization_confirmation():
    c = _client()
    with patch('recon.run_discovery') as scan:
        r = c.post('/api/recon', json={'target': 'example.com'})
        assert r.status_code == 400 and not scan.called
