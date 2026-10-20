"""
PDF raporu (report_pdf.build_pdf_report ve /api/projects/<id>/reports/pdf).

Windows hatasi: xhtml2pdf, CSS @font-face ile verilen fontu acik tuttugu bir
NamedTemporaryFile'a kopyalayip reportlab'e ADIYLA actirir. Windows acik
dosyanin ikinci kez acilmasina izin vermedigi icin rapor PermissionError ile
500 donuyordu. test_no_temp_font_files bu Windows davranisini Linux'ta taklit
eder: gecici bir .ttf olusturulmaya calisilirsa test basarisiz olur.
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pypdf
import pytest

import report_pdf

PROJECT = {'id': 'p1', 'name': 'Örnek Proje', 'client': 'Müşteri A.Ş.'}
FINDINGS = [{
    'id': 1, 'finding_code': 'FND-0001', 'title': 'Giriş formunda SQL enjeksiyonu (ğüşıöçİ)',
    'description': "Parola alanı ' OR 1=1-- ile atlatılabiliyor.",
    'severity': 'critical', 'cvss_score': 9.8, 'status': 'open',
}]
RESULTS = [{'test_id': 'WSTG-INPV-05', 'status': 'done'}, {'test_id': 'WSTG-ATHN-01', 'status': 'pending'}]


def _build(**kw):
    buf = report_pdf.build_pdf_report(PROJECT, FINDINGS, RESULTS, options=kw.pop('options', {}), lang=kw.pop('lang', 'tr'))
    data = buf.getvalue()
    assert data.startswith(b'%PDF-')
    return data


def _fonts(data):
    """Görünen metni basan fontların adları (boş metin bloklarındaki
    reportlab varsayılanı Helvetica sayılmaz)."""
    reader = pypdf.PdfReader(io.BytesIO(data))
    names = set()

    def visitor(text, cm, tm, font_dict, font_size):
        if text.strip() and font_dict:
            names.add(str(font_dict.get('/BaseFont', '')))

    for page in reader.pages:
        page.extract_text(visitor_text=visitor)
    return reader, names


def test_no_temp_font_files(monkeypatch):
    import xhtml2pdf.files as xfiles
    real = tempfile.NamedTemporaryFile

    def windows_like(*args, **kwargs):
        suffix = str(kwargs.get('suffix') or '').lower()
        if suffix.endswith(('.ttf', '.ttc', '.afm', '.pfb')):
            raise PermissionError(13, 'Windows: açık geçici dosya adıyla tekrar açılamaz', 'tmp' + suffix)
        return real(*args, **kwargs)

    monkeypatch.setattr(xfiles.tempfile, 'NamedTemporaryFile', windows_like)
    _build()


def test_turkish_text_and_embedded_vera_fonts():
    data = _build()
    reader, fonts = _fonts(data)
    text = ''.join(p.extract_text() for p in reader.pages)
    for word in ('Örnek Proje', 'Sızma Testi', 'Yönetici Özeti', 'ğüşıöçİ'):
        assert word in text, word
    # Düz ve kalın metin gömülü Vera TTF ile basılır; standart 14 fonta
    # (Helvetica, Türkçe ğ/ş/ı/İ içermez) hiç düşülmez.
    assert any(n.endswith('BitstreamVeraSans-Roman') for n in fonts), fonts
    assert any(n.endswith('BitstreamVeraSans-Bold') for n in fonts), fonts
    assert not any('Helvetica' in n or 'Times' in n for n in fonts), fonts


def test_repeated_builds_and_english():
    _build()
    data = _build(lang='en', options={'confidential': True})
    text = ''.join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(data)).pages)
    assert 'CONFIDENTIAL' in text and 'Executive Summary' in text


def test_pdf_route_returns_attachment():
    import app as app_module
    app_module.app.config['TESTING'] = True
    c = app_module.app.test_client()
    project = c.post('/api/projects', json={'name': 'PDF Rota Testi'}).get_json()
    c.post(f'/api/projects/{project["id"]}/findings', json={
        'title': 'Şifre sıfırlamada IDOR', 'description': 'Başka kullanıcının bağlantısı üretilebiliyor.',
        'severity': 'high',
    })
    r = c.post(f'/api/projects/{project["id"]}/reports/pdf', json={'lang': 'tr'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.mimetype == 'application/pdf'
    assert 'attachment' in r.headers.get('Content-Disposition', '')
    assert r.data.startswith(b'%PDF-')
    assert c.get('/api/projects/yok/reports/pdf').status_code == 404
