"""
PDF Profesyonel Rapor.

report_html.py'nin ayni veri hazirlama mantigini (bulgu filtreleme/siralama,
severity sayimi, genel risk etiketi) yeniden kullanir, ama CIKTI olarak
gercek, indirilebilir bir PDF dosyasi uretir -- tarayicinin "Yazdir / PDF
olarak kaydet" diyaloguna ihtiyac duymadan.

Neden WeasyPrint/pdfkit DEGIL:
  report_html.py'deki ayni gerekce burada da gecerli -- bu araclar sistem
  seviyesinde ek bagimlilik ister (WeasyPrint: GTK/Pango/Cairo runtime,
  pdfkit: wkhtmltopdf binary'si). Bircok pentester Windows'ta calisiyor ve
  bu kurulumlar orada sikca sorun cikariyor.

Neden xhtml2pdf:
  Saf Python -- tek bagimliligi reportlab (zaten pip ile duz kuruluyor,
  hicbir sistem paketi/binary gerektirmiyor). `pip install -r
  requirements.txt` disinda HICBIR EK ADIM gerekmez, Windows dahil her
  platformda calisir.

Turkce karakter notu (onemli):
  xhtml2pdf varsayilan olarak PDF'in standart 14 fontunu (Helvetica vb.)
  kullanir; bu fontlar WinAnsi/Latin-1 kodlamasindadir ve Turkce'ye ozgu
  ğ/Ğ, ş/Ş, ı/İ karakterlerini İCERMEZ (ç/ö/ü Latin-1'de oldugu icin sorun
  cikarmaz, ama ğ/ş/ı/İ bos kare olarak basilir). Bunu cozmek icin
  reportlab'in kendi paketiyle birlikte gelen Bitstream Vera TTF fontlarini
  (Vera.ttf / VeraBd.ttf) @font-face ile gomuyoruz -- bu fontlar WGL4
  kapsamina sahip oldugu icin Turkce alfabenin tamamini dogru basar. Ekstra
  bir font dosyasi indirmeye/pakete eklemeye gerek yok: reportlab zaten
  xhtml2pdf'in bagimliligi oldugu icin bu dosyalar her kurulumda hazir gelir.
"""

import io
import os
from datetime import datetime

import reportlab
from xhtml2pdf import pisa

from report_html import (
    SEVERITY_ORDER, SEVERITY_HEX, _esc, _severity_counts, _sorted_findings,
    _filter_findings, _overall_risk_label, _is_safe_data_uri,
)

_FONT_DIR = os.path.join(os.path.dirname(reportlab.__file__), 'fonts')
_FONT_REGULAR = os.path.join(_FONT_DIR, 'Vera.ttf').replace('\\', '/')
_FONT_BOLD = os.path.join(_FONT_DIR, 'VeraBd.ttf').replace('\\', '/')


class PdfReportError(Exception):
    pass


def _render_findings_pdf(sorted_findings, lang, template):
    if not sorted_findings:
        empty = ('Bu değerlendirmede bulgu tespit edilmemiştir.' if lang == 'tr'
                 else 'No findings were identified in this assessment.')
        return f'<p class="empty-state">{empty}</p>'

    items = []
    for f in sorted_findings:
        sev = (f.get('severity') or 'info').lower()
        color = SEVERITY_HEX.get(sev, SEVERITY_HEX['info'])
        code = f.get('finding_code') or (f"FND-{f['id']:04d}" if f.get('id') else '')
        meta_bits = []
        if f.get('cvss_score') is not None:
            meta_bits.append(f"CVSS {f['cvss_score']}")
        if f.get('cwe'):
            meta_bits.append(_esc(f['cwe']))
        if f.get('test_id'):
            meta_bits.append(_esc(f['test_id']))
        meta_line = ' &middot; '.join(meta_bits)

        body_blocks = [f'<p>{_esc(f.get("description") or "")}</p>']
        if template != 'executive':
            if f.get('endpoint'):
                body_blocks.append(f'<p><b>{"Endpoint" if lang=="tr" else "Endpoint"}:</b> {_esc(f["endpoint"])}</p>')
            if f.get('impact'):
                body_blocks.append(f'<p><b>{"Etki" if lang=="tr" else "Impact"}:</b> {_esc(f["impact"])}</p>')
            if f.get('remediation'):
                body_blocks.append(f'<p><b>{"Giderim" if lang=="tr" else "Remediation"}:</b> {_esc(f["remediation"])}</p>')

        items.append(f'''
        <div class="finding-item" style="border-left-color:{color};">
          <table class="finding-header-table"><tr>
            <td class="finding-code">{_esc(code)}</td>
            <td class="sev-chip-cell"><span class="sev-chip" style="background:{color};">{sev.upper()}</span></td>
            <td class="finding-title">{_esc(f.get('title') or '')}</td>
          </tr></table>
          <div class="finding-meta">{meta_line}</div>
          {''.join(body_blocks)}
        </div>''')
    return ''.join(items)


def build_pdf_report(project, findings, all_results, options=None, executive_summary=None, lang='tr'):
    """report_html.build_html_report ile ayni imza/parametreler; donus
    degeri (bytes) hazir bir PDF dosyasidir. Hata durumunda PdfReportError
    firlatir."""
    options = options or {}
    title = options.get('title') or f"{project.get('name', '')} Security Assessment"
    client_name = options.get('client_name') or project.get('client') or ''
    pentester_name = options.get('pentester_name') or ''
    date_range = options.get('date_range') or ''
    logo_uri = options.get('logo_data_uri')
    template = options.get('template') or 'standard'
    confidential = bool(options.get('confidential'))

    scoped_findings = _filter_findings(findings, options.get('include'))
    sorted_findings = _sorted_findings(scoped_findings)
    sev_counts = _severity_counts(scoped_findings)
    risk_label, risk_color = _overall_risk_label(sev_counts, lang)

    completed = len([r for r in all_results if r.get('status') != 'pending'])
    total_tests = len(all_results)

    if not executive_summary:
        executive_summary = (
            f"Bu değerlendirme kapsamında toplam {total_tests} test çalıştırılmış, "
            f"{len(scoped_findings)} bulgu tespit edilmiştir. Genel risk seviyesi: {risk_label}."
            if lang == 'tr' else
            f"This assessment executed {total_tests} tests and identified {len(scoped_findings)} findings. "
            f"Overall risk rating: {risk_label}."
        )

    logo_html = ''
    if _is_safe_data_uri(logo_uri):
        logo_html = f'<img class="report-logo" src="{_esc(logo_uri)}"/>'

    confidential_html = ''
    if confidential:
        label = 'GİZLİ' if lang == 'tr' else 'CONFIDENTIAL'
        confidential_html = f'<div class="confidential-banner">{label}</div>'

    sev_table_cells = ''.join(
        f'<td style="background:{SEVERITY_HEX[s]};"><div class="sev-count">{sev_counts[s]}</div>'
        f'<div class="sev-label">{s.upper()}</div></td>'
        for s in SEVERITY_ORDER
    )

    findings_html = _render_findings_pdf(sorted_findings, lang, template)

    coverage_html = ''
    if all_results:
        pct = round((completed / total_tests) * 100, 1) if total_tests else 0
        coverage_html = f'''
        <div class="report-section">
          <h2>{'Test Kapsamı' if lang == 'tr' else 'Test Coverage'}</h2>
          <p>{'Tamamlanan' if lang == 'tr' else 'Completed'}: <b>{completed}/{total_tests}</b> (%{pct})</p>
        </div>'''

    generated_at = datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')

    html = f'''<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<style>
@font-face {{ font-family: "Vera"; src: url("{_FONT_REGULAR}"); }}
@font-face {{ font-family: "Vera"; font-weight: bold; src: url("{_FONT_BOLD}"); }}

@page {{
  size: a4 portrait;
  margin: 2.6cm 1.8cm 2.2cm 1.8cm;
  @frame footer_frame {{
    -pdf-frame-content: footerContent;
    bottom: 1cm; margin-left: 1.8cm; margin-right: 1.8cm; height: 1.2cm;
  }}
}}

body {{ font-family: "Vera"; font-size: 9.5pt; color: #1e293b; }}
#footerContent {{ text-align: center; font-size: 7.5pt; color: #94a3b8; border-top: 0.5pt solid #cbd5e1; padding-top: 4px; }}

.confidential-banner {{ background-color: #991818; color: #ffffff; text-align: center; padding: 6px; font-weight: bold; }}

.report-cover {{ text-align: center; padding-top: 40px; }}
.report-logo {{ max-height: 60px; }}
.report-cover h1 {{ font-size: 22pt; color: #0f172a; margin-bottom: 4px; }}
.report-subtitle {{ color: #64748b; font-size: 11pt; margin-bottom: 30px; }}
.cover-meta {{ margin: 0 auto; width: 70%; }}
.cover-meta td {{ padding: 5px 10px; font-size: 10pt; border-bottom: 0.5pt solid #e2e8f0; }}
.cover-meta td.k {{ color: #64748b; font-weight: bold; width: 40%; }}

.report-section {{ margin-top: 18px; margin-bottom: 10px; page-break-inside: avoid; }}
.report-section h2 {{ font-size: 13pt; color: #0f172a; border-bottom: 1pt solid #e2e8f0; padding-bottom: 6px; }}

.risk-badge {{ display: inline; color: #ffffff; padding: 4px 12px; font-weight: bold; }}

.sev-summary-table {{ width: 100%; border-collapse: collapse; }}
.sev-summary-table td {{ color: #ffffff; text-align: center; padding: 10px 2px; width: 20%; }}
.sev-count {{ font-size: 16pt; font-weight: bold; }}
.sev-label {{ font-size: 8pt; }}

.finding-item {{ border-left: 3pt solid #475569; padding: 8px 10px; margin-bottom: 12px; background-color: #f8fafc; page-break-inside: avoid; }}
.finding-header-table {{ width: 100%; }}
.finding-header-table td {{ vertical-align: middle; padding: 0; border: none; }}
.finding-code {{ font-size: 8pt; color: #64748b; width: 90px; }}
.sev-chip-cell {{ width: 70px; }}
.sev-chip {{ color: #ffffff; font-size: 7.5pt; font-weight: bold; padding: 2px 6px; }}
.finding-title {{ font-weight: bold; font-size: 10.5pt; }}
.finding-meta {{ font-size: 8pt; color: #64748b; margin: 3px 0 6px; }}
.finding-item p {{ margin: 4px 0; font-size: 9.5pt; line-height: 1.4; }}
.empty-state {{ color: #64748b; font-style: italic; }}
</style>
</head>
<body>
<div id="footerContent">{_esc(project.get('name', ''))} &middot; {generated_at}</div>

{confidential_html}

<div class="report-cover">
  {logo_html}
  <h1>{_esc(title)}</h1>
  <p class="report-subtitle">{'Sızma Testi Değerlendirme Raporu' if lang == 'tr' else 'Penetration Test Assessment Report'}</p>
  <table class="cover-meta">
    <tr><td class="k">{'Müşteri' if lang == 'tr' else 'Client'}</td><td>{_esc(client_name) or '-'}</td></tr>
    <tr><td class="k">{'Test Uzmanı' if lang == 'tr' else 'Pentester'}</td><td>{_esc(pentester_name) or '-'}</td></tr>
    <tr><td class="k">{'Tarih Aralığı' if lang == 'tr' else 'Date Range'}</td><td>{_esc(date_range) or '-'}</td></tr>
    <tr><td class="k">{'Oluşturulma' if lang == 'tr' else 'Generated'}</td><td>{generated_at}</td></tr>
  </table>
</div>

<div style="page-break-before: always;"></div>

<div class="report-section">
  <h2>{'Yönetici Özeti' if lang == 'tr' else 'Executive Summary'}</h2>
  <p>{_esc(executive_summary)}</p>
  <div class="risk-badge" style="background-color:{risk_color};">
    {'Genel Risk' if lang == 'tr' else 'Overall Risk'}: {risk_label}
  </div>
</div>

<div class="report-section">
  <h2>{'Risk Özeti' if lang == 'tr' else 'Risk Summary'}</h2>
  <table class="sev-summary-table"><tr>{sev_table_cells}</tr></table>
</div>

{coverage_html}

<div class="report-section" style="page-break-inside:auto;">
  <h2>{'Bulgular' if lang == 'tr' else 'Findings'}</h2>
  {findings_html}
</div>

<div class="report-section">
  <h2>{'Ekler' if lang == 'tr' else 'Appendices'}</h2>
  <p>{'Test Kapsam Matrisi' if lang == 'tr' else 'Test Coverage Matrix'}: {completed}/{total_tests}</p>
  <p>{'Toplam Bulgu' if lang == 'tr' else 'Total Findings'}: {len(scoped_findings)}</p>
</div>

</body>
</html>'''

    buf = io.BytesIO()
    result = pisa.CreatePDF(io.StringIO(html), dest=buf, encoding='utf-8')
    if result.err:
        raise PdfReportError('PDF oluşturulamadı (xhtml2pdf hata kodu: %s)' % result.err)
    buf.seek(0)
    return buf
