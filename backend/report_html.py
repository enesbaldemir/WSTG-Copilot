"""
HTML Profesyonel Rapor.

Tek dosyalik, disariya bagimliligi olmayan (gomulu CSS, harici script/CDN
yok) bir HTML pentest raporu uretir. PDF ihtiyaci icin ayri bir sunucu
tarafi kutuphane (WeasyPrint/pdfkit) EKLENMEDI -- Windows'ta bu kutuphaneler
(GTK runtime / wkhtmltopdf binary) kurulum riski tasidigi icin, rapor
kendi icinde "Print / Save as PDF" butonu barindirir ve @media print
kurallariyla tarayicinin yerel yazdirma diyalogu uzerinden PDF'e
donusturulmesini saglar.

DOCX raporlariyla (report_builder.py) ayni kavramsal yapiyi izler:
kapak -> yonetici ozeti -> risk/severity tablosu -> detayli bulgular ->
ekler. report_builder.py'nin ic (underscore ile baslayan) yardimcilarina
bagimli olmamak icin kucuk severity siralama/sayma mantigi burada
tekrarlanir (report_builder.py'yi degistirmeden, dusuk riskli bir yaklasim).
"""

import html as html_lib
from datetime import datetime

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
SEVERITY_HEX = {
    'critical': '#991818',
    'high': '#c2410c',
    'medium': '#a16207',
    'low': '#15803d',
    'info': '#475569',
}


def _esc(value):
    return html_lib.escape(str(value)) if value is not None else ''


def _severity_counts(findings):
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get('severity') or 'info').lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _sorted_findings(findings):
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: rank.get((f.get('severity') or 'info').lower(), 99))


def _filter_findings(findings, include):
    if include in (None, 'all'):
        return list(findings)
    if include == 'critical_high':
        return [f for f in findings if (f.get('severity') or '').lower() in ('critical', 'high')]
    if isinstance(include, (list, tuple, set)):
        wanted = {int(i) for i in include}
        return [f for f in findings if f.get('id') in wanted]
    return list(findings)


def _overall_risk_label(severity_counts, lang):
    if severity_counts.get('critical') or severity_counts.get('high'):
        return ('YÜKSEK', '#c2410c') if lang == 'tr' else ('HIGH', '#c2410c')
    if severity_counts.get('medium'):
        return ('ORTA', '#a16207') if lang == 'tr' else ('MEDIUM', '#a16207')
    if severity_counts.get('low'):
        return ('DÜŞÜK', '#15803d') if lang == 'tr' else ('LOW', '#15803d')
    return ('BİLGİ', '#475569') if lang == 'tr' else ('INFO', '#475569')


def _is_safe_data_uri(value):
    return isinstance(value, str) and value.strip().lower().startswith('data:image/')


def build_html_report(project, findings, all_results, options=None, executive_summary=None, lang='tr'):
    """
    project: Project.to_dict()
    findings: [Finding.to_dict(), ...] (proje genelindeki tum bulgular; filtreleme burada yapilir)
    all_results: [TestResult.to_dict(), ...] (kapsam/metodoloji ekinde kullanilir)
    options: {
        'title': str, 'client_name': str, 'pentester_name': str,
        'date_range': str, 'logo_data_uri': str, 'include': 'all'|'critical_high'|list[int],
        'template': 'standard'|'executive'|'detailed', 'confidential': bool
    }
    executive_summary: onceden uretilmis (AI veya manuel duzenlenmis) metin; verilmezse
                        istatistik tabanli sade bir paragraf kullanilir.
    """
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
        logo_html = f'<img class="report-logo" src="{_esc(logo_uri)}" alt="logo">'

    confidential_html = ''
    if confidential:
        label = 'GİZLİ' if lang == 'tr' else 'CONFIDENTIAL'
        confidential_html = f'<div class="confidential-banner">{label}</div>'

    sev_table_rows = "".join(
        f'<td style="background:{SEVERITY_HEX[s]}"><div class="sev-count">{sev_counts[s]}</div>'
        f'<div class="sev-label">{s.upper()}</div></td>'
        for s in SEVERITY_ORDER
    )

    findings_html = _render_findings_section(sorted_findings, lang, template)

    coverage_html = ''
    if all_results:
        pct = round((completed / total_tests) * 100, 1) if total_tests else 0
        coverage_html = f'''
        <section class="report-section">
          <h2>{'Test Kapsamı' if lang == 'tr' else 'Test Coverage'}</h2>
          <p>{'Tamamlanan' if lang == 'tr' else 'Completed'}: <strong>{completed}/{total_tests}</strong> (%{pct})</p>
        </section>'''

    generated_at = datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')

    return f'''<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{_REPORT_CSS}
</style>
</head>
<body>
{confidential_html}
<div class="report-toolbar no-print">
  <button onclick="window.print()">{'🖨️ Yazdır / PDF Olarak Kaydet' if lang == 'tr' else '🖨️ Print / Save as PDF'}</button>
</div>

<header class="report-cover">
  {logo_html}
  <h1>{_esc(title)}</h1>
  <p class="report-subtitle">{'Sızma Testi Değerlendirme Raporu' if lang == 'tr' else 'Penetration Test Assessment Report'}</p>
  <table class="cover-meta">
    <tr><td>{'Müşteri' if lang == 'tr' else 'Client'}</td><td>{_esc(client_name) or '-'}</td></tr>
    <tr><td>{'Test Uzmanı' if lang == 'tr' else 'Pentester'}</td><td>{_esc(pentester_name) or '-'}</td></tr>
    <tr><td>{'Tarih Aralığı' if lang == 'tr' else 'Date Range'}</td><td>{_esc(date_range) or '-'}</td></tr>
    <tr><td>{'Oluşturulma' if lang == 'tr' else 'Generated'}</td><td>{generated_at}</td></tr>
  </table>
</header>

<main class="report-body">
  <section class="report-section">
    <h2>{'Yönetici Özeti' if lang == 'tr' else 'Executive Summary'}</h2>
    <p>{_esc(executive_summary)}</p>
    <div class="risk-badge" style="background:{risk_color}">
      {'Genel Risk' if lang == 'tr' else 'Overall Risk'}: {risk_label}
    </div>
  </section>

  <section class="report-section">
    <h2>{'Risk Özeti' if lang == 'tr' else 'Risk Summary'}</h2>
    <table class="sev-summary-table"><tr>{sev_table_rows}</tr></table>
  </section>

  {coverage_html}

  <section class="report-section">
    <h2>{'Bulgular' if lang == 'tr' else 'Findings'}</h2>
    {findings_html}
  </section>

  <section class="report-section">
    <h2>{'Ekler' if lang == 'tr' else 'Appendices'}</h2>
    <ul>
      <li>{'Test Kapsam Matrisi' if lang == 'tr' else 'Test Coverage Matrix'}: {completed}/{total_tests}</li>
      <li>{'Toplam Bulgu' if lang == 'tr' else 'Total Findings'}: {len(scoped_findings)}</li>
    </ul>
  </section>
</main>

<footer class="report-footer">
  <p>{_esc(project.get('name', ''))} — {generated_at}</p>
</footer>
</body>
</html>'''


def _render_findings_section(sorted_findings, lang, template):
    if not sorted_findings:
        return f'<p class="empty-state">{"Bu değerlendirmede bulgu tespit edilmemiştir." if lang == "tr" else "No findings were identified in this assessment."}</p>'

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
        meta_line = ' · '.join(meta_bits)

        body_blocks = [f'<p>{_esc(f.get("description") or "")}</p>']
        if template != 'executive':
            if f.get('endpoint'):
                body_blocks.append(f'<p><strong>{"Endpoint" if lang=="tr" else "Endpoint"}:</strong> {_esc(f["endpoint"])}</p>')
            if f.get('impact'):
                body_blocks.append(f'<p><strong>{"Etki" if lang=="tr" else "Impact"}:</strong> {_esc(f["impact"])}</p>')
            if f.get('remediation'):
                body_blocks.append(f'<p><strong>{"Giderim" if lang=="tr" else "Remediation"}:</strong> {_esc(f["remediation"])}</p>')

        items.append(f'''
        <article class="finding-item" style="border-left-color:{color}">
          <div class="finding-header">
            <span class="finding-code">{_esc(code)}</span>
            <span class="sev-chip" style="background:{color}">{sev.upper()}</span>
            <span class="finding-title">{_esc(f.get('title') or '')}</span>
          </div>
          <div class="finding-meta">{meta_line}</div>
          {''.join(body_blocks)}
        </article>''')
    return ''.join(items)


_REPORT_CSS = '''
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #f1f5f9; color: #1e293b; }
  .report-toolbar { position: sticky; top: 0; background: #0f172a; padding: 10px 20px; text-align: right; z-index: 10; }
  .report-toolbar button { background: #6366f1; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; }
  .confidential-banner { background: #991818; color: #fff; text-align: center; padding: 6px; font-weight: bold; letter-spacing: 2px; }
  .report-cover { text-align: center; padding: 48px 20px; background: #fff; border-bottom: 4px solid #6366f1; }
  .report-logo { max-height: 64px; margin-bottom: 16px; }
  .report-cover h1 { margin: 0 0 8px; font-size: 28px; }
  .report-subtitle { color: #64748b; margin: 0 0 24px; }
  .cover-meta { margin: 0 auto; border-collapse: collapse; }
  .cover-meta td { padding: 4px 12px; text-align: left; font-size: 14px; }
  .cover-meta td:first-child { color: #64748b; font-weight: 600; }
  .report-body { max-width: 900px; margin: 0 auto; padding: 24px 20px 60px; }
  .report-section { background: #fff; border-radius: 10px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow-x: auto; }
  .report-section h2 { margin-top: 0; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; }
  .risk-badge { display: inline-block; color: #fff; padding: 6px 14px; border-radius: 6px; font-weight: 600; margin-top: 8px; }
  .sev-summary-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
  .sev-summary-table td { color: #fff; text-align: center; padding: 14px 4px; border-radius: 6px; }
  .sev-count { font-size: 22px; font-weight: 700; }
  .sev-label { font-size: 11px; letter-spacing: 1px; }
  .finding-item { border-left: 4px solid #475569; padding: 12px 16px; margin-bottom: 16px; background: #f8fafc; border-radius: 0 8px 8px 0; page-break-inside: avoid; }
  .finding-header { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 4px; }
  .finding-code { font-family: monospace; color: #64748b; font-size: 13px; }
  .sev-chip { color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
  .finding-title { font-weight: 600; font-size: 15px; }
  .finding-meta { font-size: 12px; color: #64748b; margin-bottom: 8px; }
  .finding-item p { margin: 6px 0; font-size: 14px; line-height: 1.5; }
  .empty-state { color: #64748b; font-style: italic; }
  .report-footer { text-align: center; color: #94a3b8; font-size: 12px; padding: 20px; }
  @media print {
    .no-print { display: none !important; }
    body { background: #fff; }
    .report-section { box-shadow: none; border: 1px solid #e2e8f0; }
    .finding-item { break-inside: avoid; }
  }
'''
