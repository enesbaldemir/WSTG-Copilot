"""
Yeniden Test Raporu (HTML ve PDF).

Müşteri bulguları düzelttiğini bildirdikten sonra yapılan yeniden testin
sonucunu özetler: hangi bulgunun düzeldiği doğrulandı, hangisi hâlâ açık,
hangisi henüz yeniden test edilmedi. Sınıflandırma retest.py'dedir.

  build_html(project, findings, options, lang) -> str
  build_pdf(project, findings, options, lang)  -> BytesIO
"""

from datetime import datetime
from html import escape

import report_pdf
import retest as retest_lib
from report_html import SEVERITY_ORDER, SEVERITY_HEX

STATE_ORDER = ('verified', 'still_open', 'pending')
STATE_COLOR = {'verified': '#15803d', 'still_open': '#b42318', 'pending': '#a15c07'}

TEXT = {
    'tr': {
        'subtitle': 'Yeniden Test Raporu', 'title_suffix': 'Yeniden Test Raporu',
        'client': 'Müşteri', 'pentester': 'Test Uzmanı', 'retest_date': 'Yeniden Test Tarihi', 'generated': 'Oluşturulma',
        'summary': 'Özet',
        'summary_text': ('Daha önce raporlanan ve düzeltildiği bildirilen bulgular yeniden test edilmiştir. '
                         'Bu rapor yalnızca yeniden test kapsamındaki bulguları içerir.'),
        'state_verified': 'Düzeldi (doğrulandı)', 'state_still_open': 'Hâlâ açık', 'state_pending': 'Yeniden test edilmedi',
        'total': 'Kapsamdaki bulgu',
        'overview': 'Sonuçlar', 'code': 'Kod', 'finding': 'Bulgu', 'severity': 'Önem', 'endpoint': 'Endpoint',
        'result': 'Sonuç', 'date': 'Tarih',
        'details': 'Bulgu Ayrıntıları', 'retest_note': 'Yeniden test notu', 'remediation': 'Çözüm önerisi',
        'no_note': 'Not girilmedi.', 'empty': 'Yeniden test kapsamında bulgu yok.',
        'confidential': 'GİZLİ',
    },
    'en': {
        'subtitle': 'Retest Report', 'title_suffix': 'Retest Report',
        'client': 'Client', 'pentester': 'Pentester', 'retest_date': 'Retest Date', 'generated': 'Generated',
        'summary': 'Summary',
        'summary_text': ('Findings that were previously reported and declared fixed have been retested. '
                         'This report only covers findings in the retest scope.'),
        'state_verified': 'Fixed (verified)', 'state_still_open': 'Still open', 'state_pending': 'Not yet retested',
        'total': 'Findings in scope',
        'overview': 'Results', 'code': 'ID', 'finding': 'Finding', 'severity': 'Severity', 'endpoint': 'Endpoint',
        'result': 'Result', 'date': 'Date',
        'details': 'Finding Details', 'retest_note': 'Retest note', 'remediation': 'Remediation',
        'no_note': 'No note.', 'empty': 'No findings are in the retest scope.',
        'confidential': 'CONFIDENTIAL',
    },
}


def _t(lang):
    return TEXT['en' if lang == 'en' else 'tr']


def _date(iso):
    if not iso:
        return '—'
    try:
        return datetime.fromisoformat(str(iso).replace('Z', '')).strftime('%d.%m.%Y')
    except ValueError:
        return '—'


def _sev(f):
    s = (f.get('severity') or 'info').lower()
    return s if s in SEVERITY_ORDER else 'info'


def prepare(findings, include_pending=True):
    """Kapsamdaki bulgular: durum (doğrulandı, hâlâ açık, bekliyor) ve önem sırasına göre."""
    items = []
    for f in findings:
        st = retest_lib.classify(f)
        if not st or (st == 'pending' and not include_pending):
            continue
        items.append(dict(f, retest_state=st))
    items.sort(key=lambda f: (STATE_ORDER.index(f['retest_state']), SEVERITY_ORDER.index(_sev(f)), f.get('id') or 0))
    counts = {k: sum(1 for f in items if f['retest_state'] == k) for k in STATE_ORDER}
    counts['total'] = len(items)
    return items, counts


def _code(f):
    return f.get('finding_code') or (f"FND-{f['id']:04d}" if f.get('id') else '')


def _wrap(text, width=30):
    """xhtml2pdf boşluksuz uzun metni bölemez; '/' ve sabit uzunlukta böler."""
    out, line = [], ''
    protected = str(text).replace('://', '\x01')      # şema ayracını bölme
    for seg in protected.replace('/', '\x00/').split('\x00'):
        seg = seg.replace('\x01', '://')
        while len(seg) > width:
            if line:
                out.append(line)
                line = ''
            out.append(seg[:width])
            seg = seg[width:]
        if line and len(line) + len(seg) > width:
            out.append(line)
            line = ''
        line += seg
    if line:
        out.append(line)
    return '<br/>'.join(escape(x) for x in out)


def _body(project, items, counts, options, lang, pdf):
    T = _t(lang)
    template = options.get('template') or 'standard'
    title = options.get('title') or project.get('name', '') or T['title_suffix']
    generated = datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')
    retest_date = options.get('retest_date') or _date(max((f.get('retested_at') or '' for f in items), default='')) or '—'
    endpoint = (lambda e: _wrap(e, 22)) if pdf else (lambda e: f'<code>{escape(e)}</code>')

    cards = ''.join(
        f'<td style="background-color:{STATE_COLOR[k]};" class="state-card"><div class="state-count">{counts[k]}</div>'
        f'<div class="state-label">{escape(T["state_" + k])}</div></td>' for k in STATE_ORDER)

    if items:
        rows = ''.join(f'''<tr>
          <td class="c">{escape(_code(f))}</td><td class="c">{escape(f.get("title") or "")}</td>
          <td class="c"><span class="chip" style="background-color:{SEVERITY_HEX[_sev(f)]};">{_sev(f).upper()}</span></td>
          <td class="c">{endpoint(f.get("endpoint")) if f.get("endpoint") else "—"}</td>
          <td class="c" style="color:{STATE_COLOR[f["retest_state"]]};font-weight:bold;">{escape(T["state_" + f["retest_state"]])}</td>
          <td class="c">{_date(f.get("retested_at")) if f["retest_state"] != "pending" else "—"}</td></tr>''' for f in items)
        widths = ('11%', '27%', '10%', '24%', '16%', '12%')
        heads = (T["code"], T["finding"], T["severity"], T["endpoint"], T["result"], T["date"])
        table = f'''<table class="rt-table"><thead><tr>
          {"".join(f'<th class="c" style="width:{w};">{escape(h)}</th>' for w, h in zip(widths, heads))}
        </tr></thead><tbody>{rows}</tbody></table>'''
    else:
        table = f'<p class="empty">{escape(T["empty"])}</p>'

    details = ''
    if items and template != 'executive':
        blocks = []
        for f in items:
            st = f['retest_state']
            note = (f.get('retest_notes') or '').strip() if st != 'pending' else ''
            rem = (f.get('remediation') or '').strip() if st != 'verified' else ''
            blocks.append(f'''<div class="rt-item" style="border-left-color:{STATE_COLOR[st]};">
              <div class="rt-head"><span class="rt-code">{escape(_code(f))}</span> <b>{escape(f.get("title") or "")}</b>
                — <span style="color:{STATE_COLOR[st]};font-weight:bold;">{escape(T["state_" + st])}</span></div>
              {f'<p><b>{escape(T["retest_note"])}:</b> {escape(note)}</p>' if st != 'pending' else ''}
              {f'<p class="muted">{escape(T["no_note"])}</p>' if st != 'pending' and not note else ''}
              {f'<p><b>{escape(T["remediation"])}:</b> {escape(rem)}</p>' if rem else ''}
            </div>''')
        details = f'<div class="rt-section"><h2>{escape(T["details"])}</h2>{"".join(blocks)}</div>'

    conf = f'<div class="conf">{escape(T["confidential"])}</div>' if options.get('confidential') else ''
    return f'''{conf}
<div class="rt-cover">
  <h1>{escape(title)}</h1>
  <p class="sub">{escape(T["subtitle"])}</p>
  <table class="meta">
    <tr><td class="k">{escape(T["client"])}</td><td>{escape(options.get("client_name") or project.get("client") or "-")}</td></tr>
    <tr><td class="k">{escape(T["pentester"])}</td><td>{escape(options.get("pentester_name") or "-")}</td></tr>
    <tr><td class="k">{escape(T["retest_date"])}</td><td>{escape(retest_date)}</td></tr>
    <tr><td class="k">{escape(T["generated"])}</td><td>{generated}</td></tr>
  </table>
</div>
<div class="rt-section">
  <h2>{escape(T["summary"])}</h2>
  <p>{escape(T["summary_text"])}</p>
  <table class="state-table"><tr>{cards}</tr></table>
  <p>{escape(T["total"])}: <b>{counts["total"]}</b></p>
</div>
<div class="rt-section">
  <h2>{escape(T["overview"])}</h2>
  {table}
</div>
{details}'''


HTML_CSS = '''
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #f1f5f9; color: #1e293b; }
  .page { max-width: 920px; margin: 0 auto; padding: 24px 20px 60px; }
  .toolbar { position: sticky; top: 0; background: #0f172a; padding: 10px 20px; text-align: right; }
  .toolbar button { background: #2563eb; color: #fff; border: 0; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; }
  .conf { background: #991818; color: #fff; text-align: center; padding: 6px; font-weight: bold; letter-spacing: 2px; }
  .rt-cover, .rt-section { background: #fff; border-radius: 10px; padding: 24px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow-x: auto; }
  .rt-cover h1 { margin: 0 0 6px; font-size: 26px; }
  .sub { color: #64748b; margin: 0 0 18px; }
  .meta td { padding: 3px 12px 3px 0; font-size: 14px; } .meta .k { color: #64748b; font-weight: 600; }
  h2 { font-size: 18px; margin-top: 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }
  .state-table { width: 100%; border-collapse: separate; border-spacing: 8px 0; table-layout: fixed; margin: 6px -8px; }
  .state-card { color: #fff; text-align: center; padding: 14px 6px; border-radius: 8px; }
  .state-count { font-size: 26px; font-weight: 700; } .state-label { font-size: 12px; }
  .rt-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .rt-table th, .rt-table td { border-bottom: 1px solid #e2e8f0; padding: 8px; text-align: left; vertical-align: top; }
  .rt-table th { background: #f8fafc; }
  .rt-table code { font-family: monospace; font-size: 12px; word-break: break-all; }
  .chip { color: #fff; font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 9px; }
  .rt-item { border-left: 4px solid #475569; background: #f8fafc; padding: 10px 14px; margin-bottom: 12px; border-radius: 0 8px 8px 0; }
  .rt-item p { margin: 6px 0; font-size: 14px; line-height: 1.5; white-space: pre-wrap; }
  .rt-code { font-family: monospace; color: #64748b; }
  .muted, .empty { color: #64748b; font-style: italic; }
  @media print { .no-print { display: none !important; } body { background: #fff; } .rt-cover, .rt-section { box-shadow: none; border: 1px solid #e2e8f0; } }
'''

PDF_CSS = '''
@page { size: a4 portrait; margin: 2.2cm 1.8cm 2.2cm 1.8cm;
  @frame footer_frame { -pdf-frame-content: footerContent; bottom: 1cm; margin-left: 1.8cm; margin-right: 1.8cm; height: 1.2cm; } }
body { font-family: "Vera"; font-size: 9.5pt; color: #1e293b; }
#footerContent { text-align: center; font-size: 7.5pt; color: #94a3b8; }
.conf { background-color: #991818; color: #ffffff; text-align: center; padding: 5px; font-weight: bold; }
.rt-cover h1 { font-size: 20pt; margin-bottom: 2px; }
.sub { color: #64748b; font-size: 11pt; margin-bottom: 14px; }
.meta td { padding: 3px 8px 3px 0; font-size: 9.5pt; } .meta .k { color: #64748b; font-weight: bold; }
.rt-section { margin-top: 14px; }
h2 { font-size: 13pt; border-bottom: 1pt solid #e2e8f0; padding-bottom: 4px; }
.state-card { color: #ffffff; text-align: center; padding: 8px 4px; }
.state-count { font-size: 16pt; font-weight: bold; } .state-label { font-size: 8pt; }
.rt-table { width: 100%; }
.rt-table .c { border-bottom: 0.5pt solid #cbd5e1; padding: 4px; font-size: 8pt; vertical-align: top; }
.rt-table th.c { background-color: #f1f5f9; text-align: left; }
.chip { color: #ffffff; font-size: 7pt; font-weight: bold; padding: 1px 4px; }
.rt-item { border-left: 3pt solid #475569; background-color: #f8fafc; padding: 6px 8px; margin-bottom: 8px; }
.rt-item p { margin: 3px 0; font-size: 9pt; }
.rt-code { color: #64748b; font-size: 8pt; }
.muted, .empty { color: #64748b; font-style: italic; }
'''


def build_html(project, findings, options=None, lang='tr'):
    options = options or {}
    items, counts = prepare(findings, options.get('include_pending', True))
    T = _t(lang)
    print_label = '🖨️ Yazdır / PDF Olarak Kaydet' if lang != 'en' else '🖨️ Print / Save as PDF'
    title = options.get('title') or f"{project.get('name', '')} — {T['title_suffix']}"
    return f'''<!doctype html>
<html lang="{'en' if lang == 'en' else 'tr'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title>
<style>{HTML_CSS}</style></head>
<body><div class="toolbar no-print"><button onclick="window.print()">{print_label}</button></div>
<div class="page">{_body(project, items, counts, options, lang, pdf=False)}</div></body></html>'''


def build_pdf(project, findings, options=None, lang='tr'):
    options = options or {}
    items, counts = prepare(findings, options.get('include_pending', True))
    generated = datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')
    html = f'''<!doctype html><html><head><meta charset="utf-8"><style>{PDF_CSS}</style></head><body>
<div id="footerContent">{escape(project.get("name", ""))} · {escape(_t(lang)["subtitle"])} · {generated}</div>
{_body(project, items, counts, options, lang, pdf=True)}</body></html>'''
    return report_pdf.html_to_pdf(html)
