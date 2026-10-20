"""
Raporlarda "Yetkilendirme Testleri" bölümü (HTML ve PDF).

Kaynak, projenin yetkilendirme matrisidir (authz_matrix.py ile doğrulanmış
belge). Bölüm yalnızca en az bir hücrede sonuç ya da beklenti girilmişse
eklenir. Tüm metinler escape edilir.

  prepare(doc)            -> görünüm modeli ya da None
  render_html(vm, ...)    -> report_html.py için <section>
  render_pdf(vm, ...)     -> report_pdf.py (xhtml2pdf) için <div>
"""

from html import escape

MAX_ROWS = 150

STATUS_STYLE = {   # (arka plan, yazı) — HTML ve PDF aynı renkleri kullanır
    'violation': ('#fdecea', '#b42318'),
    'over': ('#fdf6e7', '#a15c07'),
    'ok': ('#ecf8f1', '#15803d'),
    'observed': ('#f1f5f9', '#334155'),
    'untested': ('#f8fafc', '#64748b'),
    'unset': ('#ffffff', '#94a3b8'),
}

TEXT = {
    'tr': {
        'title': 'Yetkilendirme Testleri',
        'intro': ('Her rolün her endpoint için beklenen erişimi ile testte gözlenen sonuç karşılaştırılmıştır. '
                  'Beklenen "Yasak" iken erişilebilen kaynaklar yetkilendirme açığıdır.'),
        'cells': 'Hücre', 'tested': 'Denendi', 'violations': 'İzinsiz erişim', 'over': 'Fazla kısıtlı', 'untested': 'Denenmedi',
        'violations_title': 'İzinsiz erişimler', 'no_violations': 'Testlerde izinsiz erişim gözlenmedi.',
        'role': 'Rol', 'endpoint': 'Endpoint', 'note': 'Not', 'finding': 'Bulgu',
        'matrix_title': 'Matris (beklenen → gözlenen)',
        'allow': 'İzinli', 'deny': 'Yasak', 'allowed': 'Erişti', 'denied': 'Engellendi', 'none': '—', 'not_tested': 'denenmedi',
        'more_rows': 'satır daha (tam liste uygulamada)',
        'empty_rows': 'sonuç girilmemiş endpoint tabloya alınmadı',
    },
    'en': {
        'title': 'Authorization Testing',
        'intro': ('For each role and endpoint, the expected access was compared with the result observed during testing. '
                  'Resources expected to be "Denied" that were accessible are authorization flaws.'),
        'cells': 'Cells', 'tested': 'Tested', 'violations': 'Unauthorized', 'over': 'Over-restricted', 'untested': 'Untested',
        'violations_title': 'Unauthorized access', 'no_violations': 'No unauthorized access was observed.',
        'role': 'Role', 'endpoint': 'Endpoint', 'note': 'Note', 'finding': 'Finding',
        'matrix_title': 'Matrix (expected → observed)',
        'allow': 'Allowed', 'deny': 'Denied', 'allowed': 'Accessible', 'denied': 'Blocked', 'none': '—', 'not_tested': 'not tested',
        'more_rows': 'more rows (full list in the application)',
        'empty_rows': 'endpoint(s) without results omitted from the table',
    },
}


def _status(cell):
    if not cell.get('observed'):
        return 'untested' if cell.get('expected') else 'unset'
    if not cell.get('expected'):
        return 'observed'
    if cell['expected'] == 'deny' and cell['observed'] == 'allowed':
        return 'violation'
    if cell['expected'] == 'allow' and cell['observed'] == 'denied':
        return 'over'
    return 'ok'


def prepare(doc):
    if not doc or not doc.get('roles') or not doc.get('endpoints'):
        return None
    cells = doc.get('cells') or {}
    if not cells:
        return None
    roles = doc['roles']
    rows, violations, empty = [], [], 0
    summary = {'cells': len(roles) * len(doc['endpoints']), 'tested': 0, 'violations': 0, 'over': 0}
    for e in doc['endpoints']:
        row_cells, filled = [], False
        for r in roles:
            c = cells.get(f"{e['id']}:{r['id']}") or {}
            st = _status(c)
            filled = filled or st != 'unset'
            if c.get('observed'):
                summary['tested'] += 1
            if st == 'violation':
                summary['violations'] += 1
                violations.append({'role': r['name'], 'method': e['method'], 'path': e['path'],
                                   'note': c.get('note') or '', 'finding_id': c.get('finding_id')})
            elif st == 'over':
                summary['over'] += 1
            row_cells.append({'status': st, 'expected': c.get('expected'), 'observed': c.get('observed')})
        if filled:
            rows.append({'method': e['method'], 'path': e['path'], 'cells': row_cells})
        else:
            empty += 1
    if summary['tested'] == 0 and not any(c.get('expected') for c in cells.values()):
        return None
    summary['untested'] = summary['cells'] - summary['tested']
    return {'roles': [r['name'] for r in roles], 'rows': rows[:MAX_ROWS], 'more_rows': max(0, len(rows) - MAX_ROWS),
            'empty_rows': empty, 'summary': summary, 'violations': violations}


def _t(lang):
    return TEXT['en' if lang == 'en' else 'tr']


def _cell_text(c, T, arrow='→'):
    exp = T[c['expected']] if c['expected'] else T['none']
    obs = T[c['observed']] if c['observed'] else T['not_tested']
    return f"{exp} {arrow} {obs}" if (c['expected'] or c['observed']) else T['none']


PDF_PATH_LINE = 26


def _wrap_path(path, width=PDF_PATH_LINE):
    """xhtml2pdf boşluksuz metni bölemez; yolu '/' sınırlarından (gerekirse
    sabit uzunlukta) satırlara ayırır."""
    parts, line = [], ''
    for seg in path.replace('/', '\x00/').split('\x00'):
        while len(seg) > width:
            if line:
                parts.append(line)
                line = ''
            parts.append(seg[:width])
            seg = seg[width:]
        if len(line) + len(seg) > width and line:
            parts.append(line)
            line = ''
        line += seg
    if line:
        parts.append(line)
    return parts


def _path_html(method, path, pdf=False):
    if not pdf:
        return f'<code>{escape(method)} {escape(path)}</code>'
    # PDF: Courier Türkçe karakter içermez ve satır bölmez -> Vera + elle bölme
    return f'<span class="authz-path">{escape(method)}<br/>' + '<br/>'.join(escape(x) for x in _wrap_path(path)) + '</span>'


def _finding_code(fid):
    return f'FND-{fid:04d}' if isinstance(fid, int) and fid > 0 else ''


def _violations_table(vm, T, cell_attr='', pdf=False):
    if not vm['violations']:
        return f'<p>{escape(T["no_violations"])}</p>'
    head = ''.join(f'<th{cell_attr}>{escape(h)}</th>' for h in (T['role'], T['endpoint'], T['note'], T['finding']))
    body = ''.join(
        f'<tr><td{cell_attr}>{escape(v["role"])}</td><td{cell_attr}>{_path_html(v["method"], v["path"], pdf)}</td>'
        f'<td{cell_attr}>{escape(v["note"]) or "—"}</td><td{cell_attr}>{escape(_finding_code(v["finding_id"])) or "—"}</td></tr>'
        for v in vm['violations'])
    return f'<table class="authz-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def _summary_line(vm, T):
    s = vm['summary']
    return ' · '.join(f'{escape(T[k])}: <strong>{s[k2]}</strong>' for k, k2 in
                      (('cells', 'cells'), ('tested', 'tested'), ('violations', 'violations'), ('over', 'over'), ('untested', 'untested')))


def _matrix_table(vm, T, cell_attr='', style_cells=True, pdf=False):
    head = f'<th{cell_attr}>{escape(T["endpoint"])}</th>' + ''.join(f'<th{cell_attr}>{escape(r)}</th>' for r in vm['roles'])
    body = []
    for row in vm['rows']:
        tds = []
        for c in row['cells']:
            bg, fg = STATUS_STYLE[c['status']]
            style = f' style="background-color:{bg};color:{fg};"' if style_cells else ''
            tds.append(f'<td{cell_attr}{style} class="authz-{c["status"]}">{escape(_cell_text(c, T, "/" if pdf else "→"))}</td>')
        body.append(f'<tr><td{cell_attr}>{_path_html(row["method"], row["path"], pdf)}</td>{"".join(tds)}</tr>')
    notes = []
    if vm['more_rows']:
        notes.append(f'+{vm["more_rows"]} {escape(T["more_rows"])}')
    if vm['empty_rows']:
        notes.append(f'{vm["empty_rows"]} {escape(T["empty_rows"])}')
    note_html = f'<p class="authz-note">{" · ".join(notes)}</p>' if notes else ''
    return f'<table class="authz-table authz-matrix"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>{note_html}'


def render_html(vm, lang='tr', template='standard'):
    if not vm:
        return ''
    T = _t(lang)
    matrix = '' if template == 'executive' else f'<h3>{escape(T["matrix_title"])}</h3>{_matrix_table(vm, T)}'
    return f'''
  <section class="report-section">
    <h2>{escape(T["title"])}</h2>
    <p>{escape(T["intro"])}</p>
    <p class="authz-summary">{_summary_line(vm, T)}</p>
    <h3>{escape(T["violations_title"])}</h3>
    {_violations_table(vm, T)}
    {matrix}
  </section>'''


def render_pdf(vm, lang='tr', template='standard'):
    if not vm:
        return ''
    T = _t(lang)
    td = ' class="authz-td"'
    title = T["matrix_title"].replace("→", "/")
    matrix = '' if template == 'executive' else f'<h3>{escape(title)}</h3>{_matrix_table(vm, T, cell_attr=td, pdf=True)}'
    return f'''
<div class="report-section">
  <h2>{escape(T["title"])}</h2>
  <p>{escape(T["intro"])}</p>
  <p>{_summary_line(vm, T)}</p>
  <h3>{escape(T["violations_title"])}</h3>
  {_violations_table(vm, T, cell_attr=td, pdf=True)}
  {matrix}
</div>'''


HTML_CSS = '''
  .report-section h3 { font-size: 15px; margin: 18px 0 8px; }
  .authz-summary { font-size: 14px; color: #334155; }
  .authz-table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 8px; }
  .authz-table th, .authz-table td { border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; vertical-align: top; }
  .authz-table th { background: #f8fafc; font-weight: 600; }
  .authz-table code { font-family: monospace; font-size: 12px; word-break: break-all; }
  .authz-matrix td:not(:first-child) { white-space: nowrap; font-weight: 600; }
  .authz-note { font-size: 12px; color: #64748b; }
'''

PDF_CSS = '''
.report-section h3 { font-size: 10.5pt; margin: 10px 0 4px; }
.authz-table { width: 100%; border-collapse: collapse; margin-bottom: 6px; }
.authz-td { border: 0.5pt solid #cbd5e1; padding: 3px 4px; font-size: 7.5pt; vertical-align: top; }
.authz-table th { border: 0.5pt solid #cbd5e1; padding: 3px 4px; font-size: 7.5pt; background-color: #f1f5f9; text-align: left; }
.authz-note { font-size: 7.5pt; color: #64748b; }
.authz-path { font-size: 7pt; color: #334155; }
'''
