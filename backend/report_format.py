"""
Shared formatting and test coverage helpers for reports.

- format_pct: percentages in the report language ("%38,8" in Turkish, "38.8%" in English).
- format_generated_at: report timestamps in the report language.
- coverage: completed/total per checklist (WSTG, LLM Security), counted against the full
  checklist rather than only the tests that have a result. This matches the project dashboard.
"""
import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WSTG_DATA_PATH = os.path.join(BASE_DIR, 'data', 'wstg-checklist.en.json')
LLM_DATA_PATH = os.path.join(BASE_DIR, 'data', 'llm-security-checklist.en.json')


def _load_test_ids(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return frozenset()
    return frozenset(
        test['id']
        for cat in data.get('categories', [])
        for test in cat.get('tests', [])
        if test.get('id')
    )


WSTG_TEST_IDS = frozenset(i for i in _load_test_ids(WSTG_DATA_PATH) if i.startswith('WSTG-'))
LLM_TEST_IDS = frozenset(i for i in _load_test_ids(LLM_DATA_PATH) if i.startswith('LLM-'))


def format_pct(value, lang='tr'):
    """38.8 -> '%38,8' (tr) / '38.8%' (en); 100.0 -> '%100' / '100%'."""
    try:
        number = round(float(value or 0), 1)
    except (TypeError, ValueError):
        number = 0.0
    text = f'{number:.1f}'.rstrip('0').rstrip('.')
    if lang == 'tr':
        return '%' + text.replace('.', ',')
    return text + '%'


def format_generated_at(dt=None, lang='tr'):
    """Report timestamp: '07.11.2026 22:14 UTC' (tr) / '2026-11-07 22:14 UTC' (en)."""
    dt = dt or datetime.utcnow()
    if lang == 'tr':
        return dt.strftime('%d.%m.%Y %H:%M UTC')
    return dt.strftime('%Y-%m-%d %H:%M UTC')


def format_date(dt, lang='tr'):
    """Date only: '07.11.2026' (tr) / '2026-11-07' (en)."""
    if lang == 'tr':
        return dt.strftime('%d.%m.%Y')
    return dt.strftime('%Y-%m-%d')


def _field(result, name):
    if isinstance(result, dict):
        return result.get(name)
    return getattr(result, name, None)


def _entry(completed_n, total_n):
    return {
        'completed': completed_n,
        'total': total_n,
        'pct': round((completed_n / total_n) * 100, 1) if total_n else 0,
    }


def coverage(results, custom_total=0):
    """
    results: TestResult models or their to_dict() output.
    Returns {'wstg': {...}, 'llm': {...}, 'custom': {...}} with completed, total and pct.
    A test counts once even if several sessions recorded it; 'pending' does not count.
    """
    wstg_done, llm_done, custom_done = set(), set(), set()
    for r in results or []:
        test_id = _field(r, 'test_id') or ''
        status = _field(r, 'status')
        if not status or status == 'pending':
            continue
        if test_id.startswith('WSTG-'):
            wstg_done.add(test_id)
        elif test_id.startswith('LLM-'):
            llm_done.add(test_id)
        elif test_id.startswith('CUSTOM-'):
            custom_done.add(test_id)
    return {
        'wstg': _entry(len(wstg_done), len(WSTG_TEST_IDS)),
        'llm': _entry(len(llm_done), len(LLM_TEST_IDS)),
        'custom': _entry(len(custom_done), custom_total or 0),
    }


def used_frameworks(results):
    """Checklists that have at least one result, in display order. WSTG when there are none."""
    prefixes = {(_field(r, 'test_id') or '').split('-', 1)[0] for r in results or []}
    used = [key for key, prefix in (('wstg', 'WSTG'), ('llm', 'LLM')) if prefix in prefixes]
    return used or ['wstg']


FRAMEWORK_LABELS = {'wstg': 'OWASP WSTG', 'llm': 'OWASP LLM Top 10'}


def report_coverage(results, lang='tr'):
    """
    Coverage for the project reports: one line per checklist used, plus totals for the
    executive summary. Each line: {'label', 'completed', 'total', 'pct_text'}.
    """
    cov = coverage(results)
    lines = []
    for key in used_frameworks(results):
        entry = cov[key]
        lines.append({
            'label': FRAMEWORK_LABELS[key],
            'completed': entry['completed'],
            'total': entry['total'],
            'pct_text': format_pct(entry['pct'], lang),
        })
    completed = sum(line['completed'] for line in lines)
    total = sum(line['total'] for line in lines)
    pct = round((completed / total) * 100, 1) if total else 0
    return {'lines': lines, 'completed': completed, 'total': total, 'pct_text': format_pct(pct, lang)}


def default_executive_summary(cov, findings_count, risk_label, lang='tr'):
    if lang == 'tr':
        return (f"Bu değerlendirmede {cov['completed']}/{cov['total']} test tamamlanmış ({cov['pct_text']}) "
                f"ve {findings_count} bulgu tespit edilmiştir. Genel risk seviyesi: {risk_label}.")
    return (f"This assessment completed {cov['completed']} of {cov['total']} tests ({cov['pct_text']}) "
            f"and identified {findings_count} findings. Overall risk rating: {risk_label}.")
