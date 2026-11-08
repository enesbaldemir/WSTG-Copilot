import sys
from datetime import datetime

sys.path.insert(0, '.')

import report_format
import report_html


def test_format_pct_by_language():
    assert report_format.format_pct(100.0, 'tr') == '%100'
    assert report_format.format_pct(100.0, 'en') == '100%'
    assert report_format.format_pct(38.8, 'tr') == '%38,8'
    assert report_format.format_pct(38.8, 'en') == '38.8%'
    assert report_format.format_pct(0, 'en') == '0%'
    assert report_format.format_pct(None, 'tr') == '%0'


def test_generated_at_by_language():
    dt = datetime(2026, 11, 7, 22, 14)
    assert report_format.format_generated_at(dt, 'tr') == '07.11.2026 22:14 UTC'
    assert report_format.format_generated_at(dt, 'en') == '2026-11-07 22:14 UTC'


def test_coverage_counts_against_full_checklist():
    results = [
        {'test_id': 'WSTG-INFO-01', 'status': 'passed'},
        {'test_id': 'WSTG-INFO-01', 'status': 'failed'},   # same test in another session
        {'test_id': 'WSTG-INFO-02', 'status': 'pending'},  # not completed
        {'test_id': 'WSTG-ATHN-03', 'status': 'failed'},
    ]
    cov = report_format.coverage(results)
    assert cov['wstg']['completed'] == 2
    assert cov['wstg']['total'] == len(report_format.WSTG_TEST_IDS) == 98
    assert cov['wstg']['pct'] == 2.0


def test_html_report_uses_full_checklist_total():
    results = [{'test_id': f'WSTG-INFO-0{i}', 'status': 'passed'} for i in range(1, 5)]
    project = {'name': 'Demo', 'client': 'Example Corp'}
    html_en = report_html.build_html_report(project, [], results, lang='en')
    assert 'OWASP WSTG: Completed <strong>4/98</strong> (4.1%)' in html_en
    assert 'completed 4 of 98 tests (4.1%)' in html_en
    assert '%100' not in html_en and '4/4' not in html_en

    html_tr = report_html.build_html_report(project, [], results, lang='tr')
    assert 'OWASP WSTG: Tamamlanan <strong>4/98</strong> (%4,1)' in html_tr
