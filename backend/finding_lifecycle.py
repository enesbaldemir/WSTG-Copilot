"""
Proje bulgularının giderilme (remediation) durum özeti.

İki kaynak var:
  - Hızlı bulgular: checklist maddesindeki not (TestResult.finding) ve
    durumu (TestResult.finding_status).
  - Profesyonel bulgular: Finding kayıtları (Finding.status; farklı bir
    durum sözlüğü kullanır).

Eskiden yalnızca hızlı bulgular sayılıyordu; Bulgular sekmesi altta 6 açık
profesyonel bulgu listelerken üstteki sayaçlar 0 gösteriyordu. Burada ikisi
ortak durum gruplarında birleştirilir.

Çift sayım: bir hızlı bulgu "profesyonel bulguya yükseltildiğinde" ya da
Burp/ZAP içe aktarmasında hem not hem Finding oluştuğunda aynı zafiyet iki
kayıtta durur. Aynı (oturum, test) için bir Finding varsa o testin hızlı
notu ayrıca sayılmaz; Finding notun yerini almış kabul edilir.
"""

LIFECYCLE_STATUSES = ('open', 'retesting', 'fixed', 'resolved', 'wont_fix', 'accepted_risk')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')

# Finding.status -> ortak durum grubu
PRO_STATUS_TO_LIFECYCLE = {
    'open': 'open',
    'confirmed': 'open',            # doğrulanmış ama henüz düzeltilmemiş
    'retest_pending': 'retesting',
    'fixed': 'fixed',
    'resolved': 'resolved',
    'wont_fix': 'wont_fix',
    'accepted_risk': 'accepted_risk',
}
ACTIVE = ('open', 'retesting')


def summarize(quick_results, pro_findings):
    """quick_results: [{'session_id','test_id','finding','finding_status','severity'}]
    pro_findings:  [{'session_id','test_id','status','severity'}]"""
    status_counts = {k: 0 for k in LIFECYCLE_STATUSES}
    active_severity_counts = {k: 0 for k in SEVERITIES}

    def add(status, severity):
        status_counts[status] += 1
        if status in ACTIVE:
            sev = (severity or 'info').lower()
            active_severity_counts[sev if sev in active_severity_counts else 'info'] += 1

    covered = {(f.get('session_id'), f.get('test_id')) for f in pro_findings
               if f.get('session_id') and f.get('test_id')}
    for f in pro_findings:
        add(PRO_STATUS_TO_LIFECYCLE.get(f.get('status'), 'open'), f.get('severity'))

    quick_counted = 0
    for r in quick_results:
        if not (r.get('finding') or '').strip():
            continue
        if (r.get('session_id'), r.get('test_id')) in covered:
            continue
        st = r.get('finding_status')
        add(st if st in LIFECYCLE_STATUSES else 'open', r.get('severity'))
        quick_counted += 1

    total = len(pro_findings) + quick_counted
    return {
        'total_findings': total,
        'professional_findings': len(pro_findings),
        'quick_findings': quick_counted,
        'status_counts': status_counts,
        'active_severity_counts': active_severity_counts,
        'remediation_rate': round(status_counts['resolved'] / total * 100, 1) if total else 0,
    }
