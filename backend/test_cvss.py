"""
CVSS v3.1 hesaplayıcı (cvss.compute) testleri.

Not: Bu dosya eskiden cvss modülünde artık bulunmayan `calculate`/`parse_vector`
fonksiyonlarını import ettiği için hiç çalışmıyordu (toplama hatası). Referans
skorlar korunarak gerçek API'ye (compute + CvssError) ve /api/cvss/calculate
rotasına göre yeniden yazıldı.
"""
import sys, os
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import pytest
import cvss
from cvss import compute, CvssError, severity_label


def metrics(vector):
    """'CVSS:3.1/AV:N/...' -> {'AV': 'N', ...} (yalnızca test yardımcısı)."""
    parts = [p for p in vector.split('/') if ':' in p and not p.upper().startswith('CVSS:')]
    return {k.upper(): v.upper() for k, v in (p.split(':', 1) for p in parts)}


# Yayınlanmış / NVD hesaplayıcısıyla doğrulanabilir taban skorlar.
REFERENCE_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),   # kimlik doğrulamasız RCE
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),  # scope changed, tavana yuvarlanır
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),     # tipik reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0, "info"),       # etkisiz -> uygulamada 'info'
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),       # bilgi ifşası
]


@pytest.mark.parametrize("vector,score,severity", REFERENCE_VECTORS)
def test_reference_vectors(vector, score, severity):
    r = compute(metrics(vector))
    assert r['base_score'] == score
    assert r['severity'] == severity
    assert r['vector'] == vector


def test_pr_weight_depends_on_scope():
    unchanged = compute(metrics("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"))
    changed = compute(metrics("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"))
    assert unchanged['base_score'] == 8.8
    assert changed['base_score'] == 9.9


@pytest.mark.parametrize("bad", [
    {},                                                                    # hiç metrik yok
    metrics("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),                         # geçersiz AV
    metrics("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),                             # A eksik
])
def test_invalid_metrics_raise(bad):
    with pytest.raises(CvssError):
        compute(bad)


def test_parse_vector():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss.parse_vector(v) == metrics(v)
    assert cvss.parse_vector("av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h") == metrics(v)
    assert compute(cvss.parse_vector(v))['base_score'] == 9.8


@pytest.mark.parametrize("bad", [
    "", "   ", None, "CVSS:4.0/AV:N", "AV:N/AV:L", "AV:N/XX:Y", "AV=N", "AV:N:L",
])
def test_parse_vector_rejects(bad):
    with pytest.raises(CvssError):
        cvss.parse_vector(bad)


def test_roundup_follows_spec():
    # CVSS v3.1 spesifikasyonu Ek A: Roundup(4.02) = 4.1, Roundup(4.00) = 4.0.
    # Fonksiyon kayan nokta hatalarına karşı 5. ondalıkta yuvarlar; bu yüzden
    # 4.000001 gibi değerler bilinçli olarak 4.0 kalır.
    assert cvss._roundup(4.02) == 4.1
    assert cvss._roundup(4.00) == 4.0
    assert cvss._roundup(4.000001) == 4.0


def test_severity_boundaries():
    assert [severity_label(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == \
        ['info', 'low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']


def test_calculate_route():
    import app as app_module
    app_module.app.config['TESTING'] = True
    c = app_module.app.test_client()
    ok = c.post('/api/cvss/calculate', json=metrics("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
    assert ok.status_code == 200 and ok.get_json()['base_score'] == 9.8
    bad = c.post('/api/cvss/calculate', json={'AV': 'X'})
    assert bad.status_code == 400
