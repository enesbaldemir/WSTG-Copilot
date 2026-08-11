import sys
sys.path.insert(0, '.')
import study_metrics as sm


def make_session(sid, group, started, completed):
    return {"id": sid, "name": f"Session {sid}", "study_group": group,
            "started_at": started, "completed_at": completed}


def test_completion_minutes_computed_correctly():
    session = make_session("s1", "ai_assisted", "2026-01-01T10:00:00", "2026-01-01T10:30:00")
    metrics = sm.compute_session_metrics(session, [], [], [])
    assert metrics["completion_minutes"] == 30.0
    print("OK: başlangıç/bitiş zamanından tamamlanma süresi (dakika) doğru hesaplanıyor")


def test_completion_minutes_none_when_not_completed():
    session = make_session("s1", "ai_assisted", "2026-01-01T10:00:00", None)
    metrics = sm.compute_session_metrics(session, [], [], [])
    assert metrics["completion_minutes"] is None
    print("OK: oturum henüz tamamlanmadıysa completion_minutes None dönüyor (yanlış varsayım yok)")


def test_false_positive_rate_only_over_determined_findings():
    session = make_session("s1", "ai_assisted", None, None)
    notes = [
        {"severity": "high", "is_false_positive": True},
        {"severity": "high", "is_false_positive": True},
        {"severity": "medium", "is_false_positive": False},
        {"severity": "low", "is_false_positive": None},  # henuz degerlendirilmedi
    ]
    metrics = sm.compute_session_metrics(session, [], notes, [])
    assert metrics["total_findings"] == 4
    assert metrics["confirmed_false_positives"] == 2
    assert metrics["confirmed_valid_findings"] == 1
    assert metrics["undetermined_findings"] == 1
    # FP orani: 2 / (2+1) = %66.7 -- henuz degerlendirilmemis olan paydaya girmemeli
    assert metrics["false_positive_rate_pct"] == 66.7
    print("OK: false-positive oranı sadece 'karara bağlanmış' bulgular üzerinden hesaplanıyor")


def test_false_positive_rate_none_when_nothing_determined():
    session = make_session("s1", "control", None, None)
    notes = [{"severity": "high", "is_false_positive": None}]
    metrics = sm.compute_session_metrics(session, [], notes, [])
    assert metrics["false_positive_rate_pct"] is None
    print("OK: hiçbir bulgu karara bağlanmamışsa fp_rate None (sıfır değil) dönüyor")


def test_ai_call_aggregation():
    session = make_session("s1", "ai_assisted", None, None)
    ai_logs = [
        {"purpose": "finding_analysis", "success": True, "latency_ms": 1000},
        {"purpose": "finding_analysis", "success": True, "latency_ms": 2000},
        {"purpose": "next_test_suggestion", "success": False, "latency_ms": 500},
        {"purpose": "report_generation", "success": True, "latency_ms": 3000},
    ]
    metrics = sm.compute_session_metrics(session, [], [], ai_logs)
    assert metrics["ai_calls_total"] == 4
    assert metrics["ai_calls_by_purpose"]["finding_analysis"] == 2
    assert metrics["ai_success_rate_pct"] == 75.0
    # avg latency sadece basarili cagrilar uzerinden: (1000+2000+3000)/3 = 2000
    assert metrics["avg_ai_latency_ms"] == 2000.0
    assert metrics["report_generated"] is True
    print("OK: AI çağrı istatistikleri (sayı, amaç dağılımı, başarı oranı, gecikme, rapor üretimi) doğru")


def test_control_group_typically_has_no_ai_calls():
    session = make_session("s1", "control", None, None)
    metrics = sm.compute_session_metrics(session, [], [], [])
    assert metrics["ai_calls_total"] == 0
    assert metrics["ai_success_rate_pct"] is None
    assert metrics["report_generated"] is False
    print("OK: kontrol grubu oturumu için AI metrikleri boş/None olarak temsil ediliyor")


def test_group_comparison_basic():
    ai_metrics = [
        sm.compute_session_metrics(make_session("a1", "ai_assisted", "2026-01-01T10:00:00", "2026-01-01T10:20:00"),
                                    [], [{"severity": "high", "is_false_positive": False}] * 5, []),
        sm.compute_session_metrics(make_session("a2", "ai_assisted", "2026-01-01T10:00:00", "2026-01-01T10:30:00"),
                                    [], [{"severity": "high", "is_false_positive": False}] * 7, []),
    ]
    control_metrics = [
        sm.compute_session_metrics(make_session("c1", "control", "2026-01-01T10:00:00", "2026-01-01T11:00:00"),
                                    [], [{"severity": "high", "is_false_positive": False}] * 3, []),
        sm.compute_session_metrics(make_session("c2", "control", "2026-01-01T10:00:00", "2026-01-01T11:20:00"),
                                    [], [{"severity": "high", "is_false_positive": False}] * 4, []),
    ]
    comparison = sm.compare_groups(ai_metrics + control_metrics)

    assert comparison["ai_assisted"]["n"] == 2
    assert comparison["control"]["n"] == 2
    assert comparison["ai_assisted"]["avg_completion_minutes"] == 25.0  # (20+30)/2
    assert comparison["control"]["avg_completion_minutes"] == 70.0      # (60+80)/2
    assert comparison["ai_assisted"]["avg_total_findings"] == 6.0        # (5+7)/2
    assert comparison["control"]["avg_total_findings"] == 3.5            # (3+4)/2

    # AI grubu %64.3 daha az surede tamamlamis: (25-70)/70*100 = -64.28...
    assert comparison["diff_pct"]["completion_minutes"] == -64.3
    # AI grubu %71.4 daha fazla bulgu bulmus: (6-3.5)/3.5*100 = 71.43
    assert comparison["diff_pct"]["total_findings"] == 71.4
    print("OK: iki grup arası ortalama ve yüzdesel fark hesaplaması doğru")


def test_group_comparison_empty_groups_no_crash():
    comparison = sm.compare_groups([])
    assert comparison["ai_assisted"]["n"] == 0
    assert comparison["control"]["n"] == 0
    assert comparison["diff_pct"] == {}
    print("OK: hiç oturum yokken karşılaştırma çökmeden boş/None sonuç döner")


def test_group_comparison_only_one_group_present():
    ai_metrics = [sm.compute_session_metrics(make_session("a1", "ai_assisted", None, None), [], [], [])]
    comparison = sm.compare_groups(ai_metrics)
    assert comparison["ai_assisted"]["n"] == 1
    assert comparison["control"]["n"] == 0
    assert comparison["diff_pct"] == {}  # karsilastirma icin her iki grupta da veri olmali
    print("OK: sadece tek grup varsa diff_pct hesaplanmıyor (yanlış/anlamsız karşılaştırma önleniyor)")


def test_sessions_without_study_group_excluded():
    metrics = [
        sm.compute_session_metrics(make_session("x1", None, None, None), [], [], []),
        sm.compute_session_metrics(make_session("x2", "", None, None), [], [], []),
    ]
    comparison = sm.compare_groups(metrics)
    assert comparison["ai_assisted"]["n"] == 0
    assert comparison["control"]["n"] == 0
    print("OK: çalışma grubuna atanmamış oturumlar karşılaştırmanın dışında tutuluyor")


if __name__ == "__main__":
    test_completion_minutes_computed_correctly()
    test_completion_minutes_none_when_not_completed()
    test_false_positive_rate_only_over_determined_findings()
    test_false_positive_rate_none_when_nothing_determined()
    test_ai_call_aggregation()
    test_control_group_typically_has_no_ai_calls()
    test_group_comparison_basic()
    test_group_comparison_empty_groups_no_crash()
    test_group_comparison_only_one_group_present()
    test_sessions_without_study_group_excluded()
    print("\nTüm study_metrics testleri geçti.")
