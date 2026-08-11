"""
Deneysel A/B Karsilastirma Modulu (Faz 5).

Oturumlar olusturulurken "AI Destekli" ya da "Kontrol (Sadece Checklist)"
calisma grubuna etiketlenebiliyor (bkz. Session.study_group). Kontrol
grubundaki oturumlarda frontend AI ozelliklerini (analiz, sonraki test
onerisi, rapor taslagi) gizler/devre disi birakir -- boylece iki grup
gercekten "AI'siz" ve "AI'li" calisma kosullarini yansitir.

Bu modul, tek bir oturumdan ham metrikler cikarir ve birden fazla
oturumu grup bazinda karsilastirip ortalama farklari hesaplar. Amac,
tezin "AI destekli yaklasim, geleneksel checklist yaklasimina gore X%
daha hizliydi/daha fazla bulgu buldu" gibi olculebilir iddialar
uretebilmesini saglamaktir.

Not: Bu istatistikler ACIKLAYICI (descriptive) niteliktedir; ornek
sayisi kucukse (n<5 gibi) bunu acikca belirtmek onemlidir -- bu yuzden
her grup ozetinde 'n' alani her zaman ayri raporlanir.
"""

from collections import Counter
from datetime import datetime


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _mean(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 2) if values else None


def compute_session_metrics(session, results, notes, ai_logs):
    """
    session: Session.to_dict()
    results: [TestResult.to_dict(), ...]
    notes:   [Note.to_dict(), ...]
    ai_logs: [AIInteractionLog.to_dict(), ...] (bu oturuma ait)
    """
    started = _parse_dt(session.get("started_at"))
    completed = _parse_dt(session.get("completed_at"))
    completion_minutes = round((completed - started).total_seconds() / 60, 1) if started and completed else None

    total_tests = len(results)
    completed_tests = len([r for r in results if r.get("status") != "pending"])
    completion_pct = round((completed_tests / total_tests) * 100, 1) if total_tests else 0.0

    total_findings = len(notes)
    severity_counts = dict(Counter(n.get("severity") or "info" for n in notes))

    confirmed_fp = len([n for n in notes if n.get("is_false_positive") is True])
    confirmed_valid = len([n for n in notes if n.get("is_false_positive") is False])
    undetermined = total_findings - confirmed_fp - confirmed_valid
    determined = confirmed_fp + confirmed_valid
    fp_rate_pct = round((confirmed_fp / determined) * 100, 1) if determined else None

    ai_calls_total = len(ai_logs)
    ai_calls_by_purpose = dict(Counter(l.get("purpose") for l in ai_logs))
    ai_success_count = len([l for l in ai_logs if l.get("success")])
    ai_success_rate_pct = round((ai_success_count / ai_calls_total) * 100, 1) if ai_calls_total else None
    avg_ai_latency_ms = _mean([l.get("latency_ms") for l in ai_logs if l.get("success")])
    report_generated = any(l.get("purpose") == "report_generation" and l.get("success") for l in ai_logs)

    return {
        "session_id": session.get("id"),
        "session_name": session.get("name"),
        "study_group": session.get("study_group"),
        "completion_minutes": completion_minutes,
        "total_tests": total_tests,
        "completed_tests": completed_tests,
        "completion_pct": completion_pct,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "confirmed_false_positives": confirmed_fp,
        "confirmed_valid_findings": confirmed_valid,
        "undetermined_findings": undetermined,
        "false_positive_rate_pct": fp_rate_pct,
        "ai_calls_total": ai_calls_total,
        "ai_calls_by_purpose": ai_calls_by_purpose,
        "ai_success_rate_pct": ai_success_rate_pct,
        "avg_ai_latency_ms": avg_ai_latency_ms,
        "report_generated": report_generated,
    }


NUMERIC_FIELDS = [
    "completion_minutes", "completed_tests", "completion_pct", "total_findings",
    "false_positive_rate_pct", "ai_calls_total", "avg_ai_latency_ms",
]


def aggregate_group(metrics_list):
    n = len(metrics_list)
    agg = {"n": n}
    for field in NUMERIC_FIELDS:
        agg[f"avg_{field}"] = _mean([m.get(field) for m in metrics_list]) if n else None
    agg["pct_report_generated"] = (
        round(len([m for m in metrics_list if m.get("report_generated")]) / n * 100, 1) if n else None
    )
    return agg


def compare_groups(all_session_metrics):
    """
    all_session_metrics: her oturum icin compute_session_metrics() ciktisi.
    Sadece study_group='ai_assisted' veya 'control' olan oturumlar karsilastirmaya dahil edilir.
    """
    ai_group = [m for m in all_session_metrics if m.get("study_group") == "ai_assisted"]
    control_group = [m for m in all_session_metrics if m.get("study_group") == "control"]

    ai_agg = aggregate_group(ai_group)
    control_agg = aggregate_group(control_group)

    diff = {}
    if ai_agg["n"] and control_agg["n"]:
        for field in NUMERIC_FIELDS:
            ai_val = ai_agg.get(f"avg_{field}")
            control_val = control_agg.get(f"avg_{field}")
            if ai_val is None or control_val is None or control_val == 0:
                diff[field] = None
                continue
            # Pozitif deger: AI grubunun degeri kontrol grubundan yuksek.
            pct_change = round(((ai_val - control_val) / abs(control_val)) * 100, 1)
            diff[field] = pct_change

    return {
        "ai_assisted": ai_agg,
        "control": control_agg,
        "diff_pct": diff,  # (ai_assisted - control) / control * 100, alan bazinda
    }
