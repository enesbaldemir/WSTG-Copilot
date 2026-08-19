"""
CVSS v3.1 Temel (Base) Skor Hesaplayıcı (Faz 1).

Resmi FIRST.org CVSS v3.1 spesifikasyonundaki formüllere birebir uyar:
https://www.first.org/cvss/v3-1/specification-document

Bu modül sadece matematiksel bir yardımcıdır, herhangi bir saldırı/istismar
kodu içermez — pentest bulgularının risk seviyesini standardize bir
şekilde puanlamak için kullanılır (tıpkı ticari pentest araçlarındaki
CVSS hesaplayıcılar gibi).
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_SCOPE = {"U", "C"}

REQUIRED_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


class CVSSError(ValueError):
    pass


def _roundup(value: float) -> float:
    """CVSS spesifikasyonundaki resmi Roundup fonksiyonu (kayan nokta
    hatalarından kaçınmak için tamsayı aritmetiği kullanır)."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10


def parse_vector(vector: str) -> dict:
    """
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' formatındaki bir
    vektör string'ini {'AV':'N', 'AC':'L', ...} sözlüğüne çevirir.
    """
    if not vector or not isinstance(vector, str):
        raise CVSSError("CVSS vektörü boş olamaz")

    vector = vector.strip()
    parts = vector.split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]

    metrics = {}
    for part in parts:
        if not part:
            continue
        if ":" not in part:
            raise CVSSError(f"Geçersiz vektör parçası: '{part}'")
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()

    missing = [m for m in REQUIRED_METRICS if m not in metrics]
    if missing:
        raise CVSSError(f"Vektörde eksik metrik(ler): {', '.join(missing)}")

    if metrics["AV"] not in _AV:
        raise CVSSError(f"Geçersiz AV değeri: {metrics['AV']}")
    if metrics["AC"] not in _AC:
        raise CVSSError(f"Geçersiz AC değeri: {metrics['AC']}")
    if metrics["S"] not in _SCOPE:
        raise CVSSError(f"Geçersiz S (Scope) değeri: {metrics['S']}")
    pr_table = _PR_CHANGED if metrics["S"] == "C" else _PR_UNCHANGED
    if metrics["PR"] not in pr_table:
        raise CVSSError(f"Geçersiz PR değeri: {metrics['PR']}")
    if metrics["UI"] not in _UI:
        raise CVSSError(f"Geçersiz UI değeri: {metrics['UI']}")
    for m in ("C", "I", "A"):
        if metrics[m] not in _CIA:
            raise CVSSError(f"Geçersiz {m} değeri: {metrics[m]}")

    return metrics


def rating_for_score(score: float) -> str:
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def calculate(vector: str) -> dict:
    """
    Vektör string'inden CVSS 3.1 taban (base) skorunu hesaplar.
    Döner: {'vector': normalized, 'score': float, 'rating': str, 'metrics': {...}}
    """
    m = parse_vector(vector)

    av, ac = _AV[m["AV"]], _AC[m["AC"]]
    pr_table = _PR_CHANGED if m["S"] == "C" else _PR_UNCHANGED
    pr, ui = pr_table[m["PR"]], _UI[m["UI"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif m["S"] == "U":
        base_score = _roundup(min(impact + exploitability, 10))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))

    normalized_vector = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in REQUIRED_METRICS)

    return {
        "vector": normalized_vector,
        "score": round(base_score, 1),
        "rating": rating_for_score(base_score),
        "metrics": m,
    }
