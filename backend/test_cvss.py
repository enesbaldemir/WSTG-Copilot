import sys
sys.path.insert(0, '.')
from cvss import calculate, parse_vector, CVSSError

# Bilinen / yaygın yayınlanmış CVSS 3.1 taban skorlarıyla karşılaştırma.
REFERENCE_VECTORS = [
    # Tipik kritik RCE (kimlik doğrulama gerektirmeyen, tam etki) -> 9.8 Critical
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    # Scope Changed + tam etki -> 10.0 (üst sınıra yuvarlanır)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    # Tipik reflected XSS (kullanıcı etkileşimi gerekli, kısmi etki, scope changed) -> 6.1 Medium
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    # Etkisi olmayan bir zafiyet -> 0.0 None
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
    # Yerelden, yüksek karmaşıklıkla, sadece bilgi ifşası -> düşük/orta bant
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
]


def test_reference_vectors():
    for vector, expected_score, expected_rating in REFERENCE_VECTORS:
        result = calculate(vector)
        assert result["score"] == expected_score, (
            f"{vector} -> beklenen {expected_score}, gelen {result['score']}"
        )
        assert result["rating"] == expected_rating, (
            f"{vector} -> beklenen rating {expected_rating}, gelen {result['rating']}"
        )
        print(f"OK: {vector} => {result['score']} ({result['rating']})")


def test_case_insensitivity_and_prefix():
    r1 = calculate("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
    r2 = calculate("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # CVSS: prefix'i olmadan
    assert r1["score"] == r2["score"] == 9.8
    print("OK: case-insensitive ve prefix'siz vektörler doğru parse ediliyor")


def test_invalid_vectors_raise():
    bad_vectors = [
        "",
        "AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # gecersiz AV
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",        # eksik metrik (A yok)
        "not-a-vector-at-all",
    ]
    for v in bad_vectors:
        try:
            calculate(v)
            raise AssertionError(f"'{v}' icin hata beklenirken hata firlatilmadi")
        except CVSSError:
            pass
    print("OK: hatalı vektörler CVSSError fırlatıyor")


def test_pr_scope_dependency():
    # Scope Changed olduğunda PR:L farklı ağırlığa sahip (0.68 vs 0.62) -> skor farklı olmalı
    unchanged = calculate("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    changed = calculate("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert unchanged["score"] != changed["score"]
    print(f"OK: PR ağırlığı Scope'a göre değişiyor (U={unchanged['score']}, C={changed['score']})")


if __name__ == "__main__":
    test_reference_vectors()
    test_case_insensitivity_and_prefix()
    test_invalid_vectors_raise()
    test_pr_scope_dependency()
    print("\nTüm CVSS testleri geçti.")
