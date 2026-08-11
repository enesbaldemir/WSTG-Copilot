import sys
sys.path.insert(0, '.')

from ai.base import BaseAIProvider, AIResult
from finding_analysis import analyze_finding, FindingAnalysisError


class FakeProvider(BaseAIProvider):
    name = "fake"
    def __init__(self, canned_text):
        self.canned_text = canned_text
        self.model = "fake-model"
    def is_configured(self):
        return True
    def _call(self, system_prompt, user_prompt, max_tokens):
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return AIResult(text=self.canned_text, provider=self.name, model=self.model, latency_ms=0)


def test_clean_json_response():
    provider = FakeProvider('''{
      "suggested_cwe_id": "CWE-89",
      "suggested_cwe_name": "SQL Injection",
      "suggested_severity": "critical",
      "suggested_cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "false_positive_likelihood": "low",
      "false_positive_reasoning": "Payload ile bypass gozlemlendi, somut kanit var.",
      "rationale": "Klasik login SQLi bulgusu."
    }''')
    analysis, result = analyze_finding(provider, "Login SQLi", "' OR 1=1-- ile giris yapildi", test_id="WSTG-INPV-05")
    assert analysis["suggested_cwe_id"] == "CWE-89"
    assert analysis["suggested_severity"] == "critical"
    assert analysis["suggested_cvss_score"] == 9.8
    assert analysis["suggested_cvss_rating"] == "critical"
    assert analysis["false_positive_likelihood"] == "low"
    assert result.provider == "fake"
    print("OK: temiz JSON yanıtı doğru parse edildi ve CVSS skoru hesaplandı")


def test_markdown_fenced_json():
    provider = FakeProvider('```json\n{"suggested_cwe_id": "CWE-79", "suggested_cwe_name": "XSS", '
                             '"suggested_severity": "medium", "suggested_cvss_vector": null, '
                             '"false_positive_likelihood": "medium", "false_positive_reasoning": "test", '
                             '"rationale": "test"}\n```')
    analysis, _ = analyze_finding(provider, "XSS", "reflected xss bulundu")
    assert analysis["suggested_cwe_id"] == "CWE-79"
    assert analysis["suggested_cvss_vector"] is None
    print("OK: ```json ... ``` code-fence'li yanıt temizlenip parse edildi")


def test_preamble_before_json():
    provider = FakeProvider('Elbette, işte analiz:\n{"suggested_cwe_id": null, "suggested_severity": "low", '
                             '"false_positive_likelihood": "high", "false_positive_reasoning": "Kanit yetersiz", '
                             '"rationale": "Belirsiz bulgu"}\nUmarim yardimci olmustur.')
    analysis, _ = analyze_finding(provider, "Belirsiz", "sistem biraz yavas hissettirdi")
    assert analysis["suggested_cwe_id"] is None
    assert analysis["false_positive_likelihood"] == "high"
    print("OK: JSON öncesi/sonrası fazladan metin olsa bile { } arası doğru çıkarılıyor")


def test_invalid_json_raises():
    provider = FakeProvider("Bu hic JSON degil, sadece duz metin.")
    try:
        analyze_finding(provider, "x", "y")
        raise AssertionError("hata beklenirken hata firlatilmadi")
    except FindingAnalysisError:
        pass
    print("OK: geçersiz JSON yanıtı FindingAnalysisError fırlatıyor")


def test_invalid_fields_are_dropped_not_fatal():
    provider = FakeProvider('{"suggested_cwe_id": "not-a-cwe", "suggested_severity": "asdf", '
                             '"suggested_cvss_vector": "garbage-vector", '
                             '"false_positive_likelihood": "extreme", "rationale": "test"}')
    analysis, _ = analyze_finding(provider, "x", "y")
    assert analysis["suggested_cwe_id"] is None       # 'not-a-cwe' formatı geçersiz -> null
    assert analysis["suggested_severity"] is None      # 'asdf' gecerli severity degil -> null
    assert analysis["suggested_cvss_vector"] is None   # gecersiz vektor -> null
    assert analysis["false_positive_likelihood"] is None
    assert analysis["rationale"] == "test"             # geçerli alan korunur
    print("OK: geçersiz tekil alanlar sessizce None'a düşüyor, geçerli alanlar korunuyor (tüm istek fail olmuyor)")


def test_cwe_grounding_flag():
    # WSTG-INPV-05, WSTG->OWASP mapping'inde A05:Injection kategorisine bagli,
    # CWE-89 (SQLi) o kategorinin aday listesinde var -> grounded=True olmali.
    provider_grounded = FakeProvider('{"suggested_cwe_id": "CWE-89", "suggested_severity": "high", '
                                      '"false_positive_likelihood": "low", "rationale": "x"}')
    analysis, _ = analyze_finding(provider_grounded, "x", "y", test_id="WSTG-INPV-05")
    assert analysis["cwe_grounded"] is True, "CWE-89, Injection kategorisinin adaylarindan biri olmali"

    # Tamamen alakasiz bir CWE onerirse grounded=False olmali (aday listesinde yok)
    provider_hallucinated = FakeProvider('{"suggested_cwe_id": "CWE-1", "suggested_severity": "high", '
                                          '"false_positive_likelihood": "low", "rationale": "x"}')
    analysis2, _ = analyze_finding(provider_hallucinated, "x", "y", test_id="WSTG-INPV-05")
    assert analysis2["cwe_grounded"] is False
    print("OK: cwe_grounded bayrağı, önerinin bilinen adaylardan olup olmadığını doğru işaretliyor")


def test_prompt_includes_context():
    provider = FakeProvider('{"suggested_severity": "low", "false_positive_likelihood": "low", "rationale": "x"}')
    analyze_finding(provider, "x", "y", test_id="WSTG-ATHZ-01")
    assert "WSTG-ATHZ-01" in provider.last_user_prompt
    assert "A01" in provider.last_user_prompt or "Broken Access" in provider.last_user_prompt or "Erişim" in provider.last_user_prompt
    assert "CWE-284" in provider.last_user_prompt  # candidate CWE listesi prompt'a eklenmis olmali
    print("OK: prompt, ilişkili WSTG testi + OWASP kategorisi + aday CWE'leri bağlam olarak içeriyor")


def test_empty_content_raises():
    provider = FakeProvider('{}')
    try:
        analyze_finding(provider, "baslik", "   ")
        raise AssertionError("bos icerik icin hata beklenirdi")
    except FindingAnalysisError:
        pass
    print("OK: boş içerik erken aşamada FindingAnalysisError ile reddediliyor")


if __name__ == "__main__":
    test_clean_json_response()
    test_markdown_fenced_json()
    test_preamble_before_json()
    test_invalid_json_raises()
    test_invalid_fields_are_dropped_not_fatal()
    test_cwe_grounding_flag()
    test_prompt_includes_context()
    test_empty_content_raises()
    print("\nTüm finding_analysis testleri geçti.")
