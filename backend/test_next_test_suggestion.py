import sys
sys.path.insert(0, '.')

from ai.base import BaseAIProvider, AIResult
from next_test_suggestion import suggest_next_test, NextTestSuggestionError


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


def test_grounded_suggestion():
    provider = FakeProvider('''{
      "suggested_test_id": "WSTG-SESS-01",
      "reasoning": "Kimlik dogrulamada zafiyet bulundu, oturum yonetimi de genelde iliskilidir.",
      "priority": "high",
      "alternative_test_ids": ["WSTG-SESS-02", "WSTG-ATHZ-01"]
    }''')
    findings = [{"title": "Login SQLi", "severity": "critical", "cwe_id": "CWE-89", "test_id": "WSTG-ATHN-01"}]
    suggestion, result = suggest_next_test(provider, ["WSTG-ATHN-01"], findings)
    assert suggestion["suggested_test_id"] == "WSTG-SESS-01"
    assert suggestion["suggestion_grounded"] is True
    assert suggestion["suggested_test_title"]  # havuzdan gelen gercek baslik dolduruldu
    assert suggestion["priority"] == "high"
    assert "WSTG-SESS-02" in suggestion["alternative_test_ids"]
    assert suggestion["all_done"] is False
    assert result.provider == "fake"
    print("OK: havuzdan (grounded) bir test önerisi doğru parse edildi")


def test_hallucinated_test_id_flagged():
    provider = FakeProvider('{"suggested_test_id": "WSTG-FAKE-99", "reasoning": "x", "priority": "low", "alternative_test_ids": []}')
    suggestion, _ = suggest_next_test(provider, [], [])
    assert suggestion["suggested_test_id"] == "WSTG-FAKE-99"
    assert suggestion["suggestion_grounded"] is False
    assert suggestion["suggested_test_title"] is None  # havuzda olmadigi icin baslik doldurulamaz
    print("OK: havuzda olmayan (uydurma) bir test ID'si grounded=False olarak işaretleniyor")


def test_already_completed_test_excluded_from_alternatives():
    provider = FakeProvider('{"suggested_test_id": "WSTG-INFO-02", "reasoning": "x", "priority": "medium", '
                             '"alternative_test_ids": ["WSTG-INFO-01", "WSTG-INFO-02"]}')
    # WSTG-INFO-01 zaten tamamlanmis, dolayisiyla alternative listesinden filtrelenmeli.
    suggestion, _ = suggest_next_test(provider, ["WSTG-INFO-01"], [])
    assert "WSTG-INFO-01" not in suggestion["alternative_test_ids"]
    print("OK: zaten tamamlanmış testler alternatif önerilerden filtreleniyor")


def test_all_tests_completed_short_circuits_without_calling_ai():
    provider = FakeProvider('BU HIC CAGRILMAMALI')
    from mapping import get_all_tests
    all_ids = [t["id"] for t in get_all_tests("tr")]
    suggestion, ai_result = suggest_next_test(provider, all_ids, [])
    assert suggestion["all_done"] is True
    assert ai_result is None  # AI hic cagrilmadi
    print("OK: tüm testler tamamlanmışsa AI'a hiç gidilmeden 'all_done' dönüyor")


def test_invalid_json_raises():
    provider = FakeProvider("duz metin, json degil")
    try:
        suggest_next_test(provider, [], [])
        raise AssertionError("hata beklenirken hata firlatilmadi")
    except NextTestSuggestionError:
        pass
    print("OK: geçersiz JSON yanıtı NextTestSuggestionError fırlatıyor")


def test_findings_sorted_by_severity_in_prompt():
    provider = FakeProvider('{"suggested_test_id": "WSTG-SESS-01", "reasoning": "x", "priority": "low", "alternative_test_ids": []}')
    findings = [
        {"title": "Dusuk onem", "severity": "low", "test_id": "WSTG-INFO-01"},
        {"title": "Kritik SQLi", "severity": "critical", "test_id": "WSTG-ATHN-01"},
    ]
    suggest_next_test(provider, [], findings)
    prompt = provider.last_user_prompt
    # Kritik bulgu, dusuk onemli bulgudan ONCE gelmeli (AI'a en onemli sinyal once verilir)
    assert prompt.index("Kritik SQLi") < prompt.index("Dusuk onem")
    print("OK: bulgular önem derecesine göre sıralanıp prompt'a ekleniyor (kritik en önde)")


def test_pending_pool_grouped_by_category_in_prompt():
    provider = FakeProvider('{"suggested_test_id": "WSTG-SESS-01", "reasoning": "x", "priority": "low", "alternative_test_ids": []}')
    suggest_next_test(provider, [], [])
    assert "WSTG-SESS" in provider.last_user_prompt
    assert "WSTG-ATHN-01" in provider.last_user_prompt
    print("OK: prompt, henüz yapılmamış testleri kategoriye göre gruplanmış şekilde içeriyor")


if __name__ == "__main__":
    test_grounded_suggestion()
    test_hallucinated_test_id_flagged()
    test_already_completed_test_excluded_from_alternatives()
    test_all_tests_completed_short_circuits_without_calling_ai()
    test_invalid_json_raises()
    test_findings_sorted_by_severity_in_prompt()
    test_pending_pool_grouped_by_category_in_prompt()
    print("\nTüm next_test_suggestion testleri geçti.")
