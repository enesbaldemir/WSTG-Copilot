"""
AI Sonraki Test Onerisi (Faz 3).

Pentester'in su ana kadar TAMAMLADIGI testleri ve (varsa) bulgularini
LLM'e baglam olarak verip, HENUZ YAPILMAMIS testler havuzundan hangisinin
sirada yapilmasinin en mantikli olacagini soruyoruz. Amac, WSTG checklist'ini
korkorlere sirayla degil, mevcut bulgulara gore ONCELIKLENDIRILMIS bir
sekilde takip edebilmek (orn. "kimlik dogrulamada zafiyet bulundu, simdi
oturum yonetimini test et, cunku genelde iliskilidir").

Faz 2'deki 'grounded' fikrinin ayni: onerilen test ID'si gercekten
'henuz yapilmamis' havuzunda mi diye dogrulaniyor (suggestion_grounded).
Model havuzda olmayan bir ID uydurursa, bu acikca isaretleniyor ve
frontend kullaniciyi uyariyor.
"""

import json
import re

import mapping as mapping_lib

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

VALID_PRIORITIES = {"low", "medium", "high"}

# Prompt'un asiri uzamamasi icin, cok erken asamalarda (henuz hicbir sey
# tamamlanmamisken) havuzdaki test sayisi fazla olabilir; yine de WSTG
# checklist'i toplam ~100 madde oldugu icin bu makul bir token butcesinde
# kalir. Yine de asiri uc durumlar icin bir ust sinir koyuyoruz.
MAX_PENDING_IN_PROMPT = 120
MAX_FINDINGS_IN_PROMPT = 15


class NextTestSuggestionError(Exception):
    pass


def _format_pending_tests(pending_tests):
    lines = []
    by_category = {}
    for t in pending_tests[:MAX_PENDING_IN_PROMPT]:
        by_category.setdefault((t["category_code"], t["category_name"]), []).append(t)
    for (code, name), tests in by_category.items():
        lines.append(f"[{code} - {name}]")
        for t in tests:
            lines.append(f"  {t['id']}: {t['title']}")
    return "\n".join(lines)


def _format_findings(findings):
    if not findings:
        return "(Henüz kaydedilmiş bir bulgu yok.)"
    # En yüksek severity'li bulgular en önde olsun (AI'a en önemli sinyali erken ver).
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get((f.get("severity") or "info").lower(), 5))
    lines = []
    for f in sorted_findings[:MAX_FINDINGS_IN_PROMPT]:
        parts = [f.get("severity", "info").upper()]
        if f.get("test_id"):
            parts.append(f.get("test_id"))
        if f.get("cwe_id"):
            parts.append(f.get("cwe_id"))
        title = f.get("title") or "(başlıksız)"
        lines.append(f"- [{' / '.join(parts)}] {title}")
    return "\n".join(lines)


def _build_prompt(completed_test_ids, findings, pending_tests, lang):
    completed_summary = ", ".join(completed_test_ids) if completed_test_ids else "(henüz hiçbiri)"
    pending_block = _format_pending_tests(pending_tests)
    findings_block = _format_findings(findings)

    system_prompt = (
        "Sen deneyimli bir web uygulama penetrasyon test metodolojisi uzmanısın. "
        "Sana bir pentester'ın TAMAMLADIĞI testler, şu ana kadarki BULGULARI ve "
        "HENÜZ YAPILMAMIŞ testlerin listesi verilecek. Görevin, mevcut bulgular ve "
        "tamamlanan testler ışığında, sırada hangi testin yapılmasının en değerli "
        "olacağını önermek — checklist'i mekanik sırayla değil, risk ve bağlama göre "
        "önceliklendirerek. SADECE 'henüz yapılmamış' listesindeki bir test ID'si seç, "
        "listede olmayan bir ID uydurma.\n\n"
        "SADECE aşağıdaki şemaya uyan bir JSON nesnesi döndür, başka hiçbir metin/markdown yazma:\n"
        "{\n"
        '  "suggested_test_id": "WSTG-XXXX-NN",\n'
        '  "reasoning": "bu testin neden şimdi önerildiği, hangi bulgu/tamamlanan testle ilişkili olduğu (2-4 cümle)",\n'
        '  "priority": "low" | "medium" | "high",\n'
        '  "alternative_test_ids": ["WSTG-...", "WSTG-..."]\n'
        "}\n\n"
        "'alternative_test_ids' alanına, ana öneri kadar olmasa da mantıklı olan 1-3 test daha ekle "
        "(yine sadece 'henüz yapılmamış' listesinden)."
    )

    user_prompt = (
        f"Tamamlanan testler: {completed_summary}\n\n"
        f"Bulgular:\n{findings_block}\n\n"
        f"Henüz yapılmamış testler:\n{pending_block}\n"
    )

    return system_prompt, user_prompt


def _extract_json(raw_text):
    cleaned = _JSON_FENCE_RE.sub("", raw_text.strip()).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            pass
    raise NextTestSuggestionError(f"AI yanıtı geçerli JSON değil: {raw_text[:300]}")


def _validate_and_normalize(parsed, pending_ids_by_id):
    result = {
        "suggested_test_id": None,
        "suggested_test_title": None,
        "suggestion_grounded": None,
        "reasoning": None,
        "priority": None,
        "alternative_test_ids": [],
    }

    suggested_id = parsed.get("suggested_test_id")
    if isinstance(suggested_id, str) and suggested_id.strip():
        suggested_id = suggested_id.strip().upper()
        result["suggested_test_id"] = suggested_id
        grounded = suggested_id in pending_ids_by_id
        result["suggestion_grounded"] = grounded
        if grounded:
            result["suggested_test_title"] = pending_ids_by_id[suggested_id]["title"]

    priority = parsed.get("priority")
    if isinstance(priority, str) and priority.strip().lower() in VALID_PRIORITIES:
        result["priority"] = priority.strip().lower()

    result["reasoning"] = str(parsed.get("reasoning") or "").strip() or None

    alts = parsed.get("alternative_test_ids")
    if isinstance(alts, list):
        cleaned_alts = []
        for a in alts:
            if isinstance(a, str) and a.strip().upper() in pending_ids_by_id:
                cleaned_alts.append(a.strip().upper())
        result["alternative_test_ids"] = cleaned_alts[:5]

    return result


def suggest_next_test(provider, completed_test_ids, findings, lang="tr", max_tokens=1000):
    """
    provider: ai.base.BaseAIProvider örneği.
    completed_test_ids: tamamlanmış WSTG test ID'lerinin listesi.
    findings: [{'title':, 'severity':, 'cwe_id':, 'test_id':}, ...] (opsiyonel alanlar boş bırakılabilir)

    Döner: (suggestion_dict, ai_result) ya da tüm testler tamamlandıysa
    (all_done_dict, None).
    """
    all_tests = mapping_lib.get_all_tests(lang)
    completed_set = {tid.strip().upper() for tid in (completed_test_ids or [])}
    pending_tests = [t for t in all_tests if t["id"] not in completed_set]

    if not pending_tests:
        return {
            "all_done": True,
            "suggested_test_id": None,
            "suggested_test_title": None,
            "suggestion_grounded": None,
            "reasoning": None,
            "priority": None,
            "alternative_test_ids": [],
        }, None

    pending_ids_by_id = {t["id"]: t for t in pending_tests}
    system_prompt, user_prompt = _build_prompt(sorted(completed_set), findings or [], pending_tests, lang)

    ai_result = provider.chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
    parsed = _extract_json(ai_result.text)
    if not isinstance(parsed, dict):
        raise NextTestSuggestionError("AI yanıtı beklenen JSON nesnesi formatında değil")

    suggestion = _validate_and_normalize(parsed, pending_ids_by_id)
    suggestion["all_done"] = False
    return suggestion, ai_result
