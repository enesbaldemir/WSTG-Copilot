"""
AI Bulgu Analizi (Faz 2).

Bir pentest notunu/bulgusunu (baslik + icerik + varsa bagli WSTG testi)
LLM'e gonderip, katiligi disaridan garanti edilen (strict JSON) bir
sekilde su onerileri istiyoruz:

  - suggested_cwe_id / suggested_cwe_name : en olasi CWE siniflandirmasi
  - suggested_severity                    : info|low|medium|high|critical
  - suggested_cvss_vector                 : CVSS 3.1 vektoru (varsa)
  - false_positive_likelihood             : low|medium|high
  - false_positive_reasoning              : kisa gerekce
  - rationale                             : genel degerlendirme

Onemli tasarim karari: AI'nin onerisi notu OTOMATIK OLARAK GUNCELLEMEZ.
Sadece bir "oneri" doner; pentester bunu gorup manuel olarak uygular
(mevcut PUT /notes/<id> ucu ile). Bu "insan hep karar vericidir" ilkesi
hem sorumlu AI kullanimi hem de bitirme tezindeki "AI ne kadar guveniyor"
tartismasi icin onemli.

Ayrica: modelin urettigi CWE, WSTG<->OWASP mapping'inden gelen aday
listesiyle karsilastirilip 'grounded' (bilinen adaylardan biri mi,
yoksa modelin kendi bildigi/uydurdugu bir CWE mi) olarak isaretlenir.
Bu, Faz 5'teki "AI ne kadar guvenilir/tutarli" degerlendirmesi icin
olculebilir bir sinyal saglar.
"""

import json
import re

import cvss as cvss_lib
import mapping as mapping_lib

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_FP_LEVELS = {"low", "medium", "high"}

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


class FindingAnalysisError(Exception):
    pass


def _build_prompt(title, content, test_id, lang):
    test_info = mapping_lib.get_test_info(test_id, lang) if test_id else None
    owasp_matches = mapping_lib.get_mapping_for_test(test_id, lang) if test_id else []
    candidate_cwes = mapping_lib.suggest_cwes_for_test(test_id, lang) if test_id else []

    context_lines = []
    if test_info:
        context_lines.append(
            f"İlişkili WSTG testi: {test_info['id']} - {test_info['title']} "
            f"({test_info['category_name']})"
        )
        if test_info.get("description"):
            context_lines.append(f"Test açıklaması: {test_info['description']}")
    if owasp_matches:
        owasp_titles = ", ".join(f"{m['owasp_id']} {m['owasp_title']}" for m in owasp_matches)
        context_lines.append(f"İlişkili OWASP Top 10 kategorisi: {owasp_titles}")
    if candidate_cwes:
        cwe_list = ", ".join(f"{c['id']} ({c['name']})" for c in candidate_cwes if c['id'])
        context_lines.append(
            f"Bu test kategorisiyle sıkça ilişkilendirilen CWE'ler (mümkünse bunlardan "
            f"birini seç, ama bulgunun içeriği başka bir CWE'ye daha çok uyuyorsa onu öner): {cwe_list}"
        )

    context_block = "\n".join(context_lines) if context_lines else "(Bu not belirli bir WSTG test maddesine bağlı değil, genel bir bulgu.)"

    system_prompt = (
        "Sen deneyimli bir web uygulama penetrasyon test uzmanısın. Sana bir pentester'ın "
        "sahada yazdığı ham bir bulgu notu verilecek. Görevin bu notu analiz edip SADECE "
        "aşağıdaki alanları içeren GEÇERLİ BİR JSON NESNESİ döndürmek. Başka hiçbir açıklama, "
        "markdown kod bloğu işareti veya ek metin YAZMA — cevabın SADECE JSON olmalı.\n\n"
        "JSON şeması:\n"
        "{\n"
        '  "suggested_cwe_id": "CWE-XX" | null,\n'
        '  "suggested_cwe_name": "kısa CWE adı" | null,\n'
        '  "suggested_severity": "info" | "low" | "medium" | "high" | "critical",\n'
        '  "suggested_cvss_vector": "AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:..." | null,\n'
        '  "false_positive_likelihood": "low" | "medium" | "high",\n'
        '  "false_positive_reasoning": "false-positive olma ihtimaline dair 1-2 cümlelik gerekçe",\n'
        '  "rationale": "bulgunun genel değerlendirmesi, 2-3 cümle"\n'
        "}\n\n"
        "Notta somut bir kanıt/adım yoksa veya bulgu belirsizse false_positive_likelihood'u "
        "yüksek işaretle ve nedenini açıkla. Emin olamadığın alanları null bırak, tahmin uydurma."
    )

    user_prompt = (
        f"Bağlam:\n{context_block}\n\n"
        f"Bulgu başlığı: {title or '(başlıksız)'}\n"
        f"Bulgu notu:\n{content}\n"
    )

    return system_prompt, user_prompt, candidate_cwes


def _extract_json(raw_text):
    cleaned = _JSON_FENCE_RE.sub("", raw_text.strip()).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Bazı modeller JSON'un önüne/sonuna kısa bir cümle ekleyebiliyor;
    # metindeki ilk '{' ile son '}' arasını yakalayıp tekrar dene.
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            pass
    raise FindingAnalysisError(f"AI yanıtı geçerli JSON değil: {raw_text[:300]}")


def _validate_and_normalize(parsed, candidate_cwe_ids):
    result = {
        "suggested_cwe_id": None,
        "suggested_cwe_name": None,
        "suggested_severity": None,
        "suggested_cvss_vector": None,
        "suggested_cvss_score": None,
        "suggested_cvss_rating": None,
        "false_positive_likelihood": None,
        "false_positive_reasoning": None,
        "rationale": None,
        "cwe_grounded": None,
    }

    cwe_id = parsed.get("suggested_cwe_id")
    if isinstance(cwe_id, str) and re.match(r"^CWE-\d+$", cwe_id.strip(), re.IGNORECASE):
        result["suggested_cwe_id"] = cwe_id.strip().upper()
        result["suggested_cwe_name"] = str(parsed.get("suggested_cwe_name") or "").strip() or None
        result["cwe_grounded"] = result["suggested_cwe_id"] in candidate_cwe_ids

    severity = parsed.get("suggested_severity")
    if isinstance(severity, str) and severity.strip().lower() in VALID_SEVERITIES:
        result["suggested_severity"] = severity.strip().lower()

    vector = parsed.get("suggested_cvss_vector")
    if isinstance(vector, str) and vector.strip():
        try:
            calc = cvss_lib.calculate(vector.strip())
            result["suggested_cvss_vector"] = calc["vector"]
            result["suggested_cvss_score"] = calc["score"]
            result["suggested_cvss_rating"] = calc["rating"]
        except cvss_lib.CVSSError:
            pass  # gecersiz vektor sessizce atlanir, diger alanlar korunur

    fp = parsed.get("false_positive_likelihood")
    if isinstance(fp, str) and fp.strip().lower() in VALID_FP_LEVELS:
        result["false_positive_likelihood"] = fp.strip().lower()
    result["false_positive_reasoning"] = str(parsed.get("false_positive_reasoning") or "").strip() or None
    result["rationale"] = str(parsed.get("rationale") or "").strip() or None

    return result


def analyze_finding(provider, title, content, test_id=None, lang="tr", max_tokens=1200):
    """
    provider: ai.base.BaseAIProvider örneği (get_ai_provider() ile alınır).
    Döner: (analysis_dict, ai_result) — ai_result loglama için latency/provider/model taşır.
    """
    if not (content or "").strip():
        raise FindingAnalysisError("Analiz için bulgu içeriği (content) gereklidir")

    system_prompt, user_prompt, candidate_cwes = _build_prompt(title, content, test_id, lang)
    candidate_cwe_ids = {c["id"] for c in candidate_cwes if c.get("id")}

    ai_result = provider.chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
    parsed = _extract_json(ai_result.text)
    if not isinstance(parsed, dict):
        raise FindingAnalysisError("AI yanıtı beklenen JSON nesnesi formatında değil")

    analysis = _validate_and_normalize(parsed, candidate_cwe_ids)
    return analysis, ai_result
