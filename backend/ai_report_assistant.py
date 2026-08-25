"""
AI Report Assistant.

Rapor yazimini hizlandirmak icin dort serbest-metin uretim gorevi saglar:
description, remediation, "make more professional" rewrite ve proje bazli
executive summary. finding_analysis.py'deki (CWE/severity/CVSS onerisi,
strict JSON) tasarimdan FARKLI olarak burada model serbest metin uretir --
JSON semasi yok, ama ayni disiplin gecerli:

  - AI SADECE bir ONERI/TASLAK uretir, hicbir alani otomatik güncellemez.
    Kullanici metni gorup "Description" / "Remediation" alanina KENDISI
    yapistirir (mevcut PUT /findings/<id> ucu ile).
  - Saglayici yapilandirilmamissa (ai.base.AIConfigError) ozellik sessizce
    devre disi kalir -- ust katman (app.py) bunu 200 disi bir JSON hataya
    cevirir, sahte/uydurma icerik ASLA uretilmez.
  - Remediation, mumkunse report_builder.CATEGORY_REMEDIATION (WSTG kategori
    bazli, kamuya acik, savunma amacli best-practice) ile GROUNDLANIR --
    model bu baglami baz alir ama bulgunun spesifik detaylarina gore
    (endpoint, parametre) somutlastirir.
"""

import re

from report_builder import CATEGORY_REMEDIATION

_WRAP_QUOTES_RE = re.compile(r'^["\']|["\']$')


def _category_prefix(test_id):
    if not test_id:
        return None
    parts = test_id.split('-')
    return '-'.join(parts[:2]) if len(parts) >= 2 else test_id


def _clean_text(raw):
    text = (raw or '').strip()
    # Bazi modeller cevabi tek satirlik tirnak icine alabiliyor; kabaca temizle.
    if len(text) > 1 and text[0] in '"\'' and text[-1] == text[0]:
        text = text[1:-1].strip()
    return text


def _finding_context_lines(finding, lang):
    lines = []
    if finding.get('test_id'):
        lines.append(f"WSTG/Test ID: {finding['test_id']}")
    if finding.get('endpoint'):
        lines.append(f"Endpoint: {finding['endpoint']}")
    if finding.get('parameter'):
        lines.append(f"Parametre: {finding['parameter']}")
    if finding.get('cwe'):
        lines.append(f"CWE: {finding['cwe']}")
    if finding.get('severity'):
        lines.append(f"Önem Derecesi: {finding['severity']}")
    if finding.get('description'):
        lines.append(f"Mevcut açıklama/not: {finding['description']}")
    return "\n".join(lines) if lines else "(Ek bağlam yok.)"


def generate_description(provider, finding, lang="tr", max_tokens=500):
    """finding: bir Finding.to_dict() -- en az 'title' dolu olmali."""
    title = finding.get('title') or ''
    system_prompt = (
        "Sen deneyimli bir web uygulama penetrasyon test raporu yazarısın. Sana bir "
        "güvenlik bulgusunun başlığı ve mevcut teknik bağlamı verilecek. Görevin, bu "
        "bulgu için 2-4 cümlelik, profesyonel ve teknik olarak net bir AÇIKLAMA METNİ "
        "yazmak: zafiyetin ne olduğu, nerede/nasıl gözlemlendiği. SADECE açıklama "
        "metnini yaz — başlık, madde işareti, markdown biçimlendirmesi veya ek "
        "yorum EKLEME. Bilmediğin/verilmeyen teknik detayı UYDURMA; sadece verilen "
        "bağlamdan genellenebilir ifadeler kullan."
    )
    user_prompt = f"Bulgu başlığı: {title}\n\nBağlam:\n{_finding_context_lines(finding, lang)}\n"
    ai_result = provider.chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
    return _clean_text(ai_result.text), ai_result


def generate_remediation(provider, finding, lang="tr", max_tokens=500):
    cat_prefix = _category_prefix(finding.get('test_id'))
    grounding = CATEGORY_REMEDIATION.get(cat_prefix)

    context_lines = [_finding_context_lines(finding, lang)]
    if grounding:
        context_lines.append(
            f"Bu WSTG kategorisi için genel best-practice rehberi: {grounding['summary']} "
            f"(Referans: {grounding['cwe']})"
        )
    context_block = "\n".join(context_lines)

    system_prompt = (
        "Sen deneyimli bir web uygulama penetrasyon test uzmanısın. Sana bir güvenlik "
        "bulgusunun bağlamı ve (varsa) o kategoriye ait genel best-practice rehberi "
        "verilecek. Görevin, bu SPESİFİK bulgu için 2-4 cümlelik, uygulanabilir bir "
        "REMEDIATION (giderim) önerisi yazmak. Genel rehberi baz al ama bulgunun "
        "endpoint/parametre gibi somut detaylarına göre özelleştir. SADECE remediation "
        "metnini yaz — başlık, madde işareti veya ek açıklama EKLEME. Saldırı/exploit "
        "adımı YAZMA, sadece savunma amaçlı düzeltme rehberliği ver."
    )
    user_prompt = f"Bağlam:\n{context_block}\n"
    ai_result = provider.chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
    return _clean_text(ai_result.text), ai_result


def rewrite_professional(provider, text, lang="tr", max_tokens=600):
    if not (text or '').strip():
        raise ValueError("rewrite_professional için boş olmayan bir metin gereklidir")
    system_prompt = (
        "Sen deneyimli bir pentest raporu editörüsün. Sana bir bulgu metni verilecek. "
        "Görevin bu metni DAHA PROFESYONEL, DAHA TEKNİK ve DAHA RESMİ bir dile çevirmek: "
        "argo/gündelik ifadeleri kaldır, belirsiz cümleleri netleştir, pasif/nesnel bir "
        "rapor üslubu kullan. Anlamı ve teknik içeriği DEĞİŞTİRME, sadece dili düzenle. "
        "SADECE düzenlenmiş metni yaz — başlık, açıklama veya ek yorum EKLEME."
    )
    user_prompt = f"Metin:\n{text}\n"
    ai_result = provider.chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
    return _clean_text(ai_result.text), ai_result


def generate_project_executive_summary(provider, project, findings, lang="tr", max_tokens=800):
    """project: Project.to_dict(); findings: [Finding.to_dict(), ...] (proje genelinde)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get((f.get("severity") or "info").lower(), 5))

    severity_counts = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    top_lines = []
    for f in sorted_findings[:10]:
        cwe = f" ({f['cwe']})" if f.get("cwe") else ""
        top_lines.append(f"- [{(f.get('severity') or 'info').upper()}] {f.get('title') or '(başlıksız)'}{cwe}")
    findings_block = "\n".join(top_lines) if top_lines else "(Kayıtlı bulgu yok.)"

    system_prompt = (
        "Sen deneyimli bir pentest raporu yazarısın. Sana bir güvenlik değerlendirmesinin "
        "proje bilgisi, bulgu istatistikleri ve öne çıkan bulgu listesi verilecek. Görevin, "
        "teknik olmayan bir yöneticinin de anlayabileceği, 150-250 kelimelik bir YÖNETİCİ "
        "ÖZETİ (executive summary) yazmak: genel risk durumu, en kritik bulgular, iş etkisi "
        "ve genel tavsiye. Teknik jargondan kaçın, CVSS/CWE kodlarını tekrarlama. SADECE "
        "özet metnini yaz — başlık, madde işareti, markdown biçimlendirmesi veya ek açıklama "
        "EKLEME, düz paragraf(lar) halinde yaz."
    )
    user_prompt = (
        f"Proje: {project.get('name', '')}\n"
        f"Müşteri: {project.get('client', '') or '-'}\n"
        f"Toplam bulgu: {len(findings)}\n"
        f"Önem derecesi dağılımı: {severity_counts}\n\n"
        f"Öne çıkan bulgular:\n{findings_block}\n"
    )
    ai_result = provider.chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)
    return _clean_text(ai_result.text), ai_result
