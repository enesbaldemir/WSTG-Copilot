"""
Profesyonel Rapor Sablonlari -- Technical / Executive / Developer Remediation

Bu modul python-docx ile 3 farkli rapor tipi uretir. Hepsi ayni proje/
session/finding verisinden beslenir, sadece hedef kitleye gore
detay seviyesi ve odak degisir:

  - technical   : Tum test sonuclari + tum bulgular, tam detay (pentester/QA)
  - executive   : Ust duzey ozet, sayilar ve genel risk posturu (yonetim)
  - developer   : Sadece bulgular, "Problem / Neden onemli / Nasil duzeltilir"
                  formatinda, gelistiriciye yonelik somut aksiyon

Remediation rehberligi WSTG kategorisi bazinda GENEL, kamuya acik,
savunma amacli best-practice metinleridir (CWE referanslariyla) -- hicbir
exploit/saldiri detayi icermez.
"""

import io
import json
import os
from datetime import datetime

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WSTG_DATA_PATH = os.path.join(BASE_DIR, 'data', 'wstg-checklist.en.json')
LLM_DATA_PATH = os.path.join(BASE_DIR, 'data', 'llm-security-checklist.en.json')

SEVERITY_COLORS = {
    'critical': RGBColor(0x99, 0x18, 0x18),
    'high': RGBColor(0xC2, 0x41, 0x0C),
    'medium': RGBColor(0xA1, 0x62, 0x07),
    'low': RGBColor(0x15, 0x80, 0x3D),
    'info': RGBColor(0x47, 0x55, 0x69),
}
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

CATEGORY_REMEDIATION = {
    'WSTG-INFO': {
        'summary': 'Bilgi sizintisini en aza indirin: surum/banner bilgilerini gizleyin, dizin listelemeyi kapatin, gereksiz meta veriyi kaldirin.',
        'cwe': 'CWE-200 (Exposure of Sensitive Information)'
    },
    'WSTG-CONF': {
        'summary': 'Sunucu/uygulama yapilandirmasini sikilastirin: varsayilan/yedek dosyalari kaldirin, yonetim arayuzlerini kisitlayin, en az yetki ilkesini uygulayin.',
        'cwe': 'CWE-16 (Configuration)'
    },
    'WSTG-IDNT': {
        'summary': 'Kimlik yonetimi akislarinda (kayit, kullanici adi) numaralandirmayi zorlastirin; hiz sinirlama ve genel hata mesajlari kullanin.',
        'cwe': 'CWE-204 (Observable Response Discrepancy)'
    },
    'WSTG-ATHN': {
        'summary': 'Guclu parola politikasi, MFA, guvenli kimlik bilgisi tasima ve hesap kilitleme mekanizmalari uygulayin.',
        'cwe': 'CWE-287 (Improper Authentication)'
    },
    'WSTG-ATHZ': {
        'summary': 'Her istekte sunucu tarafi yetkilendirme kontrolu yapin; varsayilan olarak reddet, nesne sahipligini dogrulayin (IDOR onleme).',
        'cwe': 'CWE-285 (Improper Authorization)'
    },
    'WSTG-SESS': {
        'summary': 'Secure/HttpOnly/SameSite cookie bayraklari, giriste session ID yenileme, CSRF token ve uygun oturum zaman asimi uygulayin.',
        'cwe': 'CWE-384 (Session Fixation)'
    },
    'WSTG-INPV': {
        'summary': 'Parametreli sorgular (prepared statements), cikti kodlama, allowlist tabanli girdi dogrulama kullanin; WAF ek savunma katmani olarak dusunulmeli.',
        'cwe': 'CWE-20 (Improper Input Validation)'
    },
    'WSTG-ERRH': {
        'summary': 'Kullaniciya genel hata mesajlari gosterin; detayli stack trace/hata bilgisi yalnizca sunucu tarafli loglarda tutulmali.',
        'cwe': 'CWE-209 (Information Exposure Through an Error Message)'
    },
    'WSTG-CRYP': {
        'summary': 'Guncel/guclu TLS surumleri ve sifre paketleri kullanin, kriptografik anahtarlari guvenli yonetin, eski algoritmalari devre disi birakin.',
        'cwe': 'CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)'
    },
    'WSTG-BUSL': {
        'summary': 'Is mantigi kurallarini ve is akisi durum gecislerini sunucu tarafinda dogrulayin; istemciye guvenmeyin.',
        'cwe': 'CWE-840 (Business Logic Errors)'
    },
    'WSTG-CLNT': {
        'summary': 'Content-Security-Policy uygulayin, DOM ciktisini temizleyin (sanitize), postMessage kullanimini kisitlayin.',
        'cwe': 'CWE-79 (Cross-site Scripting)'
    },
    'WSTG-APIT': {
        'summary': 'Her API endpoint\'inde kimlik dogrulama/yetkilendirme zorunlu kilin, hiz sinirlama ve sema dogrulamasi uygulayin.',
        'cwe': 'CWE-285 (Improper Authorization)'
    },
    # --- OWASP Top 10 for LLM Applications 2025 (v2.0) ---
    'LLM-PI': {
        'summary': 'Guvenilmeyen icerigi (kullanici girdisi, dis belgeler, arac ciktilari) sistem talimatlarindan net sekilde ayirin; kritik eylemlerde ek dogrulama/onay katmani kullanin.',
        'cwe': 'OWASP LLM01:2025 (Prompt Injection)'
    },
    'LLM-SID': {
        'summary': 'Cikti filtreleme ve hassas veri kalip taramasi uygulayin; modelin egitim verisini/PII bilgisini geri uretmesini sinirlayan koruma katmanlari ekleyin.',
        'cwe': 'OWASP LLM02:2025 (Sensitive Information Disclosure)'
    },
    'LLM-SC': {
        'summary': 'Model/eklenti kaynaklarini dogrulanmis surumlere sabitleyin, checksum/imza dogrulamasi yapin, tedarikci guvenlik durusunu duzenli gozden gecirin.',
        'cwe': 'OWASP LLM03:2025 (Supply Chain)'
    },
    'LLM-DMP': {
        'summary': 'Egitim/fine-tuning ve RAG veri kaynaklarina erisim kontrolu ve onay adimlari ekleyin; supheli katkilar icin anomali tespiti kurun.',
        'cwe': 'OWASP LLM04:2025 (Data and Model Poisoning)'
    },
    'LLM-OH': {
        'summary': 'LLM ciktisini asla dogrudan HTML/JS/SQL/shell baglaminda calistirmayin; her zaman cikti kodlama (output encoding) ve sanitization uygulayin.',
        'cwe': 'OWASP LLM05:2025 (Improper Output Handling)'
    },
    'LLM-EA': {
        'summary': 'Ajana taninan arac/izin kapsamini en az yetki ilkesiyle sinirlayin; geri alinamaz/yuksek etkili eylemlerde insan onayi zorunlu kilin.',
        'cwe': 'OWASP LLM06:2025 (Excessive Agency)'
    },
    'LLM-SPL': {
        'summary': 'Sistem promptuna gizli anahtar/kimlik bilgisi veya hassas is mantigi gommeyin; bunlari guvenli backend mantigina tasiyin.',
        'cwe': 'OWASP LLM07:2025 (System Prompt Leakage)'
    },
    'LLM-VEW': {
        'summary': 'Vektor deposuna kaynak veriyle esdeger erisim kontrolu uygulayin; cok kiracili sistemlerde izolasyonu veri erisim katmaninda zorlayin.',
        'cwe': 'OWASP LLM08:2025 (Vector and Embedding Weaknesses)'
    },
    'LLM-MIS': {
        'summary': 'Yuksek riskli kararlarda insan onayli inceleme ve guven/belirsizlik gostergeleri ekleyin; modelin kaynak/alinti uydurmasina karsi dogrulama katmani kurun.',
        'cwe': 'OWASP LLM09:2025 (Misinformation)'
    },
    'LLM-UC': {
        'summary': 'Kullanici/IP bazinda hiz sinirlama ve token/context limitlerini sunucu tarafinda zorunlu kilin; anormal kullanim icin maliyet uyarisi kurun.',
        'cwe': 'OWASP LLM10:2025 (Unbounded Consumption)'
    },
}


def _load_test_index(path):
    """test_id -> {'title':..., 'category_code':..., 'category_name':...}"""
    index = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for cat in data.get('categories', []):
            for test in cat.get('tests', []):
                index[test['id']] = {
                    'title': test.get('title', ''),
                    'category_code': cat.get('code', ''),
                    'category_name': cat.get('name', '')
                }
    except Exception:
        pass
    return index


# WSTG (web) ve LLM Security (AI) checklist'lerinin ikisi de birlestiriliyor,
# boylece rapor uretimi hangi framework'ten geldigine bakmaksizin (WSTG-* veya
# LLM-*) her bulgu icin dogru baslik/kategori adini gosterebiliyor.
WSTG_INDEX = _load_test_index(WSTG_DATA_PATH)
WSTG_INDEX.update(_load_test_index(LLM_DATA_PATH))


def _category_prefix(test_id):
    parts = test_id.split('-')
    return '-'.join(parts[:2]) if len(parts) >= 2 else test_id


def _set_cell_shading(cell, hex_color):
    shd = OxmlElement('w:shd')
    shd.set(qn('w:fill'), hex_color)
    cell._tc.get_or_add_tcPr().append(shd)


def _add_page_number_footer(doc):
    section = doc.sections[0]
    footer = section.footer
    p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    fld_begin = OxmlElement('w:fldChar')
    fld_begin.set(qn('w:fldCharType'), 'begin')
    instr = OxmlElement('w:instrText')
    instr.set(qn('xml:space'), 'preserve')
    instr.text = 'PAGE'
    fld_end = OxmlElement('w:fldChar')
    fld_end.set(qn('w:fldCharType'), 'end')
    run._r.append(fld_begin)
    run._r.append(instr)
    run._r.append(fld_end)


def _cover_page(doc, title_text, project, subtitle=None):
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title.add_run(title_text)
    title_run.bold = True
    title_run.font.size = Pt(28)

    if subtitle:
        sub = doc.add_paragraph()
        sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        sub_run = sub.add_run(subtitle)
        sub_run.font.size = Pt(14)
        sub_run.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    doc.add_paragraph()
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta_run = meta.add_run(
        "%s\n%s\nOlusturulma: %s" % (
            project.get('name', ''),
            project.get('client', '') or '',
            datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')
        )
    )
    meta_run.font.size = Pt(12)
    doc.add_page_break()


def _add_severity_table(doc, severity_counts):
    table = doc.add_table(rows=1, cols=len(SEVERITY_ORDER))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr = table.rows[0].cells
    for i, sev in enumerate(SEVERITY_ORDER):
        hdr[i].text = sev.upper()
        for p in hdr[i].paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for r in p.runs:
                r.bold = True
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        color = SEVERITY_COLORS[sev]
        _set_cell_shading(hdr[i], '%02X%02X%02X' % (color[0], color[1], color[2]))
    row = table.add_row().cells
    for i, sev in enumerate(SEVERITY_ORDER):
        row[i].text = str(severity_counts.get(sev, 0))
        for p in row[i].paragraphs:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    return table


def _severity_counts(findings):
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get('severity') or 'info').lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _sorted_findings(findings):
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: rank.get((f.get('severity') or 'info').lower(), 99))


def _finding_title(f):
    meta = WSTG_INDEX.get(f['test_id'], {})
    return "%s - %s" % (f['test_id'], meta.get('title', '')) if meta.get('title') else f['test_id']


def build_technical_report(project, sessions, findings, all_results):
    doc = Document()
    _cover_page(doc, 'Technical Penetration Test Report', project, subtitle='Detayli Teknik Rapor')
    _add_page_number_footer(doc)

    doc.add_heading('1. Proje Bilgileri', level=1)
    info_table = doc.add_table(rows=0, cols=2)
    for label, value in [
        ('Proje', project.get('name', '')),
        ('Musteri', project.get('client', '') or '-'),
        ('Durum', project.get('status', '')),
        ('Baslangic', project.get('start_date') or '-'),
        ('Bitis', project.get('end_date') or '-'),
        ('Test Oturumu Sayisi', str(len(sessions))),
    ]:
        row = info_table.add_row().cells
        row[0].text = label
        row[0].paragraphs[0].runs[0].bold = True
        row[1].text = str(value)

    doc.add_heading('2. Yonetici Ozeti', level=1)
    sev_counts = _severity_counts(findings)
    doc.add_paragraph(
        "Bu degerlendirme kapsaminda toplam %d WSTG testi calistirilmis, %d bulgu tespit edilmistir." % (
            len(all_results), len(findings)
        )
    )
    _add_severity_table(doc, sev_counts)
    doc.add_paragraph()

    doc.add_heading('3. Test Kapsami', level=1)
    completed = len([r for r in all_results if r.get('status') != 'pending'])
    doc.add_paragraph("Toplam planlanan test: %d" % len(all_results))
    doc.add_paragraph("Tamamlanan test: %d" % completed)

    doc.add_heading('4. Detayli Bulgular', level=1)
    if not findings:
        doc.add_paragraph('Bu degerlendirmede bulgu tespit edilmemistir.')
    for f in _sorted_findings(findings):
        meta = WSTG_INDEX.get(f['test_id'], {})
        h = doc.add_heading(_finding_title(f), level=2)
        sev = (f.get('severity') or 'info').lower()
        for run in h.runs:
            run.font.color.rgb = SEVERITY_COLORS.get(sev, SEVERITY_COLORS['info'])

        meta_p = doc.add_paragraph()
        meta_p.add_run(
            "Severity: %s   |   WSTG Kategori: %s   |   Durum: %s" % (
                sev.upper(), meta.get('category_name', ''), f.get('finding_status', 'open')
            )
        ).italic = True

        doc.add_paragraph('Bulgu Detayi:').runs[0].bold = True
        doc.add_paragraph(f.get('finding', ''))

        cat_prefix = _category_prefix(f['test_id'])
        remediation = CATEGORY_REMEDIATION.get(cat_prefix)
        if remediation:
            doc.add_paragraph('Onerilen Aksiyon:').runs[0].bold = True
            doc.add_paragraph(remediation['summary'])
            ref_p = doc.add_paragraph()
            ref_p.add_run("Referans: %s" % remediation['cwe']).italic = True

    doc.add_heading('5. Tamamlanan Tum Testler', level=1)
    table = doc.add_table(rows=1, cols=3)
    table.style = 'Light Grid Accent 1'
    hdr = table.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text = 'WSTG ID', 'Durum', 'Severity'
    for r in all_results:
        row = table.add_row().cells
        row[0].text = r.get('test_id', '')
        row[1].text = r.get('status', '')
        row[2].text = r.get('severity') or '-'

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


def build_executive_report(project, sessions, findings, all_results):
    doc = Document()
    _cover_page(doc, 'Executive Summary', project, subtitle='Yonetici Ozeti')
    _add_page_number_footer(doc)

    sev_counts = _severity_counts(findings)
    completed = len([r for r in all_results if r.get('status') != 'pending'])
    progress = round((completed / len(all_results)) * 100, 1) if all_results else 0
    critical_high = sev_counts['critical'] + sev_counts['high']

    doc.add_heading('Genel Risk Posturu', level=1)
    if critical_high > 0:
        risk_text = (
            "Degerlendirme sirasinda %d adet KRITIK/YUKSEK onem dereceli bulgu tespit edilmistir. "
            "Bu bulgularin onceliklendirilerek giderilmesi onerilir." % critical_high
        )
    elif sev_counts['medium'] > 0:
        risk_text = "Kritik veya yuksek seviyede bulgu tespit edilmemistir; orta seviyeli bulgular giderilmelidir."
    else:
        risk_text = "Degerlendirme kapsaminda onemli bir guvenlik bulgusu tespit edilmemistir."
    doc.add_paragraph(risk_text)

    doc.add_paragraph()
    _add_severity_table(doc, sev_counts)
    doc.add_paragraph()

    doc.add_heading('Test Kapsami Ozeti', level=1)
    p = doc.add_paragraph()
    p.add_run("Test Tamamlanma Orani: ").bold = True
    p.add_run("%%%s" % progress)
    p2 = doc.add_paragraph()
    p2.add_run("Toplam Bulgu: ").bold = True
    p2.add_run(str(len(findings)))

    doc.add_heading('One Cikan Bulgular', level=1)
    top = [f for f in _sorted_findings(findings) if (f.get('severity') or 'info').lower() in ('critical', 'high')][:5]
    if not top:
        doc.add_paragraph('Kritik/Yuksek seviyeli bulgu bulunmamaktadir.')
    for f in top:
        bullet = doc.add_paragraph(style='List Bullet')
        bullet.add_run("%s " % _finding_title(f)).bold = True
        bullet.add_run("(%s)" % (f.get('severity') or 'info').upper())

    doc.add_heading('Sonuc', level=1)
    doc.add_paragraph(
        'Bu rapor, teknik ekiplerin kullanimina yonelik ayrintili Technical Report ile birlikte '
        'degerlendirilmelidir. Gelistirici odakli somut aksiyon adimlari icin Developer Remediation '
        'Report\'a basvurulabilir.'
    )

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


def build_developer_report(project, sessions, findings, all_results):
    doc = Document()
    _cover_page(doc, 'Developer Remediation Report', project, subtitle='Gelistirici Aksiyon Rehberi')
    _add_page_number_footer(doc)

    doc.add_paragraph(
        'Bu rapor, tespit edilen her bulgu icin "Problem", "Neden Onemli" ve "Nasil Duzeltilir" '
        'formatinda somut, uygulanabilir rehberlik saglar. Oncelik sirasi severity\'e goredir.'
    )
    doc.add_paragraph()

    if not findings:
        doc.add_paragraph('Giderilmesi gereken bir bulgu bulunmamaktadir.')

    importance_map = {
        'critical': 'Bu seviyedeki bir zafiyet, saldirganlarin sistemi tamamen ele gecirmesine veya kritik veriye erismesine yol acabilir. Acil giderilmelidir.',
        'high': 'Bu zafiyet ciddi veri sizintisi veya yetkisiz erisime yol acabilir. Yuksek oncelikle giderilmelidir.',
        'medium': 'Bu zafiyet tek basina sinirli etkiye sahip olsa da baska zafiyetlerle birlestiginde risk olusturabilir.',
        'low': 'Dogrudan risk dusuk olsa da savunma derinligi ilkesi geregi giderilmesi onerilir.',
        'info': 'Bilgilendirme amaclidir, dogrudan bir risk teskil etmeyebilir ancak gozden gecirilmelidir.',
    }

    for f in _sorted_findings(findings):
        sev = (f.get('severity') or 'info').lower()
        h = doc.add_heading(_finding_title(f), level=2)
        for run in h.runs:
            run.font.color.rgb = SEVERITY_COLORS.get(sev, SEVERITY_COLORS['info'])

        badge_p = doc.add_paragraph()
        badge_p.add_run("Severity: %s" % sev.upper()).bold = True
        badge_p.add_run("   |   Konum/Test: %s   |   Durum: %s" % (f['test_id'], f.get('finding_status', 'open')))

        doc.add_paragraph('Problem:').runs[0].bold = True
        doc.add_paragraph(f.get('finding', ''))

        doc.add_paragraph('Neden Onemli:').runs[0].bold = True
        doc.add_paragraph(importance_map.get(sev, ''))

        doc.add_paragraph('Nasil Duzeltilir:').runs[0].bold = True
        cat_prefix = _category_prefix(f['test_id'])
        remediation = CATEGORY_REMEDIATION.get(cat_prefix)
        if remediation:
            doc.add_paragraph(remediation['summary'])
            ref_p = doc.add_paragraph()
            ref_p.add_run("Referans: %s  |  %s" % (remediation['cwe'], f['test_id'])).italic = True
        else:
            doc.add_paragraph('Ilgili WSTG kategorisinin best-practice rehberine basvurun.')

        doc.add_paragraph()

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


REPORT_BUILDERS = {
    'technical': build_technical_report,
    'executive': build_executive_report,
    'developer': build_developer_report,
}
