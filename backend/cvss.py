"""
CVSS v3.1 Calculator -- resmi FIRST.org / NVD formulune dayanir.

DURUSTLUK NOTU: CVSS v4.0 kasitli olarak UYGULANMADI. v4.0'in skorlama
sistemi basit bir formul degil; 15 milyon vektorden turetilmis 270
"equivalence set"e dayanan buyuk bir lookup-table (MacroVector) sistemi
(bkz. FIRST.org CVSS v4.0 Specification). Bu tabloyu bellekten dogru
sekilde yeniden uretmek guvenilir degildir ve yanlis risk skorlari
uretme riski tasir -- bu nedenle CVSS v3.1 (kapali-form, dogrulanabilir
formul) tercih edildi. v4.0 istenirse, FIRST'in resmi referans
uygulamasindan alinan gercek lookup-table verisiyle ayri bir asamada
eklenebilir.

Formul kaynagi: https://www.first.org/cvss/v3.1/specification-document
(NVD "CVSS v3.1 Equations" sayfasindan dogrudan alinmis, 9.8 CRITICAL
textbook ornegiyle manuel olarak dogrulanmistir.)
"""

AV_VALUES = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
AC_VALUES = {'L': 0.77, 'H': 0.44}
PR_VALUES_UNCHANGED = {'N': 0.85, 'L': 0.62, 'H': 0.27}
PR_VALUES_CHANGED = {'N': 0.85, 'L': 0.68, 'H': 0.50}
UI_VALUES = {'N': 0.85, 'R': 0.62}
CIA_VALUES = {'H': 0.56, 'L': 0.22, 'N': 0.0}

VALID_VALUES = {
    'AV': set(AV_VALUES), 'AC': set(AC_VALUES), 'PR': set(PR_VALUES_UNCHANGED),
    'UI': set(UI_VALUES), 'S': {'U', 'C'}, 'C': set(CIA_VALUES),
    'I': set(CIA_VALUES), 'A': set(CIA_VALUES),
}


class CvssError(Exception):
    pass


def _roundup(x):
    """CVSS spesifikasyonunun resmi roundup fonksiyonu: girdiden buyuk veya
    esit, tek ondalikli en kucuk sayiyi doner."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def severity_label(score):
    if score <= 0:
        return 'info'
    if score < 4.0:
        return 'low'
    if score < 7.0:
        return 'medium'
    if score < 9.0:
        return 'high'
    return 'critical'


def compute(metrics):
    """metrics: {'AV':'N','AC':'L','PR':'N','UI':'N','S':'U','C':'H','I':'H','A':'H'}
    Doner: {'base_score', 'severity', 'vector', 'impact_subscore', 'exploitability_subscore'}"""
    for key in ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'):
        if key not in metrics:
            raise CvssError(f'Eksik metrik: {key}')
        if metrics[key] not in VALID_VALUES[key]:
            raise CvssError(f'Gecersiz {key} degeri: {metrics[key]}')

    av, ac, pr, ui, s, c, i, a = (metrics[k] for k in ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'))

    av_v, ac_v, ui_v = AV_VALUES[av], AC_VALUES[ac], UI_VALUES[ui]
    pr_v = PR_VALUES_CHANGED[pr] if s == 'C' else PR_VALUES_UNCHANGED[pr]
    c_v, i_v, a_v = CIA_VALUES[c], CIA_VALUES[i], CIA_VALUES[a]

    isc_base = 1 - (1 - c_v) * (1 - i_v) * (1 - a_v)
    if s == 'C':
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        impact = 6.42 * isc_base

    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

    if impact <= 0:
        base_score = 0.0
    elif s == 'C':
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base_score = _roundup(min(impact + exploitability, 10))

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return {
        'base_score': round(base_score, 1),
        'severity': severity_label(base_score),
        'vector': vector,
        'impact_subscore': round(max(impact, 0), 1),
        'exploitability_subscore': round(exploitability, 1),
    }
