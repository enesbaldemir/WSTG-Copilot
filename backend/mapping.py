"""
WSTG <-> OWASP Top 10 <-> CWE iliski katmani (Faz 1).

data/owasp-top10.*.json dosyalarinda zaten her Top10 kategorisi icin
'wstgRefs' (o kategoriyle iliskili WSTG test ID'leri) ve 'notableCwe'
(o kategoriyle iliskili one cikan CWE'ler) alanlari mevcut. Bu modul
o veriyi TERSINE cevirerek "bu WSTG test ID'sine bakinca hangi OWASP
Top10 kategorisi(leri) ve hangi CWE'ler iliskili?" sorusuna hizlica
cevap verebilen bir lookup insa eder.

Bu index hem:
  - not editorunde bir teste bagli not eklerken CWE onerisi sunmak,
  - Faz 2'deki AI bulgu analizine baglam (context) olarak vermek,
icin kullanilacak.
"""

import json
import os
import re

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(os.path.dirname(_BASE_DIR), "data")

_CWE_ID_RE = re.compile(r"^(CWE-\d+)\s*(.*)$")

_cache = {}  # lang -> {test_id: [{"owasp_id":..,"owasp_title":..,"cwes":[{"id":..,"name":..}]}]}


def _load_top10(lang: str):
    path = os.path.join(_DATA_DIR, f"owasp-top10.{lang}.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("top10", [])


def _parse_cwe(raw: str):
    """'CWE-89 SQL Injection' -> {'id': 'CWE-89', 'name': 'SQL Injection'}"""
    m = _CWE_ID_RE.match(raw.strip())
    if m:
        return {"id": m.group(1), "name": m.group(2).strip()}
    return {"id": None, "name": raw.strip()}


def _build_index(lang: str):
    index = {}
    for category in _load_top10(lang):
        cwes = [_parse_cwe(c) for c in category.get("notableCwe", [])]
        entry = {
            "owasp_id": category.get("id"),
            "owasp_title": category.get("title"),
            "cwes": cwes,
        }
        for test_id in category.get("wstgRefs", []):
            index.setdefault(test_id, []).append(entry)
    return index


def get_index(lang: str = "tr"):
    lang = lang if lang in ("tr", "en") else "tr"
    if lang not in _cache:
        _cache[lang] = _build_index(lang)
    return _cache[lang]


def get_mapping_for_test(test_id: str, lang: str = "tr"):
    """Belirli bir WSTG test ID'si icin iliskili OWASP Top10 + CWE listesini doner."""
    return get_index(lang).get(test_id, [])


def suggest_cwes_for_test(test_id: str, lang: str = "tr"):
    """Bir test icin, iliskili tum kategorilerden tekillestirilmis CWE onerisi."""
    seen = {}
    for match in get_mapping_for_test(test_id, lang):
        for cwe in match["cwes"]:
            if cwe["id"] and cwe["id"] not in seen:
                seen[cwe["id"]] = cwe
    return list(seen.values())


_wstg_cache = {}  # lang -> [{'id':.., 'title':.., 'category_code':.., 'category_name':..}, ...]


def get_all_tests(lang: str = "tr"):
    """Tüm WSTG test maddelerinin düz bir listesini döner (Faz 3 için: 'henüz yapılmamış testler' havuzu)."""
    lang = lang if lang in ("tr", "en") else "tr"
    if lang in _wstg_cache:
        return _wstg_cache[lang]
    path = os.path.join(_DATA_DIR, f"wstg-checklist.{lang}.json")
    tests = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for category in data.get("categories", []):
            for test in category.get("tests", []):
                tests.append({
                    "id": test["id"],
                    "title": test.get("title", ""),
                    "category_code": category.get("code", ""),
                    "category_name": category.get("name", ""),
                })
    _wstg_cache[lang] = tests
    return tests


def get_test_info(test_id: str, lang: str = "tr"):
    """Bir WSTG test ID'si için başlık/açıklama döner (AI prompt bağlamı için)."""
    lang = lang if lang in ("tr", "en") else "tr"
    path = os.path.join(_DATA_DIR, f"wstg-checklist.{lang}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for category in data.get("categories", []):
        for test in category.get("tests", []):
            if test.get("id") == test_id:
                return {
                    "id": test["id"],
                    "title": test.get("title", ""),
                    "description": test.get("description", ""),
                    "category_name": category.get("name", ""),
                    "category_code": category.get("code", ""),
                }
    return None
