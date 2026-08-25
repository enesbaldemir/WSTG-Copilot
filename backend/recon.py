"""
Attack Surface Discovery — hedefin subdomain/endpoint/teknoloji/API yüzeyini
çıkarır ve bulunanları WSTG test maddeleriyle ilişkilendirir.

Tasarım ilkeleri (bilerek konuldu, gevşetilmemeli):
  - Bu modül sadece kullanıcının KENDİ backend'inde, KENDİ makinesinde
    çalışır ve yalnızca kullanıcının açıkça belirttiği hedefe karşı
    istek atar. Anthropic/Claude bu isteği çalıştırmaz.
  - Her çağrı `confirm_authorized=True` şartına bağlıdır (app.py'de
    kontrol edilir); bu modül kendi başına bir yetkilendirme kararı
    vermez, sadece isteği taşır.
  - SSRF koruması: hedef çözümlenen IP'ler private/loopback/link-local/
    reserved ise reddedilir (örn. 127.0.0.1, 169.254.169.254 cloud
    metadata, RFC1918 iç ağlar) — pentester'ın kendi altyapısına ya da
    bulut metadata servisine yanlışlıkla istek atılmasını engeller.
  - Aktif keşif KASITLI olarak hafif tutulur: tek bir HTTP isteğiyle
    fingerprint + küçük, iyi bilinen (WSTG'nin zaten önerdiği) bir yol
    listesi kontrolü. Büyük wordlist'lerle brute-force / dizin fuzzing
    burada YAPILMAZ — bu, WSTG checklist'inin kendi "nasıl test edilir"
    adımlarında zaten manuel olarak önerilen kapsamla sınırlıdır.
  - Zaman aşımı ve sayı sınırları sabittir, çağıran taraf büyütemez.
"""

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests

REQUEST_TIMEOUT = 6
MAX_SUBDOMAINS = 15
MAX_LINKS = 40
USER_AGENT = "WSTG-Copilot-Recon/1.0 (+authorized-pentest-workspace)"

# WSTG'nin kendi "Review Old Backup and Unreferenced Files" /
# "Enumerate Admin Interfaces" adımlarında zaten önerdiği, iyi bilinen,
# küçük bir kontrol listesi. Kasıtlı olarak kısa tutuldu.
WELL_KNOWN_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "api", "api/v1", "graphql", "swagger.json", "openapi.json", "api-docs",
    "login", "admin", "administrator", "wp-admin", "wp-login.php",
    ".env", ".git/config", "backup.zip", "server-status", "actuator", "debug",
]

TECH_SIGNATURES = [
    (re.compile(r"wordpress|wp-content", re.I), "WordPress"),
    (re.compile(r"x-powered-by:\s*php", re.I), "PHP"),
    (re.compile(r"laravel_session|laravel", re.I), "Laravel"),
    (re.compile(r"x-powered-by:\s*express", re.I), "Express.js"),
    (re.compile(r"django", re.I), "Django"),
    (re.compile(r"x-drupal", re.I), "Drupal"),
    (re.compile(r"jsessionid", re.I), "Java/JSP"),
    (re.compile(r"asp\.net|x-aspnet-version", re.I), "ASP.NET"),
    (re.compile(r"cf-ray|cloudflare", re.I), "Cloudflare"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "Apache"),
    (re.compile(r"react", re.I), "React"),
    (re.compile(r"vue\.js|__vue__", re.I), "Vue.js"),
    (re.compile(r"angular", re.I), "Angular"),
    (re.compile(r"jquery[-.]?([\d.]+)?\.js", re.I), "jQuery"),
    (re.compile(r"bootstrap", re.I), "Bootstrap"),
    (re.compile(r"graphql", re.I), "GraphQL"),
]

# path/pattern -> WSTG test id eşleştirme kuralları.
WSTG_SURFACE_RULES = [
    (re.compile(r"/api(/|$|-)", re.I), ["WSTG-APIT-01", "WSTG-INPV-20"], "high", "API endpoint bulundu"),
    (re.compile(r"graphql", re.I), ["WSTG-APIT-01"], "high", "GraphQL endpoint bulundu"),
    (re.compile(r"swagger|openapi|api-docs", re.I), ["WSTG-APIT-01", "WSTG-INFO-04"], "medium", "API dokümantasyonu açık"),
    (re.compile(r"/login|/signin|/auth(?!or)", re.I), ["WSTG-ATHN-01", "WSTG-ATHN-02", "WSTG-ATHN-03", "WSTG-ATHN-04"], "high", "Kimlik doğrulama sayfası bulundu"),
    (re.compile(r"/register|/signup", re.I), ["WSTG-IDNT-02", "WSTG-IDNT-03", "WSTG-IDNT-04"], "medium", "Kayıt fonksiyonu bulundu"),
    (re.compile(r"/reset|/forgot", re.I), ["WSTG-ATHN-09"], "medium", "Şifre sıfırlama fonksiyonu bulundu"),
    (re.compile(r"/admin|/administrator|wp-admin|wp-login", re.I), ["WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-CONF-05"], "high", "Yönetim arayüzü bulundu"),
    (re.compile(r"/upload", re.I), ["WSTG-BUSL-08", "WSTG-BUSL-09"], "high", "Dosya yükleme fonksiyonu bulundu"),
    (re.compile(r"\.git/config|\.env\b|backup\.zip|\.bak\b|\.old\b", re.I), ["WSTG-CONF-04"], "high", "Hassas/yedek dosya açık olabilir"),
    (re.compile(r"server-status|actuator|debug", re.I), ["WSTG-CONF-02"], "medium", "Yönetim/tanılama endpoint'i açık"),
    (re.compile(r"robots\.txt|sitemap\.xml", re.I), ["WSTG-INFO-03"], "info", "Metafile incelenmeli"),
]


class ReconError(Exception):
    pass


def _is_public_hostname(hostname):
    """SSRF koruması: hostname'in çözümlendiği TÜM IP'ler public/global olmalı."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, []
    ips = sorted({info[4][0] for info in infos})
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, ips
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False, ips
    return True, ips


def normalize_target(raw_target):
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ReconError("Hedef boş olamaz.")
    if not re.match(r"^https?://", raw_target, re.I):
        raw_target = "https://" + raw_target
    parsed = urlparse(raw_target)
    hostname = parsed.hostname
    if not hostname:
        raise ReconError("Geçersiz hedef.")
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        raise ReconError("Geçersiz hedef adı.")
    ok, ips = _is_public_hostname(hostname)
    if not ok:
        raise ReconError(
            "Bu hedef genel (public) bir DNS kaydına çözülmüyor veya özel/yerel bir "
            "IP aralığına işaret ediyor (SSRF koruması). Yalnızca dışa açık, test "
            "yetkiniz olan hedefleri girin."
        )
    return hostname, f"{parsed.scheme}://{hostname}", ips


def discover_subdomains(domain, limit=MAX_SUBDOMAINS):
    """crt.sh Certificate Transparency loglarından PASİF subdomain keşfi.
    Hedefe hiçbir istek atmaz — sadece kamuya açık CT log veritabanını sorgular."""
    found = set()
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.ok:
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and re.match(r"^[a-z0-9.-]+$", name):
                        found.add(name)
    except Exception:
        pass  # crt.sh erişilemezse sessizce boş liste ile devam edilir
    found.add(domain)
    return sorted(found)[:limit]


def resolve_live_hosts(hostnames):
    live = []
    for h in hostnames:
        ok, ips = _is_public_hostname(h)
        if ok and ips:
            live.append({"host": h, "ips": ips})
    return live


def fetch(url, path=""):
    full = urljoin(url + "/", path)
    try:
        resp = requests.get(
            full, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        return resp
    except Exception:
        return None


def fingerprint_tech(headers_text, body_text):
    combined = f"{headers_text}\n{body_text[:20000]}"
    found = set()
    for pattern, name in TECH_SIGNATURES:
        if pattern.search(combined):
            found.add(name)
    return sorted(found)


def extract_links(html, base_url):
    links = set()
    forms = []
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
        links.add(m.group(1))
    for m in re.finditer(r'src=["\']([^"\']+)["\']', html, re.I):
        links.add(m.group(1))
    for m in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S):
        action = m.group(1)
        opening_tag = m.group(0).split('>', 1)[0] + '>'
        method_m = re.search(r'method=["\'](\w+)["\']', opening_tag, re.I)
        has_file = bool(re.search(r'type=["\']file["\']', m.group(2), re.I))
        forms.append({"action": action, "method": (method_m.group(1) if method_m else "GET").upper(), "hasFileInput": has_file})

    base_host = urlparse(base_url).netloc
    same_domain_paths = set()
    for link in links:
        if link.startswith("#") or link.startswith("mailto:") or link.startswith("javascript:"):
            continue
        absolute = urljoin(base_url, link)
        parsed = urlparse(absolute)
        if parsed.netloc == base_host and parsed.path:
            same_domain_paths.add(parsed.path)
    return sorted(same_domain_paths)[:MAX_LINKS], forms


def map_to_wstg(paths, forms, cookies_present):
    suggestions = {}

    def add(ids, level, reason):
        for tid in ids:
            entry = suggestions.setdefault(tid, {"level": level, "reasons": set()})
            # en yüksek öncelik seviyesini koru
            order = {"high": 3, "medium": 2, "low": 1, "info": 0}
            if order.get(level, 0) > order.get(entry["level"], 0):
                entry["level"] = level
            entry["reasons"].add(reason)

    for p in paths:
        for pattern, ids, level, reason in WSTG_SURFACE_RULES:
            if pattern.search(p):
                add(ids, level, f"{reason}: {p}")

    for f in forms:
        if f["hasFileInput"]:
            add(["WSTG-BUSL-08", "WSTG-BUSL-09"], "high", f"Dosya yükleme formu: {f['action'] or '(mevcut sayfa)'}")
        if f["method"] == "POST":
            add(["WSTG-SESS-05"], "medium", f"POST formu (CSRF kontrolü gerekli): {f['action'] or '(mevcut sayfa)'}")

    if cookies_present:
        add(["WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-09"], "medium", "Cookie kullanımı tespit edildi")

    return {
        tid: {"level": v["level"], "reasons": sorted(v["reasons"])}
        for tid, v in suggestions.items()
    }


def run_discovery(raw_target):
    hostname, base_url, _ips = normalize_target(raw_target)

    subdomains_raw = discover_subdomains(hostname)
    live_hosts = resolve_live_hosts(subdomains_raw)

    resp = fetch(base_url)
    technologies = []
    endpoints = []
    forms = []
    cookies_present = False
    interesting_paths = []

    if resp is not None:
        headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body_text = resp.text if resp.text else ""
        technologies = fingerprint_tech(headers_text, body_text)
        cookies_present = bool(resp.cookies) or "set-cookie" in [h.lower() for h in resp.headers.keys()]
        endpoints, forms = extract_links(body_text, base_url)

        for path in WELL_KNOWN_PATHS:
            r = fetch(base_url, path)
            if r is not None and r.status_code < 400:
                interesting_paths.append({"path": "/" + path, "status": r.status_code})

    all_paths = list(dict.fromkeys(endpoints + [p["path"] for p in interesting_paths]))
    suggestions = map_to_wstg(all_paths, forms, cookies_present)

    apis = [p for p in all_paths if re.search(r"/api(/|$)|graphql", p, re.I)]

    return {
        "target": hostname,
        "baseUrl": base_url,
        "subdomains": [h["host"] for h in live_hosts],
        "technologies": technologies,
        "endpoints": endpoints,
        "apis": apis,
        "interestingPaths": interesting_paths,
        "forms": forms,
        "cookiesPresent": cookies_present,
        "suggestions": suggestions,
    }
