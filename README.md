# Pentest Workspace — OWASP WSTG v4.2

![Frontend](https://img.shields.io/badge/frontend-HTML%20%7C%20CSS%20%7C%20JS-informational)
![Backend](https://img.shields.io/badge/backend-Flask%20%2B%20SQLite-lightgrey)
![AI](https://img.shields.io/badge/AI-multi--provider%20%2B%20BYOK-8b5cf6)
![License](https://img.shields.io/badge/license-MIT-green)

**[English](#english)** · **[Türkçe](#türkçe)**

---

## English

### Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Running](#running)
- [Authentication](#authentication)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

### Overview

Pentest Workspace is a web application for running penetration tests based on the **OWASP Web Security Testing Guide (WSTG) v4.2**. It combines the WSTG checklist with engagement management: scope definition, attack surface discovery, CVSS-scored findings, evidence collection, rule-based attack-chain correlation, a Kanban board and DOCX/HTML/PDF reporting. AI assistance (Anthropic, OpenAI, Google Gemini or Ollama) is optional and every AI output is a draft that the user reviews.

The checklist works with only a static file server. Projects, findings, evidence, reports and AI features require the Flask + SQLite backend.

### Features

**Checklist**
- 98 WSTG v4.2 test items in 12 categories; each item has a description, testing steps, an example payload/command and suggested tools
- Alternate checklist: OWASP LLM Top 10 (10 categories, 21 test items) for LLM-based targets
- OWASP Top 10:2025 reference module (10 categories) cross-linked to WSTG items
- Project-specific custom test items
- Global search, progress dashboard, Turkish/English interface
- Bundled original WSTG v4.2 PDF (`wstg-v4_2.pdf`)

**Projects and sessions** (backend required)
- Projects with client, description, status and start/end dates; each project has a timeline of events
- Scope management: in-scope / out-of-scope domains, subdomains, IPs and CIDR ranges
- Named test sessions (name, tester, target URL); checklist progress is stored in SQLite and can be resumed. If the backend is unreachable, the app falls back to `localStorage`
- Attack Surface Discovery (recon): passive subdomain discovery via crt.sh Certificate Transparency logs, DNS resolution, a single HTTP fetch for technology fingerprinting, link/form/cookie extraction and a short list of well-known paths (`robots.txt`, `swagger.json`, `.git/config`, …). Results are mapped to WSTG test IDs, stored per project and shown again when the panel is reopened. Requires explicit authorization confirmation; targets resolving to private, loopback, link-local or reserved IPs are rejected (SSRF protection)
- Tool Runner: runs an allow-listed set of tools (`nmap`, `httpx`, `whatweb`, `subfinder`, `dnsx`) with fixed argument templates, shows a command preview first and keeps a run history per project. Commands are passed as argument lists (no shell); missing tools are reported as unavailable, never auto-installed
- Test Planner: rule-based priority queue that ranks WSTG items by recon evidence and methodology order, with the reason for each ranking
- AI "What's Next?": AI-generated suggestion for the next test based on completed tests and findings, with alternate candidates
- Import of Nmap (XML), Nikto (XML/JSON) and WPScan (JSON) output into findings linked to WSTG items

**Findings**
- Title, description, affected endpoint, remediation, CWE, severity and a CVSS v3.1 calculator with live scoring (client and server side)
- Duplicate detection based on title/description/endpoint/CWE similarity (`difflib`), with merge or create-anyway options
- Attack-chain correlation: findings are matched against 10 fixed attack-chain patterns (e.g. user enumeration → weak authentication → account takeover). No AI involved
- Kanban board for test results with the columns To Do, Testing, Review, Confirmed and Done

**Evidence**
- Screenshot upload (PNG/JPEG/WebP/GIF), stored under server-generated UUID file names
- Raw HTTP request/response evidence with automatic redaction of secrets and PII (Authorization headers, cookies, JWTs, common API key formats, private keys, e-mail addresses, card-like numbers); the unredacted text is only returned on explicit request
- Optional AI vision analysis of screenshots (Anthropic Claude, enabled only when `ANTHROPIC_API_KEY` is set) that suggests WSTG test IDs validated against the real dataset; suggestions are only attached after the user accepts them

**Reporting**
- DOCX reports in three templates: Technical, Executive and Developer
- Self-contained HTML report (single file, no external dependencies) with a print / save-as-PDF button
- Server-side PDF report generated with `xhtml2pdf` (cover page, executive summary, risk breakdown, per-finding details, appendices, page numbers) with an embedded font for Turkish characters
- Finding selection for HTML/PDF reports: all, critical + high only, or hand-picked
- Session-level reports (Markdown / DOCX) and an optional AI-drafted executive summary

**AI assistance**
- Providers: Anthropic, OpenAI, Google Gemini, Ollama (local)
- AI Settings panel: store an encrypted (Fernet) API key per provider, choose the active provider and test the connection
- Bring Your Own Key (BYOK): each user can enter a personal key that is kept in the browser's `sessionStorage` and sent per request via `X-AI-*` headers; it is not stored on the server
- Uses: drafting descriptions and remediation, CWE/severity/CVSS suggestions, text rewriting, next-test suggestions, executive summary drafts
- Every AI call is logged (provider, model, latency, purpose, success/failure) and available at `/api/ai/logs`

### Tech Stack

| Layer | Technologies |
|---|---|
| Frontend | HTML5, CSS3, vanilla JavaScript (no framework, no build step), Inter font (Google Fonts) |
| Backend | Python, Flask 2.3, Flask-SQLAlchemy, Flask-CORS, SQLite |
| Reporting | `python-docx`, `xhtml2pdf` |
| Security | `cryptography` (Fernet) for stored AI keys |
| AI | Provider layer for Anthropic, OpenAI, Gemini and Ollama (HTTP via `requests`) |
| External tools (optional) | `nmap`, `httpx`, `whatweb`, `subfinder`, `dnsx` |

### Architecture

```
Browser (index.html + js/app.js)
   │  loads checklist data from data/*.json
   │  REST calls to http://localhost:5000/api  (+ optional X-AI-* BYOK headers)
   ▼
Flask API (backend/app.py)
   ├── SQLAlchemy models ──► SQLite (backend/database/wstg.db)
   ├── recon.py / tool_runner.py ──► target (after authorization + SSRF checks)
   ├── cvss.py, duplicate_detector.py, attack_chains.py, redaction.py   (rule-based)
   ├── report_builder.py / report_html.py / report_pdf.py / report_generator.py
   └── ai/factory.py ──► Anthropic | OpenAI | Gemini | Ollama
```

- The frontend is a static single-page application. It reads checklist content from `data/*.json` and talks to the backend at the fixed address `http://localhost:5000/api` (`API_BASE` in `js/app.js`). Without a backend it works in checklist-only mode using `localStorage`.
- The backend creates the database and tables on first start and adds missing columns to an existing database automatically.
- AI provider resolution order: BYOK request headers → active provider saved in the AI Settings panel → `.env` values. If none is configured, AI features are disabled; no placeholder content is generated.
- Uploaded evidence files are stored under `backend/uploads/`.

### Requirements

- Python 3 with `pip` and `venv`
- A modern web browser
- Any static file server for the frontend (e.g. `python -m http.server`)
- Optional: `nmap`, `httpx`, `whatweb`, `subfinder`, `dnsx` on `PATH` for the Tool Runner
- Optional: an API key for Anthropic / OpenAI / Gemini, or a running Ollama instance, for AI features

### Installation

```bash
git clone https://github.com/enesbaldemir/WSTG-Copilot.git
cd WSTG-Copilot/backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # optional
```

### Environment Variables

All variables are optional and are read from `backend/.env`. AI keys are normally entered in the in-app AI Settings panel; the AI variables below are fallbacks for setups without a UI.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///<backend>/database/wstg.db` | SQLAlchemy database URL |
| `SECRET_KEY` | generated | Flask secret key. If empty, a random key is generated on first start and stored in `backend/instance/secret_key` (file mode `0600`, ignored by git) |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000` | Allowed frontend origins. `POST`/`PUT`/`PATCH`/`DELETE` requests sent from any other origin are rejected with `403` |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Accepted `Host` headers (DNS rebinding protection). Add this machine's name/IP if you expose the API with `WSTG_HOST` |
| `WSTG_HOST` / `WSTG_PORT` | `127.0.0.1` / `5000` | Address `python app.py` listens on. Anything other than loopback exposes the API to the network over plain HTTP; see [Authentication](#authentication) |
| `WSTG_SESSION_HOURS` | `12` | How long a sign-in lasts, counted from sign-in (not extended by activity) |
| `SESSION_COOKIE_SECURE` | off | `1` marks the session cookie `Secure`. Only enable it when the API is served over HTTPS, otherwise the browser will not send the cookie |
| `FLASK_DEBUG` | off | `1` enables the Werkzeug debugger. Refused unless the host is loopback, because a network-reachable debugger allows remote code execution |
| `LOG_LEVEL` | `INFO` | Log level |
| `ANTHROPIC_API_KEY` | empty | Enables AI vision analysis of evidence screenshots; also the Anthropic fallback key |
| `AI_PROVIDER` | `gemini` | Fallback provider: `gemini`, `openai`, `anthropic` or `ollama` |
| `AI_REQUEST_TIMEOUT` | `30` | AI request timeout in seconds |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | empty / `gemini-3.7-flash` | Gemini key and model |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | empty / `gpt-5.6-terra` | OpenAI key and model |
| `ANTHROPIC_MODEL` | `claude-sonnet-5` | Anthropic model |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `http://localhost:11434` / `llama3.1` | Ollama server and model |
| `ENCRYPTION_KEY` | derived from `SECRET_KEY` | Key used to encrypt API keys saved in AI Settings. If it is not set and `SECRET_KEY` changes, saved keys must be re-entered |

Do not commit `backend/.env`; it is already listed in `.gitignore`.

### Running

1. Start the backend (from `backend/`, with the virtual environment active):

   ```bash
   python app.py
   ```

   The API listens on `http://127.0.0.1:5000` with the debugger off. On first start it creates `backend/instance/secret_key` if `SECRET_KEY` is not set; AI keys saved by older versions under the old built-in key are re-encrypted automatically.

2. Serve the frontend from the repository root in a second terminal:

   ```bash
   python -m http.server 8000
   ```

3. Open `http://localhost:8000` (or `http://127.0.0.1:8000`). The frontend detects the backend automatically. On first open you are asked to set a password; after that you sign in.

For checklist-only use, step 1 can be skipped; progress is then kept in `localStorage` and no sign-in is needed.

### Authentication

The backend is single-user and protected by a password.

- **First password.** The first time the interface is opened it asks for a password of at least 12 characters. This screen only works from the computer running the API (loopback address), so nobody on the network can claim the workspace first. On a headless or remote setup, set it in a terminal with `python app.py set-password`.
- **Sign-in.** The session is Flask's signed session cookie `wstg_session` (`HttpOnly`, `SameSite=Strict`), valid for 12 hours from sign-in. Without it every `/api` endpoint returns `401`, except `/api/auth/status`, `/api/auth/setup`, `/api/auth/login` and `/api/auth/logout`. When a session ends, the interface returns to the sign-in screen.
- **Storage.** Only a salted hash (`werkzeug.security`) is stored, in the `auth_settings` table. The table is created automatically on start. Existing data is not touched.
- **Failed attempts.** After 5 failed attempts from the same address, sign-in is locked for 30 seconds, doubling up to 15 minutes. The counter is kept in memory and resets when the backend restarts.
- **Change password / sign out.** Both are in the sidebar. Changing the password signs out every other browser; the current one stays signed in.
- **Forgot the password.** Run `python app.py set-password` in `backend/` (the backend can keep running). The password is asked twice and never passed as an argument. All open sessions are signed out.
- **localhost vs 127.0.0.1.** Browsers treat these as different sites, so the frontend calls the API on the same host the page was opened from (`127.0.0.1:8000` → `127.0.0.1:5000`, `localhost:8000` → `localhost:5000`). Each address needs its own sign-in.

**Upgrading.** After updating, the backend requires a sign-in. Open the interface on the API machine and set a password, or run `python app.py set-password`. Projects, findings and evidence are kept as they are.

### Project Structure

```
WSTG-Copilot/
├── index.html                  # Single-page frontend
├── css/style.css               # Styles
├── js/
│   ├── app.js                  # Application logic, i18n, API client, AI/BYOK panels
│   ├── auth.js                 # API address selection and auth error codes
│   ├── cvss.js                 # CVSS v3.1 calculator
│   └── import-parsers.js       # Nmap / Nikto / WPScan parsers
├── data/
│   ├── wstg-checklist.{tr,en}.json
│   ├── owasp-top10.{tr,en}.json
│   └── llm-security-checklist.{tr,en}.json
├── backend/
│   ├── app.py                  # Flask REST API
│   ├── models.py               # SQLAlchemy models
│   ├── config.py               # Configuration from environment variables
│   ├── auth.py                 # Password hashing, policy, login throttling
│   ├── security.py             # Local-only defaults (host, debug, CORS, Origin/Host checks)
│   ├── ai/                     # Provider layer (factory + Anthropic/OpenAI/Gemini/Ollama)
│   ├── ai_report_assistant.py  # Description / remediation / rewrite / summary prompts
│   ├── finding_analysis.py     # AI CWE / severity / CVSS suggestion
│   ├── next_test_suggestion.py # AI next-test suggestion
│   ├── evidence_intel.py       # Optional AI screenshot analysis
│   ├── recon.py                # Attack Surface Discovery
│   ├── tool_runner.py          # Allow-listed external tool execution
│   ├── attack_chains.py        # Rule-based attack-chain correlation
│   ├── duplicate_detector.py   # Duplicate finding detection
│   ├── redaction.py            # Secret / PII redaction
│   ├── crypto_utils.py         # Fernet encryption for stored keys
│   ├── mapping.py              # WSTG ↔ OWASP Top 10 ↔ CWE index
│   ├── cvss.py                 # CVSS v3.1 scoring
│   ├── report_builder.py       # DOCX project reports
│   ├── report_html.py          # HTML report
│   ├── report_pdf.py           # PDF report
│   ├── report_generator.py     # Session-level reports
│   ├── test_*.py               # Tests
│   ├── .env.example
│   └── requirements.txt
├── wstg-v4_2.pdf               # OWASP WSTG v4.2 guide
└── LICENSE
```

### Contributing

1. Fork the repository and create a branch from `main`.
2. Make your changes; keep the frontend free of build steps and frameworks.
3. Run the relevant tests from the `backend/` directory, for example:

   ```bash
   python test_finding_analysis.py
   python test_ai_layer.py
   ```

4. Open a pull request describing the change.

Bug reports and suggestions are welcome as GitHub issues.

### Disclaimer

This tool is intended for **authorized** security testing and educational use only. Testing systems without the owner's explicit permission is illegal. Recon and the Tool Runner only act on targets you specify and require you to confirm authorization. You are responsible for how you use this project.

### License

Released under the [MIT License](LICENSE).

Test content is based on the [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/), [OWASP Top 10:2025](https://owasp.org/Top10/2025/) and the OWASP LLM Top 10.

---

## Türkçe

### İçindekiler

- [Genel Bakış](#genel-bakış)
- [Özellikler](#özellikler)
- [Kullanılan Teknolojiler](#kullanılan-teknolojiler)
- [Mimari](#mimari)
- [Gereksinimler](#gereksinimler)
- [Kurulum](#kurulum)
- [Ortam Değişkenleri](#ortam-değişkenleri)
- [Çalıştırma](#çalıştırma)
- [Kimlik Doğrulama](#kimlik-doğrulama)
- [Proje Klasör Yapısı](#proje-klasör-yapısı)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)

### Genel Bakış

Pentest Workspace, **OWASP Web Security Testing Guide (WSTG) v4.2** temelli sızma testleri yürütmek için geliştirilmiş bir web uygulamasıdır. WSTG checklist'ini engagement yönetimiyle birleştirir: kapsam tanımı, saldırı yüzeyi keşfi, CVSS puanlı bulgular, kanıt toplama, kural tabanlı saldırı zinciri korelasyonu, Kanban panosu ve DOCX/HTML/PDF raporlama. AI desteği (Anthropic, OpenAI, Google Gemini veya Ollama) opsiyoneldir ve üretilen her çıktı kullanıcının gözden geçirdiği bir taslaktır.

Checklist yalnızca statik bir dosya sunucusuyla çalışır. Projeler, bulgular, kanıtlar, raporlar ve AI özellikleri için Flask + SQLite backend'i gerekir.

### Özellikler

**Checklist**
- 12 kategoride 98 WSTG v4.2 test maddesi; her maddede açıklama, test adımları, örnek payload/komut ve önerilen araçlar
- Alternatif checklist: LLM tabanlı hedefler için OWASP LLM Top 10 (10 kategori, 21 test maddesi)
- WSTG maddelerine bağlantılı OWASP Top 10:2025 referans modülü (10 kategori)
- Projeye özel test maddeleri
- Global arama, ilerleme paneli, Türkçe/İngilizce arayüz
- Orijinal WSTG v4.2 PDF'i (`wstg-v4_2.pdf`)

**Projeler ve oturumlar** (backend gerekir)
- Müşteri, açıklama, durum ve başlangıç/bitiş tarihi içeren projeler; her projenin olay zaman çizelgesi
- Kapsam yönetimi: kapsam içi/dışı domain, subdomain, IP ve CIDR aralıkları
- İsimli test oturumları (isim, test uzmanı, hedef URL); checklist ilerlemesi SQLite'a kaydedilir ve devam ettirilebilir. Backend'e erişilemezse uygulama `localStorage` moduna geçer
- Attack Surface Discovery (recon): crt.sh Certificate Transparency kayıtları üzerinden pasif subdomain keşfi, DNS çözümleme, teknoloji tespiti için tek bir HTTP isteği, link/form/cookie çıkarımı ve kısa bir iyi bilinen yol listesinin kontrolü (`robots.txt`, `swagger.json`, `.git/config`, …). Sonuçlar WSTG test ID'leriyle eşleştirilir, proje bazında saklanır ve panel yeniden açıldığında tekrar gösterilir. Yetki onayı zorunludur; private, loopback, link-local veya reserved IP'ye çözümlenen hedefler reddedilir (SSRF koruması)
- Tool Runner: izin listesindeki araçları (`nmap`, `httpx`, `whatweb`, `subfinder`, `dnsx`) sabit argüman şablonlarıyla çalıştırır, önce komut önizlemesi gösterir ve proje bazında çalıştırma geçmişi tutar. Komutlar shell kullanılmadan argüman listesi olarak verilir; kurulu olmayan araçlar "kullanılamaz" olarak bildirilir, otomatik kurulum yapılmaz
- Test Planı: WSTG maddelerini recon kanıtı ve metodoloji sırasına göre sıralayan, her sıralamanın gerekçesini gösteren kural tabanlı öncelik kuyruğu
- AI: Sırada Ne Var?: tamamlanan testlere ve bulgulara göre bir sonraki test için AI önerisi ve alternatif adaylar
- Nmap (XML), Nikto (XML/JSON) ve WPScan (JSON) çıktılarını WSTG maddelerine bağlı bulgulara dönüştüren içe aktarma

**Bulgular**
- Başlık, açıklama, etkilenen endpoint, remediation, CWE, önem derecesi ve canlı skor hesaplayan CVSS v3.1 hesaplayıcı (istemci ve sunucu tarafı)
- Başlık/açıklama/endpoint/CWE benzerliğine (`difflib`) dayalı tekrar tespiti; birleştir ya da yine de oluştur seçenekleri
- Saldırı zinciri korelasyonu: bulgular 10 sabit saldırı zinciri kalıbıyla eşleştirilir (ör. kullanıcı numaralandırma → zayıf kimlik doğrulama → hesap ele geçirme). AI kullanılmaz
- Test sonuçları için Yapılacak, Test Ediliyor, İncelemede, Onaylandı ve Tamamlandı sütunlarından oluşan Kanban panosu

**Kanıtlar**
- Ekran görüntüsü yükleme (PNG/JPEG/WebP/GIF); dosyalar sunucu tarafında üretilen UUID adlarıyla saklanır
- Gizli bilgi ve kişisel verilerin otomatik maskelendiği ham HTTP request/response kanıtı (Authorization header'ları, cookie'ler, JWT'ler, yaygın API key formatları, private key'ler, e-posta adresleri, kart benzeri numaralar); maskelenmemiş metin yalnızca açık istek üzerine döner
- Ekran görüntüleri için opsiyonel AI görsel analizi (Anthropic Claude, yalnızca `ANTHROPIC_API_KEY` tanımlıysa etkin): gerçek veri setine göre doğrulanmış WSTG test ID'leri önerir; öneriler kullanıcı onaylamadan bağlanmaz

**Raporlama**
- Üç şablonlu DOCX rapor: Technical, Executive ve Developer
- Yazdır / PDF olarak kaydet butonlu, harici bağımlılığı olmayan tek dosyalık HTML rapor
- `xhtml2pdf` ile sunucu tarafında üretilen PDF rapor (kapak, yönetici özeti, risk dağılımı, bulgu detayları, ekler, sayfa numaraları); Türkçe karakterler için gömülü font
- HTML/PDF raporlarında bulgu seçimi: tümü, yalnızca kritik + yüksek ya da tek tek seçim
- Oturum bazlı raporlar (Markdown / DOCX) ve opsiyonel AI destekli yönetici özeti taslağı

**AI desteği**
- Sağlayıcılar: Anthropic, OpenAI, Google Gemini, Ollama (yerel)
- AI Ayarları paneli: sağlayıcı bazında şifreli (Fernet) API key saklama, aktif sağlayıcı seçimi ve bağlantı testi
- Kendi Key'ini Kullan (BYOK): her kullanıcı kişisel key'ini girebilir; key tarayıcının `sessionStorage`'ında tutulur, her istekte `X-AI-*` header'larıyla gönderilir ve sunucuda saklanmaz
- Kullanım alanları: açıklama ve remediation taslağı, CWE/önem/CVSS önerisi, metin yeniden yazımı, sonraki test önerisi, yönetici özeti taslağı
- Her AI çağrısı (sağlayıcı, model, gecikme, amaç, başarı/hata) loglanır ve `/api/ai/logs` üzerinden görüntülenebilir

### Kullanılan Teknolojiler

| Katman | Teknolojiler |
|---|---|
| Frontend | HTML5, CSS3, vanilla JavaScript (framework ve build adımı yok), Inter yazı tipi (Google Fonts) |
| Backend | Python, Flask 2.3, Flask-SQLAlchemy, Flask-CORS, SQLite |
| Raporlama | `python-docx`, `xhtml2pdf` |
| Güvenlik | Saklanan AI key'leri için `cryptography` (Fernet) |
| AI | Anthropic, OpenAI, Gemini ve Ollama için sağlayıcı katmanı (`requests` ile HTTP) |
| Dış araçlar (opsiyonel) | `nmap`, `httpx`, `whatweb`, `subfinder`, `dnsx` |

### Mimari

```
Tarayıcı (index.html + js/app.js)
   │  checklist verisini data/*.json dosyalarından yükler
   │  http://localhost:5000/api adresine REST çağrıları (+ opsiyonel X-AI-* BYOK header'ları)
   ▼
Flask API (backend/app.py)
   ├── SQLAlchemy modelleri ──► SQLite (backend/database/wstg.db)
   ├── recon.py / tool_runner.py ──► hedef (yetki onayı + SSRF kontrolünden sonra)
   ├── cvss.py, duplicate_detector.py, attack_chains.py, redaction.py   (kural tabanlı)
   ├── report_builder.py / report_html.py / report_pdf.py / report_generator.py
   └── ai/factory.py ──► Anthropic | OpenAI | Gemini | Ollama
```

- Frontend statik, tek sayfalık bir uygulamadır. Checklist içeriğini `data/*.json` dosyalarından okur ve backend ile sabit `http://localhost:5000/api` adresi üzerinden konuşur (`js/app.js` içindeki `API_BASE`). Backend yoksa `localStorage` kullanan yalnızca-checklist modunda çalışır.
- Backend ilk açılışta veritabanını ve tabloları oluşturur, mevcut bir veritabanındaki eksik kolonları otomatik ekler.
- AI sağlayıcı seçim sırası: BYOK istek header'ları → AI Ayarları panelinde aktif edilen sağlayıcı → `.env` değerleri. Hiçbiri yoksa AI özellikleri devre dışı kalır; sahte içerik üretilmez.
- Yüklenen kanıt dosyaları `backend/uploads/` altında saklanır.

### Gereksinimler

- Python 3 (`pip` ve `venv` ile)
- Güncel bir web tarayıcısı
- Frontend için herhangi bir statik dosya sunucusu (ör. `python -m http.server`)
- Opsiyonel: Tool Runner için `PATH` üzerinde `nmap`, `httpx`, `whatweb`, `subfinder`, `dnsx`
- Opsiyonel: AI özellikleri için Anthropic / OpenAI / Gemini API key'i ya da çalışan bir Ollama sunucusu

### Kurulum

```bash
git clone https://github.com/enesbaldemir/WSTG-Copilot.git
cd WSTG-Copilot/backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # opsiyonel
```

### Ortam Değişkenleri

Tüm değişkenler opsiyoneldir ve `backend/.env` dosyasından okunur. AI key'leri normalde uygulama içindeki AI Ayarları panelinden girilir; aşağıdaki AI değişkenleri arayüzsüz kurulumlar için fallback'tir.

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `DATABASE_URL` | `sqlite:///<backend>/database/wstg.db` | SQLAlchemy veritabanı adresi |
| `SECRET_KEY` | otomatik üretilir | Flask gizli anahtarı. Boşsa ilk açılışta rastgele bir anahtar üretilip `backend/instance/secret_key` dosyasına (`0600` izinle, git'e girmez) kaydedilir |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000` | İzin verilen frontend origin'leri. Başka bir origin'den gelen `POST`/`PUT`/`PATCH`/`DELETE` istekleri `403` ile reddedilir |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Kabul edilen `Host` başlıkları (DNS rebinding koruması). API'yi `WSTG_HOST` ile ağa açarsanız bu makinenin adını/IP'sini ekleyin |
| `WSTG_HOST` / `WSTG_PORT` | `127.0.0.1` / `5000` | `python app.py`'nin dinlediği adres. Loopback dışındaki her değer API'yi şifresiz HTTP üzerinden ağa açar; bkz. [Kimlik Doğrulama](#kimlik-doğrulama) |
| `WSTG_SESSION_HOURS` | `12` | Bir girişin geçerlilik süresi; girişten itibaren sayılır, kullanım süreyi uzatmaz |
| `SESSION_COOKIE_SECURE` | kapalı | `1` oturum çerezini `Secure` yapar. Yalnızca API HTTPS üzerinden sunuluyorsa açın; aksi halde tarayıcı çerezi göndermez |
| `FLASK_DEBUG` | kapalı | `1` Werkzeug debugger'ını açar. Ağdan erişilebilen debugger uzaktan kod çalıştırmaya izin verdiği için host loopback değilse uygulama başlamaz |
| `LOG_LEVEL` | `INFO` | Log seviyesi |
| `ANTHROPIC_API_KEY` | boş | Kanıt ekran görüntülerinin AI görsel analizini etkinleştirir; Anthropic için fallback key'dir |
| `AI_PROVIDER` | `gemini` | Fallback sağlayıcı: `gemini`, `openai`, `anthropic` veya `ollama` |
| `AI_REQUEST_TIMEOUT` | `30` | AI isteği zaman aşımı (saniye) |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | boş / `gemini-3.7-flash` | Gemini key'i ve modeli |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | boş / `gpt-5.6-terra` | OpenAI key'i ve modeli |
| `ANTHROPIC_MODEL` | `claude-sonnet-5` | Anthropic modeli |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `http://localhost:11434` / `llama3.1` | Ollama sunucusu ve modeli |
| `ENCRYPTION_KEY` | `SECRET_KEY`'den türetilir | AI Ayarları'nda saklanan key'leri şifreleyen anahtar. Tanımlı değilse ve `SECRET_KEY` değişirse kayıtlı key'lerin yeniden girilmesi gerekir |

`backend/.env` dosyasını commit'lemeyin; `.gitignore` içinde zaten tanımlıdır.

### Çalıştırma

1. Backend'i başlatın (`backend/` klasöründe, sanal ortam aktifken):

   ```bash
   python app.py
   ```

   API `http://127.0.0.1:5000` adresinde, debugger kapalı olarak çalışır. `SECRET_KEY` tanımlı değilse ilk açılışta `backend/instance/secret_key` oluşturulur; eski sürümlerin sabit anahtarla şifrelediği AI key'leri otomatik olarak yeni anahtarla yeniden şifrelenir.

2. İkinci bir terminalde frontend'i depo kök dizininden servis edin:

   ```bash
   python -m http.server 8000
   ```

3. `http://localhost:8000` (veya `http://127.0.0.1:8000`) adresini açın. Frontend backend'i otomatik algılar. İlk açılışta bir parola belirlemeniz istenir; sonrasında giriş yaparsınız.

Yalnızca checklist kullanılacaksa 1. adım atlanabilir; ilerleme bu durumda `localStorage`'da tutulur ve giriş gerekmez.

### Kimlik Doğrulama

Backend tek kullanıcılıdır ve parola ile korunur.

- **İlk parola.** Arayüz ilk açıldığında en az 12 karakterlik bir parola ister. Bu ekran yalnızca API'nin çalıştığı bilgisayardan (loopback adresi) çalışır; böylece ağdaki biri çalışma alanını sizden önce sahiplenemez. Ekransız ya da uzak bir kurulumda terminalden `python app.py set-password` ile belirleyin.
- **Giriş.** Oturum, Flask'ın imzalı session çerezi `wstg_session`'dır (`HttpOnly`, `SameSite=Strict`) ve girişten itibaren 12 saat geçerlidir. Çerez yoksa `/api` altındaki her uç `401` döner; açık kalanlar yalnızca `/api/auth/status`, `/api/auth/setup`, `/api/auth/login` ve `/api/auth/logout`'tur. Oturum düşünce arayüz giriş ekranına döner.
- **Saklama.** Yalnızca tuzlanmış hash (`werkzeug.security`) `auth_settings` tablosunda saklanır. Tablo açılışta otomatik oluşturulur; mevcut verilere dokunulmaz.
- **Hatalı denemeler.** Aynı adresten 5 hatalı denemeden sonra giriş 30 saniye kilitlenir; süre her seferinde ikiye katlanarak en fazla 15 dakikaya çıkar. Sayaç bellekte tutulur, backend yeniden başlayınca sıfırlanır.
- **Parola değiştirme / çıkış.** İkisi de kenar çubuğundadır. Parola değişince diğer tüm tarayıcılardaki oturumlar kapanır; mevcut oturum devam eder.
- **Parolayı unuttuysanız.** `backend/` içinde `python app.py set-password` çalıştırın (backend'i durdurmanız gerekmez). Parola iki kez sorulur, argüman olarak verilmez. Açık tüm oturumlar kapanır.
- **localhost ve 127.0.0.1.** Tarayıcılar bunları farklı site sayar; bu yüzden frontend API'yi sayfanın açıldığı host üzerinden çağırır (`127.0.0.1:8000` → `127.0.0.1:5000`, `localhost:8000` → `localhost:5000`). Her adres için ayrı giriş gerekir.

**Güncelleme.** Bu sürümden sonra backend giriş ister. Arayüzü API'nin çalıştığı bilgisayarda açıp parola belirleyin ya da `python app.py set-password` çalıştırın. Projeler, bulgular ve kanıtlar olduğu gibi kalır.

### Proje Klasör Yapısı

```
WSTG-Copilot/
├── index.html                  # Tek sayfalık frontend
├── css/style.css               # Stiller
├── js/
│   ├── app.js                  # Uygulama mantığı, i18n, API istemcisi, AI/BYOK panelleri
│   ├── auth.js                 # API adresi seçimi ve kimlik doğrulama hata kodları
│   ├── cvss.js                 # CVSS v3.1 hesaplayıcı
│   └── import-parsers.js       # Nmap / Nikto / WPScan ayrıştırıcıları
├── data/
│   ├── wstg-checklist.{tr,en}.json
│   ├── owasp-top10.{tr,en}.json
│   └── llm-security-checklist.{tr,en}.json
├── backend/
│   ├── app.py                  # Flask REST API
│   ├── models.py               # SQLAlchemy modelleri
│   ├── config.py               # Ortam değişkenlerinden yapılandırma
│   ├── auth.py                 # Parola hash'i, parola kuralı, deneme sınırı
│   ├── security.py             # Yalnızca-yerel varsayılanlar (host, debug, CORS, Origin/Host kontrolleri)
│   ├── ai/                     # Sağlayıcı katmanı (factory + Anthropic/OpenAI/Gemini/Ollama)
│   ├── ai_report_assistant.py  # Açıklama / remediation / yeniden yazım / özet prompt'ları
│   ├── finding_analysis.py     # AI CWE / önem / CVSS önerisi
│   ├── next_test_suggestion.py # AI sonraki test önerisi
│   ├── evidence_intel.py       # Opsiyonel AI ekran görüntüsü analizi
│   ├── recon.py                # Attack Surface Discovery
│   ├── tool_runner.py          # İzin listeli dış araç çalıştırma
│   ├── attack_chains.py        # Kural tabanlı saldırı zinciri korelasyonu
│   ├── duplicate_detector.py   # Tekrar eden bulgu tespiti
│   ├── redaction.py            # Gizli bilgi / kişisel veri maskeleme
│   ├── crypto_utils.py         # Saklanan key'ler için Fernet şifreleme
│   ├── mapping.py              # WSTG ↔ OWASP Top 10 ↔ CWE indeksi
│   ├── cvss.py                 # CVSS v3.1 skorlama
│   ├── report_builder.py       # Proje DOCX raporları
│   ├── report_html.py          # HTML rapor
│   ├── report_pdf.py           # PDF rapor
│   ├── report_generator.py     # Oturum bazlı raporlar
│   ├── test_*.py               # Testler
│   ├── .env.example
│   └── requirements.txt
├── wstg-v4_2.pdf               # OWASP WSTG v4.2 kılavuzu
└── LICENSE
```

### Katkıda Bulunma

1. Depoyu fork'layın ve `main` dalından yeni bir dal açın.
2. Değişikliklerinizi yapın; frontend'i framework ve build adımı gerektirmeyecek şekilde tutun.
3. İlgili testleri `backend/` klasöründen çalıştırın, örneğin:

   ```bash
   python test_finding_analysis.py
   python test_ai_layer.py
   ```

4. Değişikliği açıklayan bir pull request açın.

Hata bildirimleri ve öneriler için GitHub issue açabilirsiniz.

### Sorumluluk Reddi

Bu araç yalnızca **yetkilendirilmiş** güvenlik testleri ve eğitim amaçlı kullanım içindir. Sahibinin açık izni olmayan sistemleri test etmek yasa dışıdır. Recon ve Tool Runner yalnızca sizin belirttiğiniz hedeflere karşı çalışır ve yetki onayı ister. Projenin kullanımından doğan sorumluluk kullanıcıya aittir.

### Lisans

[MIT Lisansı](LICENSE) ile yayınlanmıştır.

Test içerikleri [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/), [OWASP Top 10:2025](https://owasp.org/Top10/2025/) ve OWASP LLM Top 10 esas alınarak hazırlanmıştır.
