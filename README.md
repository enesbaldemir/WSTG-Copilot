# 🛡️ Pentest Workspace — OWASP WSTG v4.2

![Made with HTML/CSS/JS](https://img.shields.io/badge/stack-HTML%20%7C%20CSS%20%7C%20JS-informational)
![Backend](https://img.shields.io/badge/backend-Flask%20%2B%20SQLite-lightgrey)
![AI](https://img.shields.io/badge/AI-multi--provider%20%2B%20BYOK-8b5cf6)
![License](https://img.shields.io/badge/license-MIT-green)

**🇬🇧 [English](#-english)** · **🇹🇷 [Türkçe](#-türkçe)**

---

## 🇬🇧 English

A full pentest **engagement workspace** built around the **OWASP Web Security Testing Guide (WSTG) v4.2** — not just a checklist anymore. It covers an entire assessment lifecycle: scope & attack-surface discovery, a WSTG-driven test plan, professional CVSS-scored findings, evidence collection (screenshots + raw HTTP with automatic secret redaction), attack-chain correlation, a Kanban board, and DOCX/HTML report generation — with optional, pluggable AI assistance at every step.

The checklist itself still works with **zero setup** (just open `index.html`), but the full experience (Projects, findings, evidence, reports, AI) needs the small Flask + SQLite backend described below.

### ✨ Features

**Checklist core**
- **98 WSTG test items** across 12 categories (Information Gathering, Configuration Management, Identity Management, Authentication, Authorization, Session Management, Input Validation, Error Handling, Cryptography, Business Logic, Client-Side, API Testing)
- Each test includes a **description, step-by-step testing instructions, example payload/command, and recommended tools**
- 🧩 **Alternate framework**: switch the whole checklist to the **OWASP LLM Top 10 (AI Security)** checklist (10 categories / 21 test items) from the sidebar — useful when the target under test is an LLM-backed application
- 🛡️ **OWASP Top 10:2025 reference module** — all ten risk categories with description, how it happens, step-by-step guidance, example attack scenario/payload, prevention checklist, mapped CWEs and tools, cross-linked to the matching WSTG items
- ✅ Custom test items — add your own project-specific checklist entries alongside the official WSTG ones
- 🔍 Global search across categories/test items, 📊 dashboard with progress stats, 🌐 Turkish/English UI, 🎨 25 built-in themes, 📱 responsive, 📎 bundled WSTG v4.2 PDF

**Project / Engagement management (backend required)**
- 📁 **Projects** — group everything (scope, sessions, recon, findings, evidence, timeline, reports) under a named engagement (client, description, status, start/end dates)
- 🎯 **Scope management** — declare in-scope/out-of-scope domains, subdomains, IPs and CIDR ranges per project
- 🕸️ **Attack Surface Discovery (Recon)** — run passive/active recon against a declared, authorized target (subdomain enumeration, HTTP probing, tech fingerprinting via `subfinder` / `httpx` / `whatweb` / `dnsx` / `nmap` if installed on the server) and get discovered assets automatically mapped to relevant WSTG test IDs with a priority score, plus SSRF-safe target validation. **Scan results persist**: reopening the panel (or switching back into the same project/session) shows your last scan instead of forcing a re-scan; a "Reset / Re-scan" action lets you start over deliberately when you point it at a new target. Priority badges and the Test Planner are scoped per project/session, so switching or deleting one no longer leaks another's stale results.
- 🧰 **Tool Runner** — run a small allow-listed set of external recon tools directly from the UI, with a command preview before execution and a run history per project
- 📋 **Test Planner** — a rule-based, fully transparent priority queue: WSTG items are ranked by recon evidence + methodology order (no black-box AI scoring), each suggestion shows *why* it's ranked there
- 🤖 **AI: What's Next?** — a complementary, AI-reasoned suggestion for your next test, based on what you've completed and found so far. Unlike the Test Planner it needs no recon evidence and uses AI judgment instead of fixed rules, so it's always a draft to sanity-check, with alternate candidates shown alongside the primary suggestion
- 📥 **Import external findings** — parse Nmap / Nikto / WPScan output (XML/JSON) and turn matches into findings linked to the right WSTG items

**Findings**
- 🧾 **Professional findings** with title, description, affected endpoint, remediation, **CVSS v3.1 calculator** (interactive vector builder with live score), CWE mapping, and severity
- 🪞 **Duplicate detection** — new/edited findings are checked against existing ones in the project (title/description/endpoint/CWE similarity) with a merge-or-create-anyway prompt
- 🔗 **Attack Chain / Finding Correlation Engine** — matches your recorded findings against known attack-chain patterns (e.g. User Enumeration → Weak Authentication → Account Takeover) using fixed, auditable rules — no AI call involved
- 🗂️ **Kanban board** — drag findings/test results through To Do → In Progress → Review → Done, with assignee/severity/test-ID filters

**Evidence**
- 🖼️ Screenshot evidence upload (PNG/JPEG/WebP/GIF), stored under server-generated UUID filenames (never the user's original filename, to prevent path traversal)
- 🌐 Raw HTTP request/response evidence, with **automatic secrets/PII redaction** (Authorization headers, cookies, JWTs, common API key formats, private keys, emails, card-like numbers) shown by default — raw text requires an explicit "show raw" action
- 🤖 Optional AI Vision analysis of screenshots (Anthropic Claude) that suggests relevant WSTG test IDs — entirely opt-in, validated against the real WSTG dataset so it can't hallucinate a test ID, and never auto-attaches to a finding without your Accept

**Reporting**
- 📄 **Three DOCX report templates** — *Technical* (full detail for pentesters/QA), *Executive* (management-level summary and risk posture), *Developer* (finding-by-finding "Problem / Why it matters / How to fix")
- 🖨️ **Self-contained HTML report** — single file, no external CDN/script dependencies, with a built-in "Print / Save as PDF" button (no server-side PDF library required)
- 📑 **One-click downloadable PDF report** — a real, ready-to-send `.pdf` file generated server-side (cover page, executive summary, risk breakdown, per-finding detail, appendices, running footer with page numbers) via the pure-Python `xhtml2pdf` library, so it works out of the box on Windows/Mac/Linux with no GTK, Cairo, or `wkhtmltopdf` install required. Full Turkish character support (ğ/ş/ı/İ/ö/ü/ç) via an embedded font
- ✅ **Pick exactly which findings go in the report** — "All", "Critical + High only", or hand-pick individual findings from a checklist, for both the HTML and PDF report
- ✍️ Optional AI-generated executive summary draft that you review before it's included

**AI Assistance — multi-provider, bring-your-own-key**
- 🔌 Works with **Anthropic (Claude), OpenAI, Google Gemini, or a local Ollama model** — you choose the provider
- 🔑 **AI Settings** (shared/default) — store an encrypted API key per provider for the whole installation, pick which one is active, and test the connection before relying on it
- 🔐 **"Use Your Own API Key" (BYOK)** — a separate, distinctly-styled panel (top bar) lets *any* user of a shared deployment plug in their **own** API key for their **own session only**. It's kept in the browser's `sessionStorage`, never sent to be stored on the server, and is automatically discarded when the tab closes — it simply overrides the shared setting for that user's requests
- Used for: finding description/remediation drafting, CWE/severity/CVSS suggestions, professional rewriting, "what should I test next" suggestions, executive summary drafts, and optional evidence screenshot triage — all of it is a *draft you review*, never something silently written to the database
- Every AI call (success or failure) is logged (provider, model, latency, purpose) for auditability via `/api/ai/logs`

**Named test sessions (works with or without a Project)**
- 🗄️ Group a pentest run under a named session (name, tester, target URL); every checkbox is persisted to SQLite and can be resumed later
- Falls back automatically to `localStorage`-only mode if the backend isn't reachable — nothing breaks

### 🖥️ Overview

The sidebar gives you category navigation plus quick access to Projects, Test Sessions, Attack Surface Discovery, Test Planner, Import, AI Settings, and your own BYOK key panel. Opening a Project takes you into a full workspace with tabs for Overview, Scope, Assets, Recon, Tools, Test Plan, WSTG Tests, Findings, Evidence, Attack Chains, Timeline, Kanban and Reports.

### 📂 Project Structure

```
WSTG-Copilot/
├── index.html                       # Main HTML file
├── css/
│   └── style.css                    # All styles, themes, and BYOK/AI panel styling
├── js/
│   ├── app.js                       # App logic (state, rendering, i18n, themes, projects, AI, BYOK…)
│   ├── cvss.js                      # CVSS v3.1 vector calculator
│   └── import-parsers.js            # Nmap/Nikto/WPScan output parsers
├── data/
│   ├── wstg-checklist.{tr,en}.json        # WSTG v4.2 test data
│   ├── owasp-top10.{tr,en}.json           # OWASP Top 10:2025 reference data
│   └── llm-security-checklist.{tr,en}.json # Alternate OWASP LLM Top 10 checklist
├── backend/                          # Flask + SQLite API
│   ├── app.py                        # REST API — sessions, projects, recon, findings, evidence,
│   │                                  # attack chains, kanban, reports, AI endpoints
│   ├── models.py                     # SQLAlchemy models (Project, ScopeItem, TimelineEvent,
│   │                                  # Finding, ToolRun, CustomTest, Evidence, ReconRun,
│   │                                  # Session, TestResult, AIInteractionLog, AIProviderSetting)
│   ├── ai/                           # Multi-provider AI layer
│   │   ├── factory.py                 # Provider resolution: BYOK header → DB setting → .env
│   │   ├── base.py, anthropic_provider.py, openai_provider.py,
│   │   │   gemini_provider.py, ollama_provider.py
│   ├── ai_report_assistant.py        # Finding description/remediation/rewrite prompts
│   ├── finding_analysis.py           # AI CWE/severity/CVSS suggestion for a finding
│   ├── next_test_suggestion.py       # AI "what to test next" suggestion
│   ├── evidence_intel.py             # Optional AI vision analysis of evidence screenshots
│   ├── recon.py                      # Attack Surface Discovery (SSRF-safe recon orchestration)
│   ├── tool_runner.py                # Allow-listed external tool execution (nmap/httpx/…)
│   ├── attack_chains.py              # Rule-based attack-chain correlation (no AI)
│   ├── duplicate_detector.py         # difflib-based duplicate finding detection
│   ├── redaction.py                  # Secrets/PII redaction for HTTP evidence
│   ├── crypto_utils.py               # Fernet encryption for stored AI provider keys
│   ├── mapping.py                    # WSTG ↔ OWASP Top 10 ↔ CWE lookup index
│   ├── cvss.py                       # CVSS v3.1 vector parsing/scoring
│   ├── report_builder.py             # DOCX reports (technical/executive/developer)
│   ├── report_html.py                # Self-contained HTML report
│   ├── report_pdf.py                 # Downloadable PDF report (xhtml2pdf, embedded Unicode font)
│   ├── report_generator.py           # Session-level report data/markdown/docx (legacy-compatible)
│   ├── config.py                     # Config (DB path, CORS, AI defaults, timeouts)
│   ├── .env.example                  # All optional environment variables, documented
│   └── requirements.txt
├── wstg-v4_2.pdf                     # Original OWASP WSTG v4.2 guide
└── LICENSE
```

### 🚀 Getting Started

**Checklist only, no backend:**
```bash
python3 -m http.server 8000   # or: npx serve .
```
Then open `http://localhost:8000`. Progress is saved to `localStorage` only.

**Full workspace (Projects, findings, evidence, reports, AI) — run the backend:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # optional — see below for what each variable does
python3 app.py
```
The API runs on `http://localhost:5000` and creates `backend/database/wstg.db` (SQLite) on first run. Serve the frontend as above — it auto-detects the backend.

Recon and the Tool Runner rely on external binaries (`nmap`, `subfinder`, `httpx`, `whatweb`, `dnsx`) being installed and on your `PATH`; if a tool isn't available, that specific action is skipped/reported as unavailable rather than failing the whole request.

### 🔑 AI Configuration

You don't need to touch `.env` at all — the in-app **AI Settings** panel (🔑, sidebar) lets you add, test, and activate a provider (Anthropic / OpenAI / Gemini / Ollama) from the UI; keys are encrypted at rest and never shown in full.

If you're running a shared/deployed instance, each visitor can instead open **"My Own Key"** (top bar, 🔐) and plug in their **personal** API key for their **own session** — it lives only in the browser and is never persisted server-side, so a shared installation doesn't force everyone to share (or pay for) the same key.

`.env` values are only a fallback for headless/CI/Docker setups without a UI — see `backend/.env.example` for the full list (`AI_PROVIDER`, `*_API_KEY`, `*_MODEL`, `OLLAMA_BASE_URL`, `ENCRYPTION_KEY`, etc).

### 🎨 Theme System

Click **Theme** in the sidebar to choose from 25 built-in themes (Dark/Neon, Nature/Calm, Bold/Dramatic, Light/Elegant). Your pick is saved to `localStorage`. To add a new one: add an entry to `THEMES` in `js/app.js` and a matching `[data-theme="id"]{ ... }` block in `css/style.css`.

### 🌐 Language Support

Switch Turkish/English from the sidebar. UI strings live in the `I18N` object in `js/app.js`; checklist content lives in the `data/*.json` files.

### 💾 Local Storage Keys (no-backend / no-session mode)

| Key | Content |
|---|---|
| `wstg_progress_v1` | Completed test IDs (local/no-session mode only) |
| `wstg_lang_v1` | Selected language |
| `wstg_theme_v1` | Selected theme |
| `wstg_session_id_v1` | Active DB session ID, if any |
| `wstg_skip_session_v1` | Remembers "continue without a session" choice |
| `wstgAiByok` *(sessionStorage)* | Your personal BYOK provider/key/model for this browser tab only — never sent to the server for storage |

### 🛠️ Tech Stack

- Vanilla **HTML5 / CSS3 / JavaScript** — no framework, no build step
- **Flask + SQLAlchemy + SQLite** backend
- `python-docx` for DOCX report generation, `xhtml2pdf` (pure Python) for downloadable PDF reports, `cryptography` (Fernet) for at-rest AI key encryption
- Pluggable AI layer supporting Anthropic, OpenAI, Gemini, and Ollama
- [Inter](https://fonts.google.com/specimen/Inter) font (Google Fonts)

### 📖 Source

Test items are based on the [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/) and the [OWASP Top 10:2025](https://owasp.org/Top10/2025/) / OWASP LLM Top 10 references.

### ⚠️ Disclaimer

This tool is for **authorized** security testing (pentesting) only, for educational and reference purposes. Testing systems you do not own or do not have explicit written permission to test is illegal. Recon and the Tool Runner only ever target what you explicitly point them at and require you to confirm authorization — the app never runs anything on its own or against a third party. You are solely responsible for how you use this project.

### 📄 License

Licensed under the [MIT License](LICENSE). Use, modify, and distribute freely.

---

## 🇹🇷 Türkçe

**OWASP Web Security Testing Guide (WSTG) v4.2** temelli, artık sadece bir checklist değil, uçtan uca bir **pentest çalışma alanı (engagement workspace)**. Kapsam & saldırı yüzeyi keşfinden, WSTG odaklı test planına, profesyonel CVSS puanlı bulgulara, kanıt toplamaya (ekran görüntüsü + otomatik gizli-bilgi redaksiyonlu ham HTTP), saldırı zinciri korelasyonuna, bir Kanban tahtasına ve DOCX/HTML rapor üretimine kadar tüm süreci kapsar — her adımda opsiyonel, takılıp çıkarılabilir AI desteğiyle.

Checklist'in kendisi **hiçbir kurulum gerektirmeden** çalışır (`index.html`'i açmanız yeterli), ama tam deneyim (Projeler, bulgular, kanıtlar, raporlar, AI) için aşağıda anlatılan küçük Flask + SQLite backend'i gerekir.

### ✨ Özellikler

**Checklist çekirdeği**
- **12 kategoride 98 WSTG test maddesi** (Bilgi Toplama, Konfigürasyon ve Dağıtım Yönetimi, Kimlik Yönetimi, Kimlik Doğrulama, Yetkilendirme, Oturum Yönetimi, Girdi Doğrulama, Hata Yönetimi, Kriptografi, İş Mantığı, İstemci Taraflı Testler, API Testleri)
- Her testte **açıklama, adım adım test talimatı, örnek payload/komut ve önerilen araçlar**
- 🧩 **Alternatif framework**: sidebar'dan tüm checklist'i **OWASP LLM Top 10 (AI Security)** checklist'ine (10 kategori / 21 test maddesi) çevirebilirsiniz — hedef bir LLM tabanlı uygulama olduğunda kullanışlı
- 🛡️ **OWASP Top 10:2025 referans modülü** — 10 risk kategorisinin tamamı; açıklama, nasıl ortaya çıktığı, adım adım rehber, örnek saldırı senaryosu/payload, önlem kontrol listesi, ilişkili CWE'ler ve araçlar, eşleşen WSTG maddelerine bağlantılarla
- ✅ Özel test maddeleri — resmi WSTG maddelerinin yanına projeye özel kendi checklist kalemlerinizi ekleyin
- 🔍 Kategoriler/testler genelinde global arama, 📊 ilerleme istatistikli dashboard, 🌐 Türkçe/İngilizce arayüz, 🎨 25 hazır tema, 📱 responsive tasarım, 📎 dahili WSTG v4.2 PDF

**Proje / Engagement yönetimi (backend gerekir)**
- 📁 **Projeler** — kapsam, oturumlar, recon, bulgular, kanıtlar, zaman çizelgesi ve raporların tamamını isimli bir engagement altında toplayın (müşteri, açıklama, durum, başlangıç/bitiş tarihi)
- 🎯 **Kapsam (Scope) yönetimi** — proje bazında kapsam içi/dışı domain, subdomain, IP ve CIDR aralıkları tanımlayın
- 🕸️ **Attack Surface Discovery (Recon)** — tanımlanmış, yetkilendirilmiş bir hedefe karşı pasif/aktif recon çalıştırın (sunucuda kuruluysa `subfinder` / `httpx` / `whatweb` / `dnsx` / `nmap` ile subdomain keşfi, HTTP probe, teknoloji parmak izi) ve bulunan varlıkların otomatik olarak ilgili WSTG test ID'leriyle önceliklendirilmiş şekilde eşleştirilmesini sağlayın; SSRF'ye karşı hedef doğrulaması dahildir. **Tarama sonuçları kalıcıdır**: paneli tekrar açtığınızda (ya da aynı proje/oturuma geri döndüğünüzde) yeniden taramaya gerek kalmadan son taramanız gösterilir; yeni bir hedefe geçmek istediğinizde bilinçli olarak "Sıfırla / Yeniden Tara" ile başlayabilirsiniz. Öncelik rozetleri ve Test Planı artık proje/oturum bazında ayrıştırılır, böylece birini değiştirmek/silmek başka birinin eski verisini sızdırmaz.
- 🧰 **Tool Runner** — izin listesindeki küçük bir dış araç setini (nmap, httpx, whatweb, subfinder, dnsx) doğrudan arayüzden, çalıştırmadan önce komut önizlemesiyle ve proje bazlı çalıştırma geçmişiyle kullanın
- 📋 **Test Planı (Planner)** — kural tabanlı, tamamen şeffaf bir öncelik kuyruğu: WSTG maddeleri recon kanıtı + metodoloji sırasına göre sıralanır (kara kutu AI skorlaması yok), her öneri "neden orada" olduğunu gösterir
- 🤖 **AI: Sırada Ne Var?** — Test Planı'nı tamamlayan, AI akıl yürütmesine dayalı bir öneri: tamamladığınız testlere ve bulduğunuz bulgulara bakarak bir sonraki adımı gerekçesiyle önerir. Test Planı'ndan farkı: recon kanıtı gerekmez, sabit kural yerine AI kullanır — bu yüzden her zaman gözden geçirilmesi gereken bir taslaktır; ana önerinin yanında alternatif adaylar da gösterilir
- 📥 **Dış bulgu içe aktarma** — Nmap / Nikto / WPScan çıktısını (XML/JSON) ayrıştırıp eşleşmeleri ilgili WSTG maddelerine bağlı bulgulara dönüştürün

**Bulgular**
- 🧾 **Profesyonel bulgular** — başlık, açıklama, etkilenen endpoint, remediation, **CVSS v3.1 hesaplayıcı** (canlı skorlu interaktif vektör oluşturucu), CWE eşlemesi ve önem derecesi
- 🪞 **Tekrar (duplicate) tespiti** — yeni/düzenlenen bulgular projedeki mevcut bulgularla (başlık/açıklama/endpoint/CWE benzerliği) karşılaştırılır, birleştir ya da yine de oluştur seçeneği sunulur
- 🔗 **Saldırı Zinciri / Bulgu Korelasyon Motoru** — kayıtlı bulgularınızı bilinen saldırı zinciri kalıplarıyla (ör. Kullanıcı Numaralandırma → Zayıf Kimlik Doğrulama → Hesap Ele Geçirme) sabit, denetlenebilir kurallarla eşleştirir — hiçbir AI çağrısı içermez
- 🗂️ **Kanban panosu** — bulgu/test sonuçlarını Yapılacak → Devam Ediyor → İnceleme → Tamamlandı arasında taşıyın; atanan kişi/önem/test-ID filtreleriyle

**Kanıtlar (Evidence)**
- 🖼️ Ekran görüntüsü kanıtı yükleme (PNG/JPEG/WebP/GIF), diskte her zaman sunucu tarafında üretilen UUID dosya adlarıyla saklanır (kullanıcının orijinal dosya adı asla kullanılmaz — path traversal'a karşı)
- 🌐 Ham HTTP request/response kanıtı, **otomatik gizli bilgi/PII redaksiyonu** ile (Authorization header'ları, cookie'ler, JWT'ler, yaygın API key formatları, private key'ler, e-postalar, kart benzeri numaralar) varsayılan olarak gösterilir — ham metni görmek için açıkça "ham metni göster" demeniz gerekir
- 🤖 Ekran görüntülerinde opsiyonel AI Vision analizi (Anthropic Claude) ilgili WSTG test ID'lerini önerir — tamamen opsiyoneldir, gerçek WSTG veri setine karşı doğrulanır (uydurma bir ID öneremez) ve siz Accept demeden hiçbir bulguya otomatik bağlanmaz

**Raporlama**
- 📄 **Üç DOCX rapor şablonu** — *Technical* (pentester/QA için tam detay), *Executive* (yönetim için üst düzey özet ve risk duruşu), *Developer* (bulgu bazında "Problem / Neden Önemli / Nasıl Düzeltilir")
- 🖨️ **Kendi kendine yeten HTML rapor** — tek dosya, harici CDN/script bağımlılığı yok, dahili "Yazdır / PDF olarak kaydet" butonuyla (sunucu tarafı PDF kütüphanesi gerekmez)
- 📑 **Tek tıkla indirilebilir gerçek PDF rapor** — kapak sayfası, yönetici özeti, risk dağılımı, bulgu bazında detay, ekler ve sayfa numaralı alt bilgi içeren, sunucu tarafında saf Python `xhtml2pdf` kütüphanesiyle üretilen, doğrudan gönderilebilir bir `.pdf` dosyası. GTK, Cairo ya da `wkhtmltopdf` kurulumu gerekmediği için Windows/Mac/Linux'ta ekstra adım olmadan çalışır. Gömülü font sayesinde Türkçe karakterler (ğ/ş/ı/İ/ö/ü/ç) tam destekli
- ✅ **Rapora hangi bulguların gireceğini siz seçin** — "Tümü", "Sadece Kritik + Yüksek" ya da checklist'ten tek tek işaretleyerek seçtiğiniz bulgular; hem HTML hem PDF rapor için geçerlidir
- ✍️ Siz gözden geçirmeden rapora eklenmeyen, opsiyonel AI destekli yönetici özeti taslağı

**AI Desteği — çoklu sağlayıcı, kendi key'ini getir (BYOK)**
- 🔌 **Anthropic (Claude), OpenAI, Google Gemini veya yerel bir Ollama modeliyle** çalışır — sağlayıcıyı siz seçersiniz
- 🔑 **AI Ayarları** (paylaşılan/varsayılan) — kurulumun tamamı için sağlayıcı bazında şifreli bir API key saklayın, hangisinin aktif olacağını seçin, güvenmeden önce bağlantıyı test edin
- 🔐 **"Kendi API Key'inle Kullan" (BYOK)** — üst çubukta ayrı, kendine özgü tasarımlı bir panel; paylaşılan bir kurulumdaki *herhangi bir kullanıcı*, **sadece kendi oturumu için** **kendi** API key'ini girebilir. Key tarayıcının `sessionStorage`'ında tutulur, sunucuya asla kaydedilmek üzere gönderilmez ve sekme kapanınca otomatik silinir — sadece o kullanıcının isteklerinde paylaşılan ayarın önüne geçer
- Kullanım alanları: bulgu açıklama/remediation taslağı, CWE/önem/CVSS önerisi, profesyonel yeniden yazım, "sırada ne test etmeliyim" önerisi, yönetici özeti taslağı, opsiyonel kanıt ekran görüntüsü ön analizi — hepsi *sizin gözden geçirdiğiniz bir taslaktır*, hiçbir şey sessizce veritabanına yazılmaz
- Her AI çağrısı (başarılı/başarısız) denetlenebilirlik için loglanır (sağlayıcı, model, gecikme, amaç) — `/api/ai/logs`

**İsimli test oturumları (Proje ile veya Proje olmadan çalışır)**
- 🗄️ Bir pentest sürecini isimli bir oturum altında toplayın (isim, test uzmanı, hedef URL); her işaretlediğiniz test SQLite'a kaydedilir ve daha sonra devam edilebilir
- Backend'e erişilemezse otomatik olarak sadece `localStorage` moduna döner — hiçbir şey bozulmaz

### 🖥️ Ekran Görünümü

Sidebar; kategori navigasyonunun yanında Projeler, Test Oturumları, Attack Surface Discovery, Test Planı, İçe Aktarma, AI Ayarları ve kendi BYOK key panelinize hızlı erişim sunar. Bir Projeyi açtığınızda; Overview, Scope, Assets, Recon, Tools, Test Plan, WSTG Tests, Findings, Evidence, Attack Chains, Timeline, Kanban ve Reports sekmelerinden oluşan tam bir çalışma alanına geçersiniz.

### 📂 Proje Yapısı

```
WSTG-Copilot/
├── index.html                       # Ana HTML dosyası
├── css/
│   └── style.css                    # Tüm stiller, temalar, BYOK/AI panel tasarımı
├── js/
│   ├── app.js                       # Uygulama mantığı (state, render, i18n, tema, projeler, AI, BYOK…)
│   ├── cvss.js                      # CVSS v3.1 vektör hesaplayıcı
│   └── import-parsers.js            # Nmap/Nikto/WPScan çıktı ayrıştırıcıları
├── data/
│   ├── wstg-checklist.{tr,en}.json        # WSTG v4.2 test verisi
│   ├── owasp-top10.{tr,en}.json           # OWASP Top 10:2025 referans verisi
│   └── llm-security-checklist.{tr,en}.json # Alternatif OWASP LLM Top 10 checklist'i
├── backend/                          # Flask + SQLite API
│   ├── app.py                        # REST API — oturumlar, projeler, recon, bulgular, kanıtlar,
│   │                                  # saldırı zincirleri, kanban, raporlar, AI uçları
│   ├── models.py                     # SQLAlchemy modelleri (Project, ScopeItem, TimelineEvent,
│   │                                  # Finding, ToolRun, CustomTest, Evidence, ReconRun,
│   │                                  # Session, TestResult, AIInteractionLog, AIProviderSetting)
│   ├── ai/                           # Çoklu sağlayıcılı AI katmanı
│   │   ├── factory.py                 # Sağlayıcı çözümü: BYOK header → DB ayarı → .env
│   │   ├── base.py, anthropic_provider.py, openai_provider.py,
│   │   │   gemini_provider.py, ollama_provider.py
│   ├── ai_report_assistant.py        # Bulgu açıklama/remediation/yeniden yazım prompt'ları
│   ├── finding_analysis.py           # Bulgu için AI CWE/önem/CVSS önerisi
│   ├── next_test_suggestion.py       # AI "sırada ne test edilmeli" önerisi
│   ├── evidence_intel.py             # Kanıt ekran görüntülerinin opsiyonel AI vision analizi
│   ├── recon.py                      # Attack Surface Discovery (SSRF-güvenli recon orkestrasyonu)
│   ├── tool_runner.py                # İzin listeli dış araç çalıştırma (nmap/httpx/…)
│   ├── attack_chains.py              # Kural tabanlı saldırı zinciri korelasyonu (AI yok)
│   ├── duplicate_detector.py         # difflib tabanlı tekrar eden bulgu tespiti
│   ├── redaction.py                  # HTTP kanıtı için gizli bilgi/PII redaksiyonu
│   ├── crypto_utils.py               # Saklanan AI sağlayıcı key'leri için Fernet şifreleme
│   ├── mapping.py                    # WSTG ↔ OWASP Top 10 ↔ CWE ilişki indeksi
│   ├── cvss.py                       # CVSS v3.1 vektör ayrıştırma/skorlama
│   ├── report_builder.py             # DOCX raporlar (technical/executive/developer)
│   ├── report_html.py                # Kendi kendine yeten HTML rapor
│   ├── report_pdf.py                 # İndirilebilir PDF rapor (xhtml2pdf, gömülü Unicode font)
│   ├── report_generator.py           # Oturum bazlı rapor verisi/markdown/docx (geriye dönük uyum)
│   ├── config.py                     # Ayarlar (DB yolu, CORS, AI varsayılanları, timeout'lar)
│   ├── .env.example                  # Tüm opsiyonel ortam değişkenleri, açıklamalı
│   └── requirements.txt
├── wstg-v4_2.pdf                     # Orijinal OWASP WSTG v4.2 kılavuzu
└── LICENSE
```

### 🚀 Kurulum ve Çalıştırma

**Sadece checklist, backend'siz:**
```bash
python3 -m http.server 8000   # ya da: npx serve .
```
Ardından `http://localhost:8000` adresini açın. İlerleme sadece `localStorage`'a kaydedilir.

**Tam çalışma alanı (Projeler, bulgular, kanıtlar, raporlar, AI) — backend'i çalıştırın:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # opsiyonel — her değişkenin ne işe yaradığı aşağıda
python3 app.py
```
API `http://localhost:5000` üzerinde çalışır ve ilk çalıştırmada `backend/database/wstg.db` (SQLite) dosyasını otomatik oluşturur. Frontend'i yukarıdaki gibi servis edin — backend'i otomatik algılayacaktır.

Recon ve Tool Runner, sunucunuzda kurulu ve `PATH`'te olan dış araçlara (`nmap`, `subfinder`, `httpx`, `whatweb`, `dnsx`) dayanır; bir araç mevcut değilse, tüm isteği başarısız kılmak yerine sadece o araca ait adım atlanır/kullanılamaz olarak raporlanır.

### 🔑 AI Yapılandırması

`.env` dosyasına hiç dokunmanıza gerek yok — uygulama içindeki **AI Ayarları** paneli (🔑, sidebar) bir sağlayıcı (Anthropic / OpenAI / Gemini / Ollama) eklemenizi, test etmenizi ve aktif etmenizi sağlar; key'ler şifreli saklanır ve hiçbir zaman tam olarak gösterilmez.

Paylaşılan/deploy edilmiş bir kurulum çalıştırıyorsanız, her ziyaretçi bunun yerine üst çubuktaki **"Kendi Key'im"** (🔐) panelini açıp **kendi** API key'ini **sadece kendi oturumu** için girebilir — key yalnızca tarayıcıda tutulur, sunucuya asla kaydedilmez; böylece paylaşılan bir kurulum herkesi aynı key'i paylaşmaya (ya da onun maliyetine) zorlamaz.

`.env` değerleri yalnızca arayüzsüz (headless/CI/Docker) kurulumlar için bir fallback'tir — tam liste için `backend/.env.example` dosyasına bakın (`AI_PROVIDER`, `*_API_KEY`, `*_MODEL`, `OLLAMA_BASE_URL`, `ENCRYPTION_KEY` vb.).

### 🎨 Tema Sistemi

Sidebar'daki **Tema** butonuna tıklayarak 25 hazır tema arasından seçim yapın (Koyu/Neon, Doğa/Sakin, Yoğun/Dramatik, Açık/Zarif). Seçiminiz `localStorage`'a kaydedilir. Yeni tema eklemek için: `js/app.js`'teki `THEMES` dizisine bir kayıt ve `css/style.css`'e karşılık gelen `[data-theme="id"]{ ... }` bloğu ekleyin.

### 🌐 Dil Desteği

Sidebar'dan Türkçe/İngilizce arasında geçiş yapın. Arayüz metinleri `js/app.js` içindeki `I18N` nesnesinde, checklist içeriği `data/*.json` dosyalarında tutulur.

### 💾 Yerel Depolama Anahtarları (backend'siz / oturumsuz mod)

| Anahtar | İçerik |
|---|---|
| `wstg_progress_v1` | Tamamlanan test ID'leri (yalnızca yerel/oturumsuz modda) |
| `wstg_lang_v1` | Seçili dil |
| `wstg_theme_v1` | Seçili tema |
| `wstg_session_id_v1` | Aktif DB oturumunun ID'si (varsa) |
| `wstg_skip_session_v1` | "Oturumsuz devam et" tercihini hatırlar |
| `wstgAiByok` *(sessionStorage)* | Sadece bu tarayıcı sekmesine ait kişisel BYOK sağlayıcı/key/model bilgisi — sunucuya kaydedilmek üzere asla gönderilmez |

### 🛠️ Kullanılan Teknolojiler

- Vanilla **HTML5 / CSS3 / JavaScript** — framework yok, build adımı yok
- **Flask + SQLAlchemy + SQLite** backend
- DOCX rapor üretimi için `python-docx`, saklanan AI key'lerinin şifrelenmesi için `cryptography` (Fernet)
- Anthropic, OpenAI, Gemini ve Ollama'yı destekleyen takılabilir AI katmanı
- [Inter](https://fonts.google.com/specimen/Inter) yazı tipi (Google Fonts)

### 📖 Kaynak

Test maddeleri [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/) ile [OWASP Top 10:2025](https://owasp.org/Top10/2025/) / OWASP LLM Top 10 referansları esas alınarak hazırlanmıştır.

### ⚠️ Sorumluluk Reddi

Bu araç yalnızca **yetkilendirilmiş** güvenlik testleri (pentest) için eğitim ve referans amaçlı hazırlanmıştır. Kendi sahibi olmadığınız veya yazılı izniniz bulunmayan sistemlere karşı test yapmak yasa dışıdır. Recon ve Tool Runner yalnızca sizin açıkça belirttiğiniz hedefe karşı çalışır ve yetkilendirmeyi onaylamanızı gerektirir — uygulama kendi başına ya da üçüncü bir tarafa karşı hiçbir şey çalıştırmaz. Bu projenin kullanımından doğacak sorumluluk tamamen kullanıcıya aittir.

### 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır. Dilediğiniz gibi kullanabilir, değiştirebilir ve dağıtabilirsiniz.

---

Contributions are welcome — feel free to open an issue or submit a pull request. ⭐
Katkıda bulunmak isterseniz bir issue açabilir veya pull request gönderebilirsiniz. ⭐
