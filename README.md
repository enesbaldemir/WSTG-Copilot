# 🛡️ Pentest Workspace — OWASP WSTG v4.2

![Made with HTML/CSS/JS](https://img.shields.io/badge/stack-HTML%20%7C%20CSS%20%7C%20JS-informational)
![Optional backend](https://img.shields.io/badge/backend-optional%20Flask%20%2B%20SQLite-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

**🇬🇧 [English](#-english)** · **🇹🇷 [Türkçe](#-türkçe)**

---

## 🇬🇧 English

An interactive, fully client-side pentest checklist application built on the **OWASP Web Security Testing Guide (WSTG) v4.2**. It walks you through every test item step by step, with descriptions, example payloads/commands, and recommended tools.

No installation, backend, or build step required — just open `index.html` in a browser.

### ✨ Features

- **98 WSTG test items** across 12 categories (Information Gathering, Configuration Management, Authentication, Input Validation, Business Logic, API Testing, and more)
- Each test includes a **description, step-by-step testing instructions, example payload/command, and recommended tools**
- ✅ **Progress tracking** — mark tests as done; saved locally in the browser's `localStorage` (nothing is sent to a server)
- 🔍 **Global search** — instantly search across categories and test items
- 📊 **Dashboard** — completed/pending test counts and per-category progress percentages
- 📄 **Report export** — download your progress as a `.txt` report
- 🌐 **Bilingual** — Turkish / English toggle
- 🎨 **25 built-in themes** — browse and pick from a preview gallery in a popup dialog (Midnight, Cyberpunk, Matrix, Dracula, Nord, Vaporwave, Neon Tokyo, Sakura, and more)
- 📱 Responsive design — works on both desktop and mobile
- 📎 One-click access to the original **WSTG v4.2 PDF**
- 🗄️ **Optional named test sessions saved to a database** — start a session with a name, tester, and target URL before testing; every checkbox is persisted to a Flask + SQLite backend and can be resumed later (falls back to the original `localStorage`-only mode automatically if the backend isn't running)
- 📓 **Notebook** — a dedicated, evidence-friendly note space per target: entries can be linked to a specific WSTG test item or kept as general notes, with drag/paste/upload screenshot attachments
- 🛡️ **OWASP Top 10:2025 reference module** — all ten risk categories with a description, how it happens, step-by-step pentest guidance, an example attack scenario/payload, prevention checklist, mapped CWEs, and recommended tools, cross-linked to the matching WSTG test items

### 🖥️ Overview

The app has a sidebar with category navigation plus language/theme settings, and a main dashboard with stat cards and category cards. Clicking a category opens a modal listing all of its test items.

### 📂 Project Structure

```
pentest-workspace/
├── index.html                     # Main HTML file
├── css/
│   └── style.css                  # All styles and theme definitions
├── js/
│   └── app.js                     # App logic (state, rendering, i18n, themes, sessions/DB)
├── data/
│   ├── wstg-checklist.tr.json     # Turkish test data
│   ├── wstg-checklist.en.json     # English test data
│   ├── owasp-top10.tr.json        # OWASP Top 10:2025 reference data (Turkish)
│   └── owasp-top10.en.json        # OWASP Top 10:2025 reference data (English)
├── backend/                        # Optional Flask + SQLite API for named test sessions
│   ├── app.py                      # REST API (sessions & test results)
│   ├── models.py                   # SQLAlchemy models
│   ├── config.py                   # Config (DB path, CORS)
│   └── requirements.txt
├── wstg-v4_2.pdf                  # Original OWASP WSTG v4.2 guide
└── assets/                        # (optional image assets)
```

### 🗄️ Named Test Sessions (Database)

You can now group each pentest run under a **named session** that gets saved to a real database, so you (or your team) can pause, come back, and resume progress later.

**How it works**

1. Start the backend (see below). On page load the app auto-detects it at `http://localhost:5000`.
2. If the backend is reachable, a **"Test Sessions"** screen appears. Create a new one by giving it a **name** (required), a tester name, and a target URL — or resume/delete a previous session.
3. Once a session is active, every checkbox you tick is saved to the database against that session (in addition to updating the UI instantly). You can switch sessions anytime from the **"Test Sessions"** sidebar button or the badge in the top bar.
4. If the backend isn't running, the app **automatically falls back** to the original `localStorage`-only behavior — nothing breaks, you just lose the multi-session/DB persistence until the backend is back up. You can also explicitly choose *"Continue without a session (local mode)"* even when the backend is online.

**Running the backend**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

The API runs on `http://localhost:5000` and creates `backend/database/wstg.db` (SQLite) automatically on first run. Then open `index.html` (ideally via a local server, see below) in your browser — it will detect the backend automatically.

**API summary**

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/api/sessions` | List / create sessions |
| GET/PUT/DELETE | `/api/sessions/<id>` | Read / update / delete a session |
| GET/POST | `/api/sessions/<id>/results` | List / add test results for a session |
| PUT/DELETE | `/api/sessions/<id>/results/<test_id>` | Update / delete a single test result |
| GET/POST | `/api/sessions/<id>/notes` | List / add notebook entries for a session |
| PUT/DELETE | `/api/sessions/<id>/notes/<note_id>` | Update / delete a single notebook entry |
| GET | `/api/sessions/<id>/report` | JSON summary report for a session (includes notes) |
| GET | `/api/ai/ping` | Verify the configured AI provider is reachable |
| GET | `/api/ai/logs` | List logged AI interactions (Phase 5 metrics) |
| POST | `/api/ai/analyze-finding` | AI-suggested CWE/severity/CVSS + false-positive assessment for a finding (does not modify any note) |
| POST | `/api/ai/suggest-next-test` | AI-suggested next WSTG test to run, based on completed tests + findings |
| GET | `/api/sessions/<id>/report/data` | Enriched report data (stats, findings with CVSS/CWE/OWASP) for a session |
| POST | `/api/sessions/<id>/report/summary` | AI-drafted executive summary (for review, not auto-applied) |
| POST | `/api/sessions/<id>/report/download` | Download the final report as `.md` or `.docx` |
| GET | `/api/study/metrics` | Per-session metrics + AI-assisted vs. control group comparison (Phase 5) |
| POST | `/api/cvss/calculate` | Calculate a CVSS 3.1 base score from a vector string |
| GET | `/api/mapping/wstg/<test_id>` | Related OWASP Top 10 categories + suggested CWEs for a WSTG test |


### 🤖 AI Integration (Roadmap)

This project is evolving into an **AI-assisted pentest decision-support system** built on top of the WSTG checklist foundation. The plan:

| Phase | Status | What it adds |
|---|---|---|
| 0 | ✅ Done | Pluggable AI provider layer (`backend/ai/`) supporting Gemini, OpenAI, Anthropic, and local Ollama; `/api/ai/ping` connectivity check; `AIInteractionLog` table logging every AI call (provider, latency, success/failure) |
| 1 | ✅ Done | Real CVSS 3.1 base-score calculator (`backend/cvss.py` + `js/cvss.js`, verified against published reference scores), CWE fields on findings, and a WSTG↔OWASP Top 10↔CWE relationship index (`backend/mapping.py`) built from the existing Top 10 data — surfaced in the notebook editor as a live CVSS vector builder and CWE auto-suggestions |
| 2 | ✅ Done | AI finding analysis (`backend/finding_analysis.py`) — sends a finding's title/content (plus its linked WSTG test + candidate CWEs as grounding context) to the configured LLM and gets back a suggested CWE, severity, CVSS vector, and a false-positive likelihood assessment with reasoning. The AI never overwrites a finding automatically — suggestions are shown in a review panel with per-field "Apply" buttons, and each suggested CWE is flagged as "grounded" (matches a known candidate) or the model's own inference, so you can gauge how much to trust it |
| 3 | ✅ Done | AI next-test suggestion (`backend/next_test_suggestion.py`) — given completed tests and current findings (sorted by severity), the AI recommends which pending WSTG test to run next, with reasoning, a priority level, and 1-3 alternatives. Suggested test IDs are validated against the real pending-test pool (`suggestion_grounded`), and when everything is already completed the AI isn't called at all. Surfaced via a "What's Next?" panel with a one-click "Go to This Test" that jumps straight to the suggested checklist item |
| 4 | ✅ Done | Automated report generation (`backend/report_generator.py`) — aggregates findings (sorted by severity/CVSS, enriched with their OWASP Top 10 category) into a downloadable **Markdown or Word (.docx)** report with a stats summary, per-finding technical detail, and a methodology appendix of completed tests. The AI can draft a plain-language executive summary, but it's shown in an editable box first — nothing goes into the final document until the pentester reviews and approves it |
| 5 | ✅ Done | Experimental A/B comparison module (`backend/study_metrics.py`) — sessions can be tagged **AI-Assisted** or **Control (Checklist Only)** at creation; control-group sessions have every AI feature (analysis, next-test suggestion, report drafting) hidden in the UI so the two conditions are genuinely comparable. Findings can be marked as confirmed valid or confirmed false-positive (ground truth, separate from the AI's own likelihood estimate). A "Study Metrics" dashboard aggregates and compares both groups — completion time, tests completed, findings count, false-positive rate, AI call volume/latency — with a per-metric % difference, ready to back a claim like *"the AI-assisted group finished X% faster and found Y% more findings."* |

**All 6 phases (0–5) are now complete.** The project has grown from a WSTG checklist tracker into what the README below calls it: an AI-assisted pentest decision-support system with a built-in (if small-scale) experimental evaluation framework.

**Configuring a provider**

```bash
cd backend
cp .env.example .env
# then edit .env — the free/no-credit-card option is Google Gemini:
# https://aistudio.google.com/apikey
```

By default `AI_PROVIDER=gemini`. Set it to `openai`, `anthropic`, or `ollama` (fully local, no API key, no rate limits — the best option for the Phase 5 experiment) instead — no other code changes needed. Verify it's working with:

```bash
curl http://localhost:5000/api/ai/ping
```

### 📓 Notebook

Every WSTG checklist item still has its own inline "Findings/Notes" box (with a severity picker) for quick, per-item notes — that hasn't changed. On top of that, there's now a dedicated **"Notebook"** section (sidebar → Notebook) for a more freeform, evidence-friendly way of tracking findings for the current target:

- Each entry has a **title**, a **severity**, free-text **content**, and can optionally be **linked to a specific WSTG test item** — or left as a **general note** not tied to any single item (e.g. an overall observation about the target).
- You can attach **evidence screenshots**: drag & drop, paste from the clipboard (Ctrl+V), or pick files. Click any thumbnail to view it full-size.
- From inside any checklist item's detail view, the **"🗒️ Add to notebook"** button opens the note editor pre-linked to that exact test item.
- The notebook list can be filtered by test item, or to general notes only.
- Like everything else in the app, notebook entries follow the same storage mode as your session: saved to the database when a named session is active (and included in `/api/sessions/<id>/report`), or kept in `localStorage` in local/no-session mode.

### 🛡️ OWASP Top 10:2025 Module

A dedicated **"OWASP Top 10:2025"** section (from the sidebar's Reference group) lists all ten current risk categories — A01 Broken Access Control through A10 Mishandling of Exceptional Conditions, including 2025's two new categories (Software Supply Chain Failures, Mishandling of Exceptional Conditions). Clicking a card opens a detail view with:

- Description and how the weakness typically arises
- Step-by-step pentest guidance for that risk
- A worked example attack scenario plus a copyable example payload/command
- A prevention checklist
- The most notable mapped CWEs and recommended tools
- Clickable links to the matching WSTG checklist items in this workspace, where they exist

This module is purely informational/reference content (no database persistence) and is available in both Turkish and English, generated from the official [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

### 🚀 Getting Started

No dependencies or build steps needed.

**1) Open directly**
Double-click `index.html` to open it in a browser. Note: some browsers restrict `fetch()` from reading local JSON files over the `file://` protocol, so a local server is recommended.

**2) Run with a local server (recommended)**

```bash
# Using Python
python3 -m http.server 8000

# or using Node.js
npx serve .
```

Then open `http://localhost:8000` in your browser.

### 🎨 Theme System

Click the **Theme** button in the sidebar to open a popup dialog and choose from 25 themes. Your selection is saved to `localStorage` and applied automatically on your next visit.

| Category | Example Themes |
|---|---|
| Dark / Neon | Cyberpunk, Neon Tokyo, Synthwave, Vaporwave, Matrix |
| Nature / Calm | Forest, Ocean, Aurora, Coral Reef, Nord |
| Bold / Dramatic | Blood Moon, Crimson, Toxic, Solar Flare, Deep Space |
| Light / Elegant | Arctic Light, Sakura, Rose Gold, Icefall |

To add a new theme:
1. Add a new entry to the `THEMES` array in `js/app.js`: `{ id, name, emoji, primary, secondary, desc: {tr, en} }`.
2. Define its color palette in `css/style.css` with a `[data-theme="theme-id"]{ ... }` block (use an existing theme as a template).

### 🌐 Language Support

Use the language selector under the sidebar to switch between **Turkish / English**. UI translations live in the `I18N` object in `js/app.js`; test data lives in `data/wstg-checklist.tr.json` and `data/wstg-checklist.en.json`.

### 💾 Data Storage

The app never sends data to a server. All progress, language, and theme preferences are stored only in your browser's `localStorage`:

| Key | Content |
|---|---|
| `wstg_progress_v1` | Completed test IDs (used only in local/no-session mode) |
| `wstg_lang_v1` | Selected language |
| `wstg_theme_v1` | Selected theme |
| `wstg_session_id_v1` | Currently active database session id (if any) |
| `wstg_skip_session_v1` | Remembers that you chose to continue without a session |

The "Reset Progress" button clears the relevant data (local progress, or all results of the active database session).

### 🛠️ Tech Stack

- Vanilla **HTML5 / CSS3 / JavaScript** (no framework, no build step)
- CSS Custom Properties (`--variables`) powering the theme engine
- `localStorage` for local-mode persistence
- Optional **Flask + SQLAlchemy + SQLite** backend for named, database-backed test sessions
- [Inter](https://fonts.google.com/specimen/Inter) font (Google Fonts)

### 📖 Source

Test items are based on the [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/).

### ⚠️ Disclaimer

This tool is intended for educational and reference purposes for **authorized** security testing (pentesting) only. Testing systems you don't own or don't have written permission to test is illegal. Use of this project is entirely at your own risk and responsibility.

### 📄 License

This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute it.

---

## 🇹🇷 Türkçe

OWASP **Web Security Testing Guide (WSTG) v4.2** tabanlı, tamamen istemci taraflı (client-side) çalışan interaktif bir pentest checklist uygulaması. Her test maddesini adım adım nasıl uygulayacağınızı, örnek payload/komutları ve önerilen araçları görerek ilerleyebileceğiniz bir çalışma alanı sunar.

Kurulum, backend veya derleme adımı gerektirmez — sadece `index.html` dosyasını bir tarayıcıda açmanız yeterlidir.

### ✨ Özellikler

- **98 WSTG test maddesi**, 12 ana kategoride (Bilgi Toplama, Konfigürasyon, Kimlik Doğrulama, Girdi Doğrulama, İş Mantığı, API Testleri vb.)
- Her test için **açıklama, nasıl test edilir adımları, örnek payload/komut ve önerilen araçlar**
- ✅ **İlerleme takibi** — tamamlanan testler işaretlenir, tarayıcının `localStorage`'ında saklanır (veri sunucuya gönderilmez)
- 🔍 **Global arama** — kategoriler ve test maddeleri arasında anlık arama
- 📊 **Dashboard** — tamamlanan/bekleyen test sayısı, kategori bazlı ilerleme yüzdeleri
- 📄 **Rapor dışa aktarma** — ilerleme durumunu `.txt` rapor olarak indirme
- 🌐 **Çift dil desteği** — Türkçe / İngilizce
- 🎨 **25 hazır tema** — açılır pencereden seçilebilen, önizlemeli tema galerisi (Midnight, Cyberpunk, Matrix, Dracula, Nord, Vaporwave, Neon Tokyo, Sakura ve daha fazlası)
- 📱 Duyarlı (responsive) tasarım — mobil ve masaüstünde çalışır
- 📎 Orijinal **WSTG v4.2 PDF**'ine tek tıkla erişim
- 🗄️ **Opsiyonel: isim verilerek DB'ye kaydedilen test oturumları** — teste başlamadan önce bir isim, test uzmanı ve hedef URL vererek oturum başlatın; işaretlediğiniz her test Flask + SQLite tabanlı backend'e kaydedilir ve daha sonra kaldığınız yerden devam edebilirsiniz (backend çalışmıyorsa uygulama otomatik olarak eski `localStorage` moduna döner)
- 📓 **Not Defteri** — her hedef için kanıt eklemeye uygun, ayrı bir not alanı: kayıtlar dilerseniz belirli bir WSTG test maddesine bağlanabilir ya da genel not olarak kalabilir; sürükle-bırak/yapıştır/yükle ile ekran görüntüsü eklenebilir
- 🛡️ **OWASP Top 10:2025 referans modülü** — 10 risk kategorisinin tamamı; açıklama, nasıl oluştuğu, adım adım pentest rehberi, örnek saldırı senaryosu/payload, önlem listesi, ilişkili CWE'ler ve önerilen araçlarla birlikte, ilgili WSTG test maddelerine çapraz bağlantılı olarak

### 🖥️ Ekran Görünümü

Uygulama, sol tarafta kategori navigasyonu ve tema/dil ayarları bulunan bir sidebar; sağ tarafta ise dashboard, istatistik kartları ve kategori kartlarının yer aldığı ana ekrandan oluşur. Bir kategoriye tıklandığında, o kategoriye ait test maddeleri açılır pencerede (modal) listelenir.

### 📂 Proje Yapısı

```
pentest-workspace/
├── index.html                     # Ana HTML dosyası
├── css/
│   └── style.css                  # Tüm stiller ve tema tanımları
├── js/
│   └── app.js                     # Uygulama mantığı (state, render, i18n, tema, oturum/DB)
├── data/
│   ├── wstg-checklist.tr.json     # Türkçe test verisi
│   ├── wstg-checklist.en.json     # İngilizce test verisi
│   ├── owasp-top10.tr.json        # OWASP Top 10:2025 referans verisi (Türkçe)
│   └── owasp-top10.en.json        # OWASP Top 10:2025 referans verisi (İngilizce)
├── backend/                        # Opsiyonel Flask + SQLite API (isimli test oturumları için)
│   ├── app.py                      # REST API (oturumlar & test sonuçları)
│   ├── models.py                   # SQLAlchemy modelleri
│   ├── config.py                   # Ayarlar (DB yolu, CORS)
│   └── requirements.txt
├── wstg-v4_2.pdf                  # Orijinal OWASP WSTG v4.2 kılavuzu
└── assets/                        # (opsiyonel görsel varlıklar)
```

### 🗄️ İsimli Test Oturumları (Veritabanı)

Artık her pentest sürecini **isim vererek** bir veritabanına kaydedebilir, kaldığınız yerden devam edebilirsiniz.

**Nasıl çalışır?**

1. Backend'i başlatın (aşağıya bakın). Sayfa açıldığında uygulama `http://localhost:5000` adresindeki backend'i otomatik olarak algılar.
2. Backend erişilebilirse karşınıza **"Test Oturumları"** ekranı gelir. Bir **isim** (zorunlu), test uzmanı adı ve hedef URL vererek yeni bir oturum başlatın; ya da önceki bir oturuma devam edin/silin.
3. Bir oturum aktifken işaretlediğiniz her test, arayüzü anında güncellemenin yanında o oturuma bağlı olarak veritabanına da kaydedilir. Sidebar'daki **"Test Oturumları"** butonundan veya üst çubuktaki rozetten istediğiniz zaman oturum değiştirebilirsiniz.
4. Backend çalışmıyorsa uygulama otomatik olarak eski **sadece `localStorage`** davranışına döner — hiçbir şey bozulmaz, sadece backend tekrar ayağa kalkana kadar çoklu oturum/DB kalıcılığını kaybedersiniz. Backend açık olsa bile isterseniz *"Oturumsuz / yerel modda devam et"* seçeneğiyle DB kullanmadan da devam edebilirsiniz.

**Backend'i çalıştırma**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

API `http://localhost:5000` üzerinde çalışır ve ilk çalıştırmada `backend/database/wstg.db` (SQLite) dosyasını otomatik oluşturur. Ardından `index.html`'i (tercihen aşağıdaki gibi yerel bir sunucu ile) tarayıcıda açın — backend'i otomatik algılayacaktır.

**API özeti**

| Metod | Endpoint | Açıklama |
|---|---|---|
| GET/POST | `/api/sessions` | Oturumları listele / yeni oturum oluştur |
| GET/PUT/DELETE | `/api/sessions/<id>` | Oturumu getir / güncelle / sil |
| GET/POST | `/api/sessions/<id>/results` | Oturuma ait test sonuçlarını listele / ekle |
| PUT/DELETE | `/api/sessions/<id>/results/<test_id>` | Tek bir test sonucunu güncelle / sil |
| GET/POST | `/api/sessions/<id>/notes` | Oturuma ait not defteri kayıtlarını listele / ekle |
| PUT/DELETE | `/api/sessions/<id>/notes/<note_id>` | Tek bir not defteri kaydını güncelle / sil |
| GET | `/api/sessions/<id>/report` | Oturum için JSON özet raporu (notlar dahil) |
| GET | `/api/ai/ping` | Yapılandırılan AI sağlayıcısına erişilebildiğini doğrular |
| GET | `/api/ai/logs` | Loglanan AI çağrılarını listeler (Faz 5 metrikleri) |
| POST | `/api/ai/analyze-finding` | Bir bulgu için AI destekli CWE/severity/CVSS önerisi + false-positive değerlendirmesi (hiçbir notu değiştirmez) |
| POST | `/api/ai/suggest-next-test` | Tamamlanan testler + bulgulara göre AI'nin önerdiği sıradaki WSTG testi |
| GET | `/api/sessions/<id>/report/data` | Bir oturum için zenginleştirilmiş rapor verisi (istatistikler, CVSS/CWE/OWASP dahil bulgular) |
| POST | `/api/sessions/<id>/report/summary` | AI'nin yazdığı yönetici özeti taslağı (incelemeye sunulur, otomatik uygulanmaz) |
| POST | `/api/sessions/<id>/report/download` | Nihai raporu `.md` veya `.docx` olarak indirir |
| GET | `/api/study/metrics` | Oturum bazlı metrikler + AI destekli/kontrol grubu karşılaştırması (Faz 5) |
| POST | `/api/cvss/calculate` | Bir CVSS 3.1 vektöründen taban skoru hesaplar |
| GET | `/api/mapping/wstg/<test_id>` | Bir WSTG testi için ilişkili OWASP Top 10 kategorileri + önerilen CWE'ler |


### 🤖 AI Entegrasyonu (Yol Haritası)

Bu proje, WSTG checklist temeli üzerine kurulan **AI destekli bir pentest karar destek sistemine** dönüşüyor. Plan:

| Faz | Durum | Ne ekliyor |
|---|---|---|
| 0 | ✅ Tamamlandı | Pluggable AI sağlayıcı katmanı (`backend/ai/`) — Gemini, OpenAI, Anthropic ve yerel Ollama desteği; bağlantı testi için `/api/ai/ping`; her AI çağrısını (sağlayıcı, gecikme, başarı/hata) loglayan `AIInteractionLog` tablosu |
| 1 | ✅ Tamamlandı | Resmi formüle uygun CVSS 3.1 taban skoru hesaplayıcı (`backend/cvss.py` + `js/cvss.js`, yayınlanmış referans skorlarıyla doğrulandı), bulgulara CWE alanları, ve mevcut Top 10 verisinden inşa edilen WSTG↔OWASP Top 10↔CWE ilişki indexi (`backend/mapping.py`) — not editöründe canlı CVSS vektör oluşturucu ve otomatik CWE önerisi olarak karşınıza çıkıyor |
| 2 | ✅ Tamamlandı | AI bulgu analizi (`backend/finding_analysis.py`) — bir bulgunun başlığını/içeriğini (bağlı olduğu WSTG testi ve aday CWE'leri bağlam olarak vererek) yapılandırılan LLM'e gönderip önerilen CWE, önem derecesi, CVSS vektörü ve gerekçeli bir false-positive değerlendirmesi alıyor. AI bulguyu asla otomatik güncellemiyor — öneriler, her alan için ayrı "Uygula" butonu olan bir inceleme panelinde gösteriliyor; önerilen her CWE, bilinen adaylardan biri mi yoksa modelin kendi çıkarımı mı olduğuna göre işaretleniyor, böylece ne kadar güvenileceğinizi siz değerlendiriyorsunuz |
| 3 | ✅ Tamamlandı | AI sonraki test önerisi (`backend/next_test_suggestion.py`) — tamamlanan testlere ve (önem derecesine göre sıralanmış) mevcut bulgulara bakarak AI, henüz yapılmamış testler arasından hangisinin sırada yapılmasının en mantıklı olacağını gerekçesiyle, bir öncelik seviyesiyle ve 1-3 alternatifle önerir. Önerilen test ID'leri gerçek "yapılmamış" havuzuna karşı doğrulanır (`suggestion_grounded`); zaten her şey tamamlanmışsa AI'a hiç gidilmez. "Sırada Ne Var?" panelinde, önerilen checklist maddesine tek tıkla götüren bir "Bu Teste Git" butonuyla sunulur |
| 4 | ✅ Tamamlandı | Otomatik rapor üretimi (`backend/report_generator.py`) — bulguları (severity/CVSS'e göre sıralı, OWASP Top 10 kategorisiyle zenginleştirilmiş) indirilebilir bir **Markdown ya da Word (.docx)** raporuna dönüştürür: istatistik özeti, bulgu bazlı teknik detay, tamamlanan testlerin metodoloji eki. AI sade bir dille yönetici özeti taslağı yazabilir, ama önce düzenlenebilir bir kutuda gösterilir — pentester onaylamadan hiçbir şey nihai belgeye girmez |
| 5 | ✅ Tamamlandı | Deneysel A/B karşılaştırma modülü (`backend/study_metrics.py`) — oturumlar oluşturulurken **AI Destekli** ya da **Kontrol (Sadece Checklist)** olarak etiketlenebilir; kontrol grubu oturumlarında tüm AI özellikleri (analiz, sonraki test önerisi, rapor taslağı) arayüzden gizlenir, böylece iki koşul gerçekten karşılaştırılabilir olur. Bulgular doğrulanmış geçerli/false-positive olarak işaretlenebilir (AI'nin kendi tahmininden ayrı, pentester'ın nihai kararı — ground truth). "Çalışma Metrikleri" paneli iki grubu topluca karşılaştırır — tamamlanma süresi, tamamlanan test sayısı, bulgu sayısı, false-positive oranı, AI çağrı hacmi/gecikmesi — her metrik için yüzdesel farkla birlikte; *"AI destekli grup %X daha hızlı tamamladı ve %Y daha fazla bulgu buldu"* gibi bir iddiayı destekleyecek şekilde. |

**Artık 6 fazın (0–5) tamamı tamamlandı.** Proje bir WSTG checklist takip aracından, README'nin başında tarif edilen şeye dönüştü: küçük ölçekli de olsa gömülü bir deneysel değerlendirme çerçevesine sahip, AI destekli bir pentest karar destek sistemi.

**Sağlayıcı yapılandırma**

```bash
cd backend
cp .env.example .env
# .env dosyasını düzenleyin — kredi kartı gerektirmeyen ücretsiz seçenek Google Gemini:
# https://aistudio.google.com/apikey
```

Varsayılan `AI_PROVIDER=gemini`. İsterseniz `openai`, `anthropic`, ya da `ollama` (tamamen yerel, API key gerekmez, rate-limit yoktur — Faz 5 deneyi için en uygun seçenek) olarak değiştirin — başka hiçbir kod değişikliği gerekmez. Çalıştığını doğrulamak için:

```bash
curl http://localhost:5000/api/ai/ping
```

### 📓 Not Defteri

Her WSTG checklist maddesinin kendi satır içi "Bulgular/Notlar" kutusu (önem derecesi seçimiyle birlikte) hâlâ duruyor — bu değişmedi. Bunun yanına, aktif hedef için daha serbest ve kanıt eklemeye uygun bir **"Not Defteri"** bölümü eklendi (sidebar → Not Defteri):

- Her kayıt bir **başlık**, bir **önem derecesi**, serbest metin bir **içerik** içerir ve dilerseniz belirli bir **WSTG test maddesine bağlanabilir** — ya da hiçbir maddeye bağlı olmayan bir **genel not** olarak bırakılabilir (örn. hedefle ilgili genel bir gözlem).
- Kanıt için **ekran görüntüsü** ekleyebilirsiniz: sürükle-bırak, panodan yapıştırma (Ctrl+V) veya dosya seçerek. Küçük resme tıklayarak büyük halini görebilirsiniz.
- Herhangi bir checklist maddesinin detay görünümünden **"🗒️ Not defterine ekle"** butonuyla, not editörü doğrudan o test maddesine bağlı şekilde açılır.
- Not listesi test maddesine göre ya da sadece genel notlar olacak şekilde filtrelenebilir.
- Uygulamanın geri kalanında olduğu gibi not defteri kayıtları da o anki oturumun saklama modunu izler: isimli bir oturum aktifken veritabanına kaydedilir (ve `/api/sessions/<id>/report` çıktısına dahil olur), oturumsuz/yerel modda ise `localStorage`'da tutulur.

### 🛡️ OWASP Top 10:2025 Modülü

Sidebar'daki "Referans" grubundan erişilen **"OWASP Top 10:2025"** bölümü, güncel 10 risk kategorisinin tamamını listeler — A01 Bozuk Erişim Kontrolü'nden A10 İstisnai Durumların Hatalı Yönetimi'ne kadar, 2025'in iki yeni kategorisi (Yazılım Tedarik Zinciri Hataları, İstisnai Durumların Hatalı Yönetimi) dahil. Bir karta tıklandığında şu bilgileri içeren bir detay ekranı açılır:

- Açıklama ve zafiyetin genelde nasıl ortaya çıktığı
- O risk için adım adım pentest rehberi
- Örnek bir saldırı senaryosu ve kopyalanabilir örnek payload/komut
- Bir önlem (prevention) kontrol listesi
- En dikkat çekici ilişkili CWE'ler ve önerilen araçlar
- Bu çalışma alanındaki eşleşen WSTG checklist maddelerine (varsa) tıklanabilir bağlantılar

Bu modül tamamen bilgilendirme/referans amaçlıdır (veritabanına kayıt yapmaz) ve resmi [OWASP Top 10:2025](https://owasp.org/Top10/2025/) kaynağından üretilmiş olarak hem Türkçe hem İngilizce mevcuttur.

### 🚀 Kurulum ve Çalıştırma

Proje herhangi bir bağımlılık veya build adımı gerektirmez.

**1) Doğrudan açma**
`index.html` dosyasına çift tıklayarak tarayıcıda açabilirsiniz. Ancak bazı tarayıcılar `fetch()` ile yerel JSON dosyalarını `file://` protokolünden okumayı kısıtlayabilir; bu durumda yerel bir sunucu kullanmanız önerilir.

**2) Yerel sunucu ile çalıştırma (önerilen)**

```bash
# Python ile
python3 -m http.server 8000

# ya da Node.js ile
npx serve .
```

Ardından tarayıcıdan `http://localhost:8000` adresini açın.

### 🎨 Tema Sistemi

Sidebar'daki **Tema** butonuna tıklayarak açılır pencereden 25 farklı tema arasından seçim yapabilirsiniz. Seçiminiz `localStorage`'a kaydedilir ve bir sonraki ziyaretinizde otomatik uygulanır.

| Kategori | Örnek Temalar |
|---|---|
| Koyu / Neon | Cyberpunk, Neon Tokyo, Synthwave, Vaporwave, Matrix |
| Doğa / Sakin | Forest, Ocean, Aurora, Coral Reef, Nord |
| Yoğun / Dramatik | Blood Moon, Crimson, Toxic, Solar Flare, Deep Space |
| Açık / Zarif | Arctic Light, Sakura, Rose Gold, Icefall |

Yeni bir tema eklemek isterseniz:
1. `js/app.js` içindeki `THEMES` dizisine `{ id, name, emoji, primary, secondary, desc: {tr, en} }` formatında yeni bir kayıt ekleyin.
2. `css/style.css` içine `[data-theme="tema-id"]{ ... }` bloğu ile renk paletini tanımlayın (mevcut temaların altına örnek alarak ekleyebilirsiniz).

### 🌐 Dil Desteği

Sidebar altındaki dil seçiciden **Türkçe / English** arasında geçiş yapılabilir. Çeviri metinleri `js/app.js` içindeki `I18N` nesnesinde, test verileri ise `data/wstg-checklist.tr.json` ve `data/wstg-checklist.en.json` dosyalarında tutulur.

### 💾 Veri Saklama

Uygulama herhangi bir sunucuya veri göndermez. Tüm ilerleme, dil ve tema tercihleri yalnızca tarayıcınızın `localStorage`'ında saklanır:

| Anahtar | İçerik |
|---|---|
| `wstg_progress_v1` | Tamamlanan test ID'leri (yalnızca oturumsuz/yerel modda kullanılır) |
| `wstg_lang_v1` | Seçili dil |
| `wstg_theme_v1` | Seçili tema |
| `wstg_session_id_v1` | Aktif veritabanı oturumunun ID'si (varsa) |
| `wstg_skip_session_v1` | Oturumsuz devam etme tercihinizi hatırlar |

"İlerlemeyi Sıfırla" butonu ilgili veriyi temizler (yerel ilerleme ya da aktif DB oturumunun tüm sonuçları).

### 🛠️ Kullanılan Teknolojiler

- Vanilla **HTML5 / CSS3 / JavaScript** (framework yok, derleme adımı yok)
- CSS Custom Properties (`--variables`) ile tema motoru
- Yerel modda `localStorage` ile kalıcı veri saklama
- İsimli, veritabanı destekli test oturumları için opsiyonel **Flask + SQLAlchemy + SQLite** backend
- [Inter](https://fonts.google.com/specimen/Inter) yazı tipi (Google Fonts)

### 📖 Kaynak

Test maddeleri [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/) referans alınarak hazırlanmıştır.

### ⚠️ Sorumluluk Reddi

Bu araç yalnızca **yetkilendirilmiş** güvenlik testleri (pentest) için eğitim ve referans amaçlı hazırlanmıştır. Kendi sahibi olmadığınız veya yazılı izniniz bulunmayan sistemlere karşı test yapmak yasa dışıdır. Bu projenin kullanımından doğacak sorumluluk tamamen kullanıcıya aittir.

### 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır. Dilediğiniz gibi kullanabilir, değiştirebilir ve dağıtabilirsiniz.

---

Contributions are welcome — feel free to open an issue or submit a pull request. ⭐
Katkıda bulunmak isterseniz bir issue açabilir veya pull request gönderebilirsiniz. ⭐
