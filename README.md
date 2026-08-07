# 🛡️ Pentest Workspace — OWASP WSTG v4.2

![Made with HTML/CSS/JS](https://img.shields.io/badge/stack-HTML%20%7C%20CSS%20%7C%20JS-informational)
![No backend](https://img.shields.io/badge/backend-none-lightgrey)
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

### 🖥️ Overview

The app has a sidebar with category navigation plus language/theme settings, and a main dashboard with stat cards and category cards. Clicking a category opens a modal listing all of its test items.

### 📂 Project Structure

```
pentest-workspace/
├── index.html                     # Main HTML file
├── css/
│   └── style.css                  # All styles and theme definitions
├── js/
│   └── app.js                     # App logic (state, rendering, i18n, themes)
├── data/
│   ├── wstg-checklist.tr.json     # Turkish test data
│   └── wstg-checklist.en.json     # English test data
├── wstg-v4_2.pdf                  # Original OWASP WSTG v4.2 guide
└── assets/                        # (optional image assets)
```

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
| `wstg_progress_v1` | Completed test IDs |
| `wstg_lang_v1` | Selected language |
| `wstg_theme_v1` | Selected theme |

The "Reset Progress" button clears this data.

### 🛠️ Tech Stack

- Vanilla **HTML5 / CSS3 / JavaScript** (no framework, no build step)
- CSS Custom Properties (`--variables`) powering the theme engine
- `localStorage` for persistence
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

### 🖥️ Ekran Görünümü

Uygulama, sol tarafta kategori navigasyonu ve tema/dil ayarları bulunan bir sidebar; sağ tarafta ise dashboard, istatistik kartları ve kategori kartlarının yer aldığı ana ekrandan oluşur. Bir kategoriye tıklandığında, o kategoriye ait test maddeleri açılır pencerede (modal) listelenir.

### 📂 Proje Yapısı

```
pentest-workspace/
├── index.html                     # Ana HTML dosyası
├── css/
│   └── style.css                  # Tüm stiller ve tema tanımları
├── js/
│   └── app.js                     # Uygulama mantığı (state, render, i18n, tema)
├── data/
│   ├── wstg-checklist.tr.json     # Türkçe test verisi
│   └── wstg-checklist.en.json     # İngilizce test verisi
├── wstg-v4_2.pdf                  # Orijinal OWASP WSTG v4.2 kılavuzu
└── assets/                        # (opsiyonel görsel varlıklar)
```

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
| `wstg_progress_v1` | Tamamlanan test ID'leri |
| `wstg_lang_v1` | Seçili dil |
| `wstg_theme_v1` | Seçili tema |

"İlerlemeyi Sıfırla" butonu bu verileri temizler.

### 🛠️ Kullanılan Teknolojiler

- Vanilla **HTML5 / CSS3 / JavaScript** (framework yok, derleme adımı yok)
- CSS Custom Properties (`--variables`) ile tema motoru
- `localStorage` ile kalıcı veri saklama
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
