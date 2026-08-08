(function(){
  "use strict";

  const STORAGE_KEY = "wstg_progress_v1";
  const FINDINGS_KEY = "wstg_findings_v1";
  const NOTEBOOK_KEY = "wstg_notebook_v1";
  const LANG_KEY = "wstg_lang_v1";
  const THEME_KEY = "wstg_theme_v1";
  const SESSION_ID_KEY = "wstg_session_id_v1";
  const SKIP_SESSION_KEY = "wstg_skip_session_v1";
  const API_BASE = "http://localhost:5000/api";

  const DATA_FILES = {
    tr: "data/wstg-checklist.tr.json",
    en: "data/wstg-checklist.en.json"
  };

  const TOP10_FILES = {
    tr: "data/owasp-top10.tr.json",
    en: "data/owasp-top10.en.json"
  };

  const SEVERITIES = ["info", "low", "medium", "high", "critical"];

  const THEMES = [
    { id: "midnight",   name: "Midnight",        emoji: "🌌", primary: "#6366f1", secondary: "#8b5cf6", desc: { tr: "Klasik indigo karanlık tema", en: "Classic indigo dark theme" } },
    { id: "cyberpunk",  name: "Cyberpunk",       emoji: "🤖", primary: "#ec4899", secondary: "#22d3ee", desc: { tr: "Neon pembe & elektrik camgöbeği", en: "Neon pink & electric cyan" } },
    { id: "matrix",     name: "Matrix",          emoji: "💻", primary: "#22c55e", secondary: "#84cc16", desc: { tr: "Yeşil terminal, dijital yağmur", en: "Green terminal, digital rain" } },
    { id: "crimson",    name: "Crimson",         emoji: "🩸", primary: "#ef4444", secondary: "#f97316", desc: { tr: "Yoğun kırmızı & turuncu ateş", en: "Bold red & fiery orange" } },
    { id: "ocean",      name: "Ocean",           emoji: "🌊", primary: "#0ea5e9", secondary: "#06b6d4", desc: { tr: "Derin mavi okyanus tonları", en: "Deep blue ocean tones" } },
    { id: "sunset",     name: "Sunset",          emoji: "🌇", primary: "#f59e0b", secondary: "#ef4444", desc: { tr: "Sıcak gün batımı tonları", en: "Warm sunset gradients" } },
    { id: "royal",      name: "Royal",           emoji: "👑", primary: "#a855f7", secondary: "#eab308", desc: { tr: "Mor & altın, asil hava", en: "Purple & gold, regal feel" } },
    { id: "dracula",    name: "Dracula",         emoji: "🧛", primary: "#bd93f9", secondary: "#ff79c6", desc: { tr: "Popüler koyu kod editörü paleti", en: "Popular dark editor palette" } },
    { id: "nord",       name: "Nord",            emoji: "❄️", primary: "#88c0d0", secondary: "#81a1c1", desc: { tr: "Soğuk, sakin İskandinav tonları", en: "Cool, calm Nordic tones" } },
    { id: "mono",       name: "Mono",            emoji: "⚫", primary: "#e5e5e5", secondary: "#a3a3a3", desc: { tr: "Siyah-beyaz minimalist görünüm", en: "Black & white minimalist look" } },
    { id: "arctic",     name: "Arctic Light",    emoji: "☀️", primary: "#2563eb", secondary: "#0891b2", desc: { tr: "Aydınlık, temiz açık tema", en: "Bright, clean light theme" } },
    { id: "vaporwave",  name: "Vaporwave",       emoji: "🌴", primary: "#ff6ec7", secondary: "#00fff0", desc: { tr: "90'lar estetiği, pembe & turkuaz", en: "90s aesthetic, pink & teal" } },
    { id: "neontokyo",  name: "Neon Tokyo",      emoji: "🏮", primary: "#ff2d78", secondary: "#00e5ff", desc: { tr: "Gece şehri, parlak neon ışıklar", en: "Night city, blazing neon lights" } },
    { id: "forest",     name: "Forest",          emoji: "🌲", primary: "#16a34a", secondary: "#65a30d", desc: { tr: "Doğal yeşil orman atmosferi", en: "Natural green forest vibe" } },
    { id: "bloodmoon",  name: "Blood Moon",      emoji: "🌑", primary: "#dc2626", secondary: "#7f1d1d", desc: { tr: "Karanlık, tehditkar kızıl ay", en: "Dark, ominous crimson eclipse" } },
    { id: "aurora",     name: "Aurora",          emoji: "🌠", primary: "#2dd4bf", secondary: "#a78bfa", desc: { tr: "Kuzey ışıkları, camgöbeği & mor", en: "Northern lights, teal & violet" } },
    { id: "solarflare",  name: "Solar Flare",    emoji: "🔥", primary: "#f97316", secondary: "#facc15", desc: { tr: "Yanan turuncu & sarı enerji", en: "Blazing orange & yellow energy" } },
    { id: "deepspace",  name: "Deep Space",      emoji: "🪐", primary: "#4f46e5", secondary: "#db2777", desc: { tr: "Yıldızlararası indigo & pembe", en: "Interstellar indigo & pink" } },
    { id: "coralreef",  name: "Coral Reef",      emoji: "🐠", primary: "#fb7185", secondary: "#2dd4bf", desc: { tr: "Mercan pembesi & tropikal camgöbeği", en: "Coral pink & tropical teal" } },
    { id: "toxic",      name: "Toxic",           emoji: "☣️", primary: "#a3e635", secondary: "#facc15", desc: { tr: "Asit yeşili, radyoaktif his", en: "Acid green, radioactive feel" } },
    { id: "goldrush",   name: "Gold Rush",       emoji: "🏆", primary: "#d4af37", secondary: "#b8860b", desc: { tr: "Lüks siyah & parlak altın", en: "Luxury black & gleaming gold" } },
    { id: "synthwave",  name: "Synthwave",       emoji: "🕹️", primary: "#ff2079", secondary: "#00d4ff", desc: { tr: "80'ler retro futurizm", en: "80s retro-futurism grid" } },
    { id: "rosegold",   name: "Rose Gold",       emoji: "🌹", primary: "#b76e79", secondary: "#d4af8a", desc: { tr: "Zarif açık pembe-altın tema", en: "Elegant light pink-gold theme" } },
    { id: "sakura",     name: "Sakura",          emoji: "🌸", primary: "#f472b6", secondary: "#fb7185", desc: { tr: "Yumuşak açık kiraz çiçeği teması", en: "Soft light cherry-blossom theme" } },
    { id: "icefall",    name: "Icefall",         emoji: "🧊", primary: "#0ea5e9", secondary: "#38bdf8", desc: { tr: "Buzul mavisi, ferah açık tema", en: "Glacier blue, crisp light theme" } }
  ];

  const I18N = {
    tr: {
      navWorkspace: "Workspace",
      navDashboard: "Dashboard",
      navCategories: "WSTG Kategorileri",
      exportReport: "Raporu Dışa Aktar",
      resetProgress: "İlerlemeyi Sıfırla",
      langLabel: "Dil",
      themeLabel: "Tema",
      themeModalTitle: "Tema Seç",
      themeModalDesc: "Çalışma alanının görünümünü kişiselleştir. Seçimin otomatik olarak kaydedilir.",
      searchPlaceholder: "WSTG testi, XSS, SQLi, JWT, SSRF ara...",
      heroTitle: "Web Pentest Workspace",
      heroDesc: "OWASP Web Security Testing Guide v4.2 tabanlı, tıklanabilir checklist ile her test maddesinin nasıl uygulanacağını adım adım ve örnekli şekilde gösteren pentest çalışma alanı.",
      startTest: "Teste Başla",
      openPdf: "WSTG PDF'i Aç",
      completedLabel: "Tamamlandı",
      statDoneLabel: "Tamamlanan",
      statDoneSub: "Bitirilen testler",
      statPendingLabel: "Bekleyen",
      statPendingSub: "Kalan testler",
      statCategoriesLabel: "Kategori",
      statCategoriesSub: "WSTG modülü",
      statTotalLabel: "Toplam Test",
      statTotalSub: "WSTG v4.2 madde sayısı",
      sectionTitle: "OWASP WSTG Kategorileri",
      sectionSub: "Başlamak için bir modül seçin",
      itemSearchPlaceholder: "Bu kategoride ara...",
      filterAll: "Tümü",
      filterPending: "Bekleyen",
      filterDone: "Tamamlanan",
      descriptionLabel: "Açıklama",
      howToLabel: "Nasıl Test Edilir",
      exampleLabel: "Örnek Payload / Komut",
      toolsLabel: "Önerilen Araçlar",
      copyBtn: "Kopyala",
      testEditedTitle: "Test edildi olarak işaretle",
      copiedToast: "Panoya kopyalandı",
      markDoneToast: "Test tamamlandı olarak işaretlendi",
      markPendingToast: "Test beklemede olarak işaretlendi",
      reportDownloadedToast: "Rapor indirildi",
      progressResetToast: "İlerleme sıfırlandı",
      resetConfirm: "Tüm ilerleme sıfırlansın mı? Bu işlem geri alınamaz.",
      noMatchInCategory: "Bu kategoride eşleşen test bulunamadı.",
      noSearchResults: q => `"${q}" için sonuç bulunamadı.`,
      completedTag: "✓ Tamamlandı",
      dataLoadError: "Veri yüklenemedi. Lütfen sayfayı yenileyin.",
      reportTitle: "PENTEST WORKSPACE - OWASP WSTG v4.2 RAPORU",
      reportCreated: "Oluşturulma",
      reportProgress: "İlerleme",
      dateLocale: "tr-TR",

      navSessions: "Test Oturumları",
      sessionGateTitle: "Test Oturumları",
      sessionGateDesc: "Her pentest sürecini bir isim vererek veritabanına kaydedin, kaldığınız yerden devam edin.",
      newSession: "+ Yeni Oturum",
      continueLocal: "Oturumsuz / yerel modda devam et",
      sessionNameLabel: "Oturum Adı *",
      sessionNamePlaceholder: "Örn: Login Sayfası Testi - Ağustos",
      testerNameLabel: "Test Uzmanı",
      testerNamePlaceholder: "Adınız",
      targetUrlLabel: "Hedef URL",
      startSession: "Oturumu Başlat",
      newSessionTitle: "Yeni Test Oturumu",
      newSessionDesc: "Bu pentest sürecini tanımlayın. İlerlemeniz bu isimle veritabanına kaydedilecek.",
      noSessionsYet: "Henüz kayıtlı test oturumu yok. Yeni bir oturum başlatın.",
      dbOnline: "🟢 Veritabanı bağlı",
      dbOffline: "🟡 Veritabanı yok — backend/app.py çalıştırın (yerel modda devam edilecek)",
      sessionCreated: "Oturum oluşturuldu ve DB'ye kaydedildi",
      sessionDeleted: "Oturum silindi",
      sessionDeleteConfirm: "Bu oturumu ve tüm test sonuçlarını silmek istiyor musunuz? Bu işlem geri alınamaz.",
      sessionNameRequired: "Lütfen bir oturum adı girin",
      sessionResumed: "kaldığı yerden devam ediyor",
      sessionResetConfirm: "Bu oturumun tüm test sonuçları sıfırlansın mı?",
      sessionTester: "Uzman",
      sessionTarget: "Hedef",
      sessionLocalMode: "Yerel mod (DB yok)",
      resultSaveError: "Sonuç veritabanına kaydedilemedi, bağlantıyı kontrol edin.",
      loadingSessions: "Oturumlar yükleniyor...",
      sessionsLoadError: "Oturumlar yüklenemedi.",
      markCompleted: "Tamamla",
      statusActive: "aktif",
      statusCompleted: "tamamlandı",

      navReference: "Referans",
      navTop10: "OWASP Top 10:2025",
      top10SectionTitle: "OWASP Top 10:2025 — En Kritik Web Uygulaması Riskleri",
      top10SectionSub: "owasp.org/Top10/2025 kaynağına dayanır ↗",
      top10NewBadge: "YENİ",
      top10CweCount: n => `${n} CWE`,
      top10DescLabel: "Açıklama",
      top10HowItHappensLabel: "Nasıl Oluşur",
      top10HowToTestLabel: "Nasıl Test Edilir (Pentest Adımları)",
      top10ScenarioLabel: "Örnek Saldırı Senaryosu",
      top10PayloadLabel: "Örnek Payload / Komut",
      top10PreventionLabel: "Nasıl Önlenir",
      top10CweLabel: "İlgili CWE'ler",
      top10ToolsLabel: "Önerilen Araçlar",
      top10WstgLabel: "İlgili WSTG Testleri",
      findingsLabel: "Bulgular / Notlar",
      findingsPlaceholder: "Bu test maddesiyle ilgili bulgularınızı, notlarınızı veya kanıtlarınızı buraya yazın...",
      severityLabel: "Önem Derecesi",
      severity_info: "Bilgi",
      severity_low: "Düşük",
      severity_medium: "Orta",
      severity_high: "Yüksek",
      severity_critical: "Kritik",
      findingSavedToast: "Kaydedildi ✓",
      findingSaveError: "Bulgu kaydedilemedi",

      top10PrevBtn: "‹ Önceki",
      top10NextBtn: "Sonraki ›",
      top10SourceNote: "Kaynak: OWASP Top 10:2025 (owasp.org/Top10/2025), pentest çalışma alanı için Türkçe/İngilizce olarak özetlenmiştir.",

      navImport: "Bulgu İçe Aktar",
      importModalTitle: "Bulgu İçe Aktar",
      importModalDesc: "Nmap, Nikto veya WPScan çıktısını (XML/JSON) yükleyin; eşleşen bulgular ilgili WSTG maddelerine not olarak eklenir.",
      importToolLabel: "Araç",
      importToolAuto: "Otomatik algıla",
      importFileLabel: "Dosya",
      importAnalyzeBtn: "Analiz Et",
      importApplyBtn: "Seçilenleri Uygula",
      importNoFile: "Lütfen bir dosya seçin.",
      importParseError: "Dosya ayrıştırılamadı",
      importNoFindings: "Bu dosyada eşleşen bir bulgu bulunamadı.",
      importPreviewCount: n => `${n} bulgu bulundu — uygulamadan önce gözden geçirin.`,
      importAppliedToast: n => `${n} bulgu checklist'e işlendi`,
      importUnmatchedTag: "Kategori önerisi yok",
      importAnalyzing: "Analiz ediliyor...",

      navNotebook: "Not Defteri",
      notebookTitle: "Not Defteri",
      notebookDesc: "Bu hedef için serbest notlarınızı ve zafiyet bulgularınızı, dilerseniz ilgili test maddesiyle ilişkilendirerek buraya kaydedin.",
      notebookDescLocal: "Yerel modda çalışıyorsunuz — notlar bu tarayıcıda saklanır. Oturum açarsanız notlar veritabanına kaydedilir.",
      notebookFilterAll: "Tüm notlar",
      notebookFilterGeneral: "Sadece genel notlar",
      newNote: "+ Yeni Not",
      editNote: "Notu Düzenle",
      noteEditorDesc: "Bulgunuzu açık ve net biçimde yazın; isterseniz kanıt olarak ekran görüntüsü ekleyin.",
      noteTitleLabel: "Başlık",
      noteTitlePlaceholder: "Örn: Login formunda SQL Injection",
      noteLinkedTestLabel: "İlgili Test Maddesi (opsiyonel)",
      noteGeneralOption: "— Genel not (belirli bir maddeye bağlı değil) —",
      noteContentLabel: "Not / Bulgu",
      noteContentPlaceholder: "Zafiyeti, adımları ve etkisini buraya yazın...",
      noteImagesLabel: "Kanıt Görselleri",
      noteImageDropText: "Görselleri buraya sürükleyin, yapıştırın (Ctrl+V) ya da seçin",
      saveNote: "Notu Kaydet",
      deleteNote: "Notu Sil",
      noteEmptyList: "Henüz not eklenmedi. İlk notunuzu ekleyin.",
      noteContentRequired: "Lütfen bir not yazın veya en az bir görsel ekleyin.",
      noteSaved: "Not kaydedildi ✓",
      noteDeleted: "Not silindi",
      noteDeleteConfirm: "Bu notu silmek istiyor musunuz?",
      noteSaveError: "Not kaydedilemedi",
      noteTooManyImages: n => `En fazla ${n} görsel ekleyebilirsiniz`,
      noteImageTooBig: "Görsel çok büyük (maks. ~4MB)",
      noteGeneralBadge: "Genel not",
      noteUntitled: "(Başlıksız not)",
      addNoteFromTest: "🗒️ Not defterine ekle",
      noteJustNow: "az önce"
    },
    en: {
      navWorkspace: "Workspace",
      navDashboard: "Dashboard",
      navCategories: "WSTG Categories",
      exportReport: "Export Report",
      resetProgress: "Reset Progress",
      langLabel: "Language",
      themeLabel: "Theme",
      themeModalTitle: "Choose a Theme",
      themeModalDesc: "Personalize the look of your workspace. Your choice is saved automatically.",
      searchPlaceholder: "Search WSTG test, XSS, SQLi, JWT, SSRF...",
      heroTitle: "Web Pentest Workspace",
      heroDesc: "A pentest workspace built on the OWASP Web Security Testing Guide v4.2, with a clickable checklist that shows step-by-step, with examples, how to carry out every test item.",
      startTest: "Start Testing",
      openPdf: "Open WSTG PDF",
      completedLabel: "Completed",
      statDoneLabel: "Completed",
      statDoneSub: "Finished tests",
      statPendingLabel: "Pending",
      statPendingSub: "Remaining tests",
      statCategoriesLabel: "Categories",
      statCategoriesSub: "WSTG modules",
      statTotalLabel: "Total Tests",
      statTotalSub: "WSTG v4.2 item count",
      sectionTitle: "OWASP WSTG Categories",
      sectionSub: "Select a module to get started",
      itemSearchPlaceholder: "Search within this category...",
      filterAll: "All",
      filterPending: "Pending",
      filterDone: "Completed",
      descriptionLabel: "Description",
      howToLabel: "How to Test",
      exampleLabel: "Example Payload / Command",
      toolsLabel: "Recommended Tools",
      copyBtn: "Copy",
      testEditedTitle: "Mark as tested",
      copiedToast: "Copied to clipboard",
      markDoneToast: "Test marked as completed",
      markPendingToast: "Test marked as pending",
      reportDownloadedToast: "Report downloaded",
      progressResetToast: "Progress reset",
      resetConfirm: "Reset all progress? This action cannot be undone.",
      noMatchInCategory: "No matching test found in this category.",
      noSearchResults: q => `No results found for "${q}".`,
      completedTag: "✓ Completed",
      dataLoadError: "Failed to load data. Please refresh the page.",
      reportTitle: "PENTEST WORKSPACE - OWASP WSTG v4.2 REPORT",
      reportCreated: "Created",
      reportProgress: "Progress",
      dateLocale: "en-US",

      navSessions: "Test Sessions",
      sessionGateTitle: "Test Sessions",
      sessionGateDesc: "Save every pentest run to the database under a name, and resume it later.",
      newSession: "+ New Session",
      continueLocal: "Continue without a session (local mode)",
      sessionNameLabel: "Session Name *",
      sessionNamePlaceholder: "e.g. Login Page Test - August",
      testerNameLabel: "Tester",
      testerNamePlaceholder: "Your name",
      targetUrlLabel: "Target URL",
      startSession: "Start Session",
      newSessionTitle: "New Test Session",
      newSessionDesc: "Describe this pentest run. Your progress will be saved to the database under this name.",
      noSessionsYet: "No saved test sessions yet. Start a new one.",
      dbOnline: "🟢 Database connected",
      dbOffline: "🟡 No database — run backend/app.py (continuing in local mode)",
      sessionCreated: "Session created and saved to the database",
      sessionDeleted: "Session deleted",
      sessionDeleteConfirm: "Delete this session and all its test results? This cannot be undone.",
      sessionNameRequired: "Please enter a session name",
      sessionResumed: "resumed",
      sessionResetConfirm: "Reset all test results for this session?",
      sessionTester: "Tester",
      sessionTarget: "Target",
      sessionLocalMode: "Local mode (no DB)",
      resultSaveError: "Could not save the result to the database, check the connection.",
      loadingSessions: "Loading sessions...",
      sessionsLoadError: "Failed to load sessions.",
      markCompleted: "Complete",
      statusActive: "active",
      statusCompleted: "completed",

      navReference: "Reference",
      navTop10: "OWASP Top 10:2025",
      top10SectionTitle: "OWASP Top 10:2025 — Most Critical Web Application Risks",
      top10SectionSub: "Based on owasp.org/Top10/2025 ↗",
      top10NewBadge: "NEW",
      top10CweCount: n => `${n} CWEs`,
      top10DescLabel: "Description",
      top10HowItHappensLabel: "How It Happens",
      top10HowToTestLabel: "How to Test (Pentest Steps)",
      top10ScenarioLabel: "Example Attack Scenario",
      top10PayloadLabel: "Example Payload / Command",
      top10PreventionLabel: "How to Prevent",
      top10CweLabel: "Related CWEs",
      top10ToolsLabel: "Recommended Tools",
      top10WstgLabel: "Related WSTG Tests",
      findingsLabel: "Findings / Notes",
      findingsPlaceholder: "Write your findings, notes, or evidence for this test item here...",
      severityLabel: "Severity",
      severity_info: "Info",
      severity_low: "Low",
      severity_medium: "Medium",
      severity_high: "High",
      severity_critical: "Critical",
      findingSavedToast: "Saved ✓",
      findingSaveError: "Could not save finding",

      top10PrevBtn: "‹ Previous",
      top10NextBtn: "Next ›",
      top10SourceNote: "Source: OWASP Top 10:2025 (owasp.org/Top10/2025), summarized in Turkish/English for this pentest workspace.",

      navImport: "Import Findings",
      importModalTitle: "Import Findings",
      importModalDesc: "Upload Nmap, Nikto, or WPScan output (XML/JSON); matching findings are attached as notes to the relevant WSTG items.",
      importToolLabel: "Tool",
      importToolAuto: "Auto-detect",
      importFileLabel: "File",
      importAnalyzeBtn: "Analyze",
      importApplyBtn: "Apply Selected",
      importNoFile: "Please choose a file.",
      importParseError: "Could not parse the file",
      importNoFindings: "No matching findings were found in this file.",
      importPreviewCount: n => `${n} findings detected — review before applying.`,
      importAppliedToast: n => `${n} findings applied to the checklist`,
      importUnmatchedTag: "No category suggestion",
      importAnalyzing: "Analyzing...",

      navNotebook: "Notebook",
      notebookTitle: "Notebook",
      notebookDesc: "Keep free-form notes and vulnerability findings for this target here, optionally linked to a specific test item.",
      notebookDescLocal: "You're in local mode — notes are stored in this browser. Open a session to save notes to the database.",
      notebookFilterAll: "All notes",
      notebookFilterGeneral: "General notes only",
      newNote: "+ New Note",
      editNote: "Edit Note",
      noteEditorDesc: "Write your finding clearly, and optionally attach a screenshot as evidence.",
      noteTitleLabel: "Title",
      noteTitlePlaceholder: "e.g. SQL Injection in login form",
      noteLinkedTestLabel: "Related Test Item (optional)",
      noteGeneralOption: "— General note (not linked to a specific item) —",
      noteContentLabel: "Note / Finding",
      noteContentPlaceholder: "Describe the vulnerability, the steps, and its impact...",
      noteImagesLabel: "Evidence Images",
      noteImageDropText: "Drag images here, paste (Ctrl+V), or click to select",
      saveNote: "Save Note",
      deleteNote: "Delete Note",
      noteEmptyList: "No notes yet. Add your first one.",
      noteContentRequired: "Please write a note or attach at least one image.",
      noteSaved: "Note saved ✓",
      noteDeleted: "Note deleted",
      noteDeleteConfirm: "Delete this note?",
      noteSaveError: "Could not save the note",
      noteTooManyImages: n => `You can attach up to ${n} images`,
      noteImageTooBig: "Image is too large (max ~4MB)",
      noteGeneralBadge: "General note",
      addNoteFromTest: "🗒️ Add to notebook",
      noteJustNow: "just now"
    }
  };

  let DATA = null;
  let TOP10 = null;
  let top10Index = 0;
  let progress = loadProgress();
  let findings = loadFindings();
  let notebook = loadNotebook(); // local-mode notebook: array of note objects
  let sessionNotes = [];         // DB-mode notebook cache for currentSession
  let notebookFilterTestId = "";
  let noteEditorImages = [];     // {name, data} being edited in the note editor
  let saveTimers = {};
  let currentCategoryId = null;
  let currentFilter = "all"; // all | done | pending
  let currentLang = loadLang();
  let currentTheme = loadTheme();
  let dbOnline = false;
  let currentSession = null;   // {id, name, tester_name, target_url, status, ...}
  let sessionResults = {};     // test_id -> backend result row (only when a session is active)

  function loadLang(){
    try{ return localStorage.getItem(LANG_KEY) || "tr"; }catch(e){ return "tr"; }
  }
  function saveLang(l){
    try{ localStorage.setItem(LANG_KEY, l); }catch(e){}
  }
  function loadTheme(){
    try{ return localStorage.getItem(THEME_KEY) || "midnight"; }catch(e){ return "midnight"; }
  }
  function saveTheme(t){
    try{ localStorage.setItem(THEME_KEY, t); }catch(e){}
  }
  function t(key){
    return (I18N[currentLang] && I18N[currentLang][key]) || I18N.tr[key] || key;
  }

  const iconPaths = {
    search: '<path d="M21 21l-4.3-4.3M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4z"/>',
    settings: '<path d="M12 15a3 3 0 100-6 3 3 0 000 6z"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09a1.65 1.65 0 00-1-1.51 1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09a1.65 1.65 0 001.51-1 1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/>',
    id: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M15 8h4M15 12h4M6 16h12"/>',
    lock: '<rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
    shield: '<path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-4z"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
    code: '<path d="M8 4L2 12l6 8M16 4l6 8-6 8"/>',
    alert: '<path d="M12 2L1 21h22L12 2z"/><path d="M12 9v5M12 17h.01"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M10.5 12.5L20 3M17 6l3 3M14 9l2 2"/>',
    flow: '<circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7 7l8 9M17 7L9.5 15.5"/>',
    browser: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/>',
    api: '<path d="M4 9h5V4M4 9l6-6M20 15h-5v5M20 15l-6 6"/><circle cx="12" cy="12" r="2.5"/>'
  };

  function loadProgress(){
    try{ return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}; }
    catch(e){ return {}; }
  }
  function saveProgress(){
    try{ localStorage.setItem(STORAGE_KEY, JSON.stringify(progress)); }catch(e){}
  }

  function loadFindings(){
    try{ return JSON.parse(localStorage.getItem(FINDINGS_KEY)) || {}; }
    catch(e){ return {}; }
  }
  function saveFindings(){
    try{ localStorage.setItem(FINDINGS_KEY, JSON.stringify(findings)); }catch(e){}
  }

  // Not Defteri (yerel mod) — DB oturumu açık değilken notlar burada saklanır.
  function loadNotebook(){
    try{
      const arr = JSON.parse(localStorage.getItem(NOTEBOOK_KEY));
      return Array.isArray(arr) ? arr : [];
    }catch(e){ return []; }
  }
  function saveNotebook(){
    try{ localStorage.setItem(NOTEBOOK_KEY, JSON.stringify(notebook)); }catch(e){}
  }

  // Returns the current finding {text, severity} for a test item, reading
  // from the active DB session's results when one is open, otherwise from
  // the local-only findings store.
  function getFindingData(testId){
    if(currentSession){
      const r = sessionResults[testId];
      return { text: (r && r.finding) || "", severity: (r && r.severity) || "info" };
    }
    const f = findings[testId];
    return { text: (f && f.text) || "", severity: (f && f.severity) || "info" };
  }

  function scheduleFindingSave(testId){
    clearTimeout(saveTimers[testId]);
    saveTimers[testId] = setTimeout(()=> saveFinding(testId), 700);
  }

  function readFindingInputs(testId){
    const safeId = CSS && CSS.escape ? CSS.escape(testId) : testId;
    const ta = document.querySelector(`.finding-textarea[data-id="${safeId}"]`);
    const sel = document.querySelector(`.severity-select[data-id="${safeId}"]`);
    return { text: ta ? ta.value : "", severity: sel ? sel.value : "info" };
  }

  function setFindingStatus(testId, msg, isError){
    const safeId = CSS && CSS.escape ? CSS.escape(testId) : testId;
    const el = document.querySelector(`.finding-status[data-id="${safeId}"]`);
    if(!el) return;
    el.textContent = msg;
    el.classList.toggle('error', !!isError);
    if(msg){
      clearTimeout(el._clearTimer);
      el._clearTimer = setTimeout(()=>{ el.textContent = ""; }, 2200);
    }
  }

  function refreshFindingBadge(testId){
    const safeId = CSS && CSS.escape ? CSS.escape(testId) : testId;
    const head = document.querySelector(`.test-item[data-id="${safeId}"] .test-item-head`);
    if(!head) return;
    let badge = head.querySelector('.severity-badge');
    const fd = getFindingData(testId);
    if(fd.text && fd.text.trim()){
      if(!badge){
        badge = document.createElement('span');
        badge.className = 'severity-badge';
        const title = head.querySelector('.test-item-title');
        if(title) title.insertAdjacentElement('afterend', badge);
      }
      badge.className = `severity-badge sev-${fd.severity || 'info'}`;
      badge.textContent = t('severity_' + (fd.severity || 'info'));
    } else if(badge){
      badge.remove();
    }
  }

  function saveFinding(testId){
    const { text, severity } = readFindingInputs(testId);
    if(currentSession){
      persistFinding(testId, text, severity);
      return;
    }
    if(!text.trim() && severity === 'info'){
      delete findings[testId];
    } else {
      findings[testId] = { text, severity, updatedAt: new Date().toISOString() };
    }
    saveFindings();
    refreshFindingBadge(testId);
    setFindingStatus(testId, t('findingSavedToast'), false);
  }

  function persistFinding(testId, text, severity){
    if(!currentSession) return Promise.resolve();
    const payload = { finding: text, severity };
    const existing = sessionResults[testId];
    const req = existing
      ? apiRequest(`/sessions/${currentSession.id}/results/${testId}`, { method: 'PUT', body: JSON.stringify(payload) })
      : apiRequest(`/sessions/${currentSession.id}/results`, { method: 'POST', body: JSON.stringify(Object.assign({ test_id: testId, status: 'pending' }, payload)) });
    return req.then(result => {
      sessionResults[testId] = result;
      refreshFindingBadge(testId);
      setFindingStatus(testId, t('findingSavedToast'), false);
    }).catch(err => {
      setFindingStatus(testId, err.message || t('findingSaveError'), true);
    });
  }

  function allTests(){
    const arr = [];
    DATA.categories.forEach(c => c.tests.forEach(t => arr.push({...t, catId:c.id, catCode:c.code, catName:c.name})));
    return arr;
  }

  function stats(){
    const tests = allTests();
    const total = tests.length;
    const done = tests.filter(t => progress[t.id]).length;
    return { total, done, pending: total-done, categories: DATA.categories.length,
             pct: total ? Math.round((done/total)*100) : 0 };
  }

  function icon(name, cls){
    return `<svg class="${cls||''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${iconPaths[name]||iconPaths.code}</svg>`;
  }

  function applyI18n(){
    document.documentElement.lang = currentLang;
    document.querySelectorAll('[data-i18n]').forEach(el=>{
      const key = el.getAttribute('data-i18n');
      el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el=>{
      const key = el.getAttribute('data-i18n-placeholder');
      el.setAttribute('placeholder', t(key));
    });
    const langSelect = document.getElementById('langSelect');
    if(langSelect) langSelect.value = currentLang;
  }

  function applyTheme(){
    document.documentElement.setAttribute('data-theme', currentTheme);
    updateThemeTrigger();
  }

  function currentThemeObj(){
    return THEMES.find(th => th.id === currentTheme) || THEMES[0];
  }

  function updateThemeTrigger(){
    const th = currentThemeObj();
    const swatch = document.getElementById('themeTriggerSwatch');
    const name = document.getElementById('themeTriggerName');
    if(swatch) swatch.style.background = `linear-gradient(135deg,${th.primary},${th.secondary})`;
    if(name) name.textContent = `${th.emoji||''} ${th.name}`.trim();
  }

  function renderThemeGrid(){
    const grid = document.getElementById('themeGrid');
    if(!grid) return;
    grid.innerHTML = THEMES.map(th => `
      <button type="button" class="theme-card ${th.id===currentTheme?'active':''}" data-theme-id="${th.id}">
        <span class="theme-card-preview" style="background:linear-gradient(135deg,${th.primary},${th.secondary})">
          <span class="theme-card-emoji">${th.emoji||''}</span>
          <span class="theme-card-check">✓</span>
        </span>
        <span class="theme-card-info">
          <span class="theme-card-name">${th.name}</span>
          <span class="theme-card-desc">${(th.desc && th.desc[currentLang]) || ''}</span>
        </span>
      </button>
    `).join('');
    grid.querySelectorAll('.theme-card').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        currentTheme = btn.dataset.themeId;
        saveTheme(currentTheme);
        applyTheme();
        grid.querySelectorAll('.theme-card').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
      });
    });
  }

  function openThemeModal(){
    renderThemeGrid();
    document.getElementById('themeOverlay').classList.add('open');
  }
  function closeThemeModal(){
    document.getElementById('themeOverlay').classList.remove('open');
  }

  function renderSidebar(){
    const nav = document.getElementById('categoryNav');
    nav.innerHTML = DATA.categories.map(c => {
      const done = c.tests.filter(t => progress[t.id]).length;
      return `<button class="nav-item" data-cat="${c.id}">
        <span class="dot"></span>${c.name}
        <span class="count">${done}/${c.tests.length}</span>
      </button>`;
    }).join('');
    nav.querySelectorAll('.nav-item').forEach(el=>{
      el.addEventListener('click', ()=> openCategory(el.dataset.cat));
    });
  }

  function renderDashboard(){
    const s = stats();
    document.getElementById('ringFill').style.background =
      `conic-gradient(#6366f1 0 ${s.pct}%, rgba(255,255,255,.08) ${s.pct}% 100%)`;
    document.getElementById('ringPct').textContent = s.pct + '%';
    document.getElementById('statDone').textContent = s.done;
    document.getElementById('statPending').textContent = s.pending;
    document.getElementById('statCategories').textContent = s.categories;
    document.getElementById('statTotal').textContent = s.total;

    const grid = document.getElementById('categoriesGrid');
    grid.innerHTML = DATA.categories.map(c => {
      const done = c.tests.filter(t => progress[t.id]).length;
      const pct = Math.round((done/c.tests.length)*100);
      return `<div class="category-card" data-cat="${c.id}">
        <div class="badge">${c.code}</div>
        ${icon(c.icon)}
        <h4>${c.name}</h4>
        <p>${c.description}</p>
        <div class="cat-progress-row">
          <div class="cat-progress-bar"><div class="cat-progress-fill" style="width:${pct}%"></div></div>
          <div class="cat-progress-text">${done}/${c.tests.length}</div>
        </div>
      </div>`;
    }).join('');
    grid.querySelectorAll('.category-card').forEach(el=>{
      el.addEventListener('click', ()=> openCategory(el.dataset.cat));
    });
  }

  function escapeHtml(s){
    return s.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }

  function renderTestItem(test){
    const done = !!progress[test.id];
    const fd = getFindingData(test.id);
    const hasFinding = fd.text && fd.text.trim();
    return `<div class="test-item ${done?'done':''}" data-id="${test.id}">
      <div class="test-item-head">
        <button class="test-check ${done?'checked':''}" data-id="${test.id}" title="${t('testEditedTitle')}">
          ${icon('code').replace('code','')}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M4 12l5 5L20 6"/></svg>
        </button>
        <span class="test-item-code">${test.id}</span>
        <span class="test-item-title">${escapeHtml(test.title)}</span>
        ${hasFinding ? `<span class="severity-badge sev-${fd.severity}">${t('severity_'+fd.severity)}</span>` : ''}
        <svg class="test-item-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
      </div>
      <div class="test-item-detail">
        <div class="test-item-detail-inner">
          <div class="detail-block">
            <h5>${t('descriptionLabel')}</h5>
            <p>${escapeHtml(test.description)}</p>
          </div>
          <div class="detail-block">
            <h5>${t('howToLabel')}</h5>
            <ol>${test.steps.map(s=>`<li>${escapeHtml(s)}</li>`).join('')}</ol>
          </div>
          <div class="detail-block">
            <h5>${t('exampleLabel')}</h5>
            <div class="example-box">${escapeHtml(test.example)}<button class="copy-btn" data-copy="${encodeURIComponent(test.example)}">${t('copyBtn')}</button></div>
          </div>
          <div class="detail-block">
            <h5>${t('toolsLabel')}</h5>
            <div class="tools-row">${test.tools.map(tool=>`<span class="tool-chip">${escapeHtml(tool)}</span>`).join('')}</div>
          </div>
          <div class="detail-block finding-block" style="margin-bottom:0">
            <div class="finding-head">
              <h5 style="margin:0">${t('findingsLabel')}</h5>
              <select class="severity-select" data-id="${test.id}" title="${t('severityLabel')}">
                ${SEVERITIES.map(s=>`<option value="${s}" ${fd.severity===s?'selected':''}>${t('severity_'+s)}</option>`).join('')}
              </select>
            </div>
            <textarea class="finding-textarea" data-id="${test.id}" placeholder="${t('findingsPlaceholder')}">${escapeHtml(fd.text)}</textarea>
            <div class="finding-status" data-id="${test.id}"></div>
            <button type="button" class="copy-btn add-note-btn" data-test-id="${test.id}" style="margin-top:10px">${t('addNoteFromTest')}</button>
          </div>
        </div>
      </div>
    </div>`;
  }

  function openCategory(catId, focusTestId){
    const cat = DATA.categories.find(c=>c.id===catId);
    if(!cat) return;
    currentCategoryId = catId;
    currentFilter = "all";
    document.getElementById('panelTitle').textContent = `${cat.code} · ${cat.name}`;
    document.getElementById('panelDesc').textContent = cat.description;
    document.getElementById('itemSearch').value = "";
    renderTestList();
    document.getElementById('categoryOverlay').classList.add('open');
    document.body.style.overflow = 'hidden';
    if(focusTestId){
      setTimeout(()=>{
        const el = document.querySelector(`.test-item[data-id="${focusTestId}"]`);
        if(el){ el.classList.add('open'); el.scrollIntoView({behavior:'smooth', block:'center'}); }
      }, 60);
    }
  }

  function closeCategory(){
    document.getElementById('categoryOverlay').classList.remove('open');
    document.body.style.overflow = '';
  }

  function renderTestList(){
    const cat = DATA.categories.find(c=>c.id===currentCategoryId);
    if(!cat) return;
    const q = document.getElementById('itemSearch').value.trim().toLowerCase();
    let items = cat.tests;
    if(currentFilter === 'done') items = items.filter(t=>progress[t.id]);
    if(currentFilter === 'pending') items = items.filter(t=>!progress[t.id]);
    if(q) items = items.filter(x => x.title.toLowerCase().includes(q) || x.id.toLowerCase().includes(q) || x.description.toLowerCase().includes(q));
    const list = document.getElementById('testList');
    if(!items.length){
      list.innerHTML = `<div class="search-empty">${t('noMatchInCategory')}</div>`;
      return;
    }
    list.innerHTML = items.map(renderTestItem).join('');
  }

  function toggleDone(id){
    progress[id] = !progress[id];
    const done = progress[id];
    if(currentSession){
      persistResult(id, done).catch(err => {
        // revert on failure
        progress[id] = !done;
        renderSidebar(); renderDashboard();
        if(currentCategoryId) renderTestList();
        showToast(t('resultSaveError'));
      });
    } else {
      saveProgress();
    }
    renderSidebar();
    renderDashboard();
    if(currentCategoryId) renderTestList();
    showToast(progress[id] ? t('markDoneToast') : t('markPendingToast'));
  }

  function showToast(msg){
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(el._t);
    el._t = setTimeout(()=> el.classList.remove('show'), 2200);
  }

  function doSearch(q){
    const box = document.getElementById('searchResults');
    q = q.trim().toLowerCase();
    if(!q){ box.classList.remove('open'); box.innerHTML=''; return; }
    const results = allTests().filter(t =>
      t.title.toLowerCase().includes(q) || t.id.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)
    ).slice(0, 12);
    if(!results.length){
      box.innerHTML = `<div class="search-empty">${escapeHtml(t('noSearchResults')(q))}</div>`;
    } else {
      box.innerHTML = results.map(r => `
        <div class="search-result-item" data-cat="${r.catId}" data-test="${r.id}">
          <div class="sr-title">${escapeHtml(r.title)}</div>
          <div class="sr-meta">${r.catCode} · ${r.id} ${progress[r.id]?'· '+t('completedTag'):''}</div>
        </div>`).join('');
    }
    box.classList.add('open');
  }

  function exportReport(){
    const s = stats();
    let out = `${t('reportTitle')}\n`;
    if(currentSession){
      out += `${t('navSessions')}: ${currentSession.name}\n`;
      if(currentSession.tester_name) out += `${t('sessionTester')}: ${currentSession.tester_name}\n`;
      if(currentSession.target_url) out += `${t('sessionTarget')}: ${currentSession.target_url}\n`;
    }
    out += `${t('reportCreated')}: ${new Date().toLocaleString(t('dateLocale'))}\n`;
    out += `${t('reportProgress')}: ${s.done}/${s.total} (%${s.pct})\n\n`;
    DATA.categories.forEach(c=>{
      out += `\n=== ${c.code} · ${c.name} ===\n`;
      c.tests.forEach(test=>{
        out += `[${progress[test.id]?'x':' '}] ${test.id} - ${test.title}\n`;
        const fd = getFindingData(test.id);
        if(fd.text && fd.text.trim()){
          out += `    ${t('severityLabel')}: ${t('severity_'+fd.severity)}\n`;
          out += `    ${t('findingsLabel')}: ${fd.text.trim().replace(/\n/g, '\n    ')}\n`;
        }
      });
    });
    const blob = new Blob([out], {type:'text/plain;charset=utf-8'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'wstg-pentest-report.txt';
    a.click();
    showToast(t('reportDownloadedToast'));
  }

  function resetProgress(){
    if(currentSession){
      if(!confirm(t('sessionResetConfirm'))) return;
      const ids = Object.keys(sessionResults);
      Promise.all(ids.map(tid => apiRequest(`/sessions/${currentSession.id}/results/${tid}`, { method: 'DELETE' }).catch(()=>{})))
        .then(()=>{
          progress = {};
          sessionResults = {};
          renderSidebar();
          renderDashboard();
          if(currentCategoryId) renderTestList();
          updateSessionUI();
          showToast(t('progressResetToast'));
        });
      return;
    }
    if(!confirm(t('resetConfirm'))) return;
    progress = {};
    findings = {};
    saveProgress();
    saveFindings();
    renderSidebar();
    renderDashboard();
    if(currentCategoryId) renderTestList();
    showToast(t('progressResetToast'));
  }

  function copyToClipboard(text){
    navigator.clipboard?.writeText(text).then(()=> showToast(t('copiedToast'))).catch(()=>{});
  }

  /* ===================== OWASP TOP 10:2025 ===================== */

  function loadTop10Data(){
    return fetch(TOP10_FILES[currentLang] || TOP10_FILES.tr)
      .then(r => r.json())
      .then(data => { TOP10 = data; })
      .catch(err => { console.error(err); });
  }

  function renderTop10Grid(){
    const grid = document.getElementById('top10Grid');
    if(!grid) return;
    if(!TOP10){ grid.innerHTML = ''; return; }
    grid.innerHTML = TOP10.top10.map((r, idx) => `
      <div class="category-card top10-card" data-idx="${idx}">
        <div class="top10-card-top">
          <span class="top10-rank-num">#${r.rank}</span>
          <div class="top10-badges">
            ${r.newIn2025 ? `<span class="top10-new-pill">${t('top10NewBadge')}</span>` : ''}
            <span class="top10-cwe-pill">${t('top10CweCount')(r.cweCount)}</span>
          </div>
        </div>
        <h4>${escapeHtml(r.id)} · ${escapeHtml(r.title)}</h4>
        <p>${escapeHtml(r.shortDesc)}</p>
      </div>
    `).join('');
    grid.querySelectorAll('.top10-card').forEach(el=>{
      el.addEventListener('click', ()=> openTop10Detail(parseInt(el.dataset.idx, 10)));
    });
  }

  function findWstgLocation(testId){
    if(!DATA) return null;
    for(const c of DATA.categories){
      const found = c.tests.find(x => x.id === testId);
      if(found) return { catId: c.id, testId: found.id };
    }
    return null;
  }

  function renderTop10Detail(){
    if(!TOP10) return;
    const r = TOP10.top10[top10Index];
    document.getElementById('top10PanelRank').textContent = `#${r.rank} · ${r.id}`;
    document.getElementById('top10PanelTitle').textContent = r.title;
    document.getElementById('top10PanelShortDesc').textContent = r.shortDesc;

    const wstgChips = (r.wstgRefs || []).map(id => {
      const loc = findWstgLocation(id);
      return loc
        ? `<button class="wstg-ref-chip" data-cat="${loc.catId}" data-test="${loc.testId}">${escapeHtml(id)}</button>`
        : `<span class="wstg-ref-chip" style="cursor:default;opacity:.6">${escapeHtml(id)}</span>`;
    }).join('');

    const dots = TOP10.top10.map((item, i) =>
      `<span class="top10-nav-dot ${i===top10Index?'active':''}" data-idx="${i}" title="${escapeHtml(item.id)}"></span>`
    ).join('');

    const body = document.getElementById('top10PanelBody');
    body.innerHTML = `
      <div class="detail-block">
        <h5>${t('top10DescLabel')}</h5>
        <p>${escapeHtml(r.description)}</p>
      </div>
      <div class="detail-block">
        <h5>${t('top10HowItHappensLabel')}</h5>
        <ul>${r.howItHappens.map(x=>`<li>${escapeHtml(x)}</li>`).join('')}</ul>
      </div>
      <div class="detail-block">
        <h5>${t('top10HowToTestLabel')}</h5>
        <ol>${r.howToTest.map(x=>`<li>${escapeHtml(x)}</li>`).join('')}</ol>
      </div>
      <div class="detail-block">
        <h5>${t('top10ScenarioLabel')}</h5>
        <p>${escapeHtml(r.exampleScenario)}</p>
      </div>
      <div class="detail-block">
        <h5>${t('top10PayloadLabel')}</h5>
        <div class="example-box">${escapeHtml(r.examplePayload)}<button class="copy-btn" data-copy="${encodeURIComponent(r.examplePayload)}">${t('copyBtn')}</button></div>
      </div>
      <div class="detail-block">
        <h5>${t('top10PreventionLabel')}</h5>
        <ul>${r.prevention.map(x=>`<li>${escapeHtml(x)}</li>`).join('')}</ul>
      </div>
      <div class="detail-block">
        <h5>${t('top10CweLabel')}</h5>
        <div class="tools-row">${r.notableCwe.map(c=>`<span class="tool-chip">${escapeHtml(c)}</span>`).join('')}</div>
      </div>
      <div class="detail-block">
        <h5>${t('top10ToolsLabel')}</h5>
        <div class="tools-row">${r.tools.map(x=>`<span class="tool-chip">${escapeHtml(x)}</span>`).join('')}</div>
      </div>
      ${r.wstgRefs && r.wstgRefs.length ? `
      <div class="detail-block" style="margin-bottom:0">
        <h5>${t('top10WstgLabel')}</h5>
        <div class="tools-row">${wstgChips}</div>
      </div>` : ''}
      <div class="top10-nav-footer">
        <button class="top10-nav-btn" id="top10PrevBtn" ${top10Index===0?'disabled':''}>${t('top10PrevBtn')}</button>
        <div class="top10-nav-dots">${dots}</div>
        <button class="top10-nav-btn" id="top10NextBtn" ${top10Index===TOP10.top10.length-1?'disabled':''}>${t('top10NextBtn')}</button>
      </div>
    `;

    body.querySelectorAll('.wstg-ref-chip[data-cat]').forEach(el=>{
      el.addEventListener('click', ()=>{
        closeTop10Detail();
        openCategory(el.dataset.cat, el.dataset.test);
      });
    });
    const prevBtn = document.getElementById('top10PrevBtn');
    const nextBtn = document.getElementById('top10NextBtn');
    if(prevBtn) prevBtn.addEventListener('click', ()=>{
      if(top10Index > 0){ top10Index--; renderTop10Detail(); document.getElementById('top10Overlay').scrollTop = 0; }
    });
    if(nextBtn) nextBtn.addEventListener('click', ()=>{
      if(top10Index < TOP10.top10.length-1){ top10Index++; renderTop10Detail(); document.getElementById('top10Overlay').scrollTop = 0; }
    });
    body.querySelectorAll('.top10-nav-dot').forEach(el=>{
      el.addEventListener('click', ()=>{ top10Index = parseInt(el.dataset.idx, 10); renderTop10Detail(); });
    });
    body.querySelectorAll('.copy-btn').forEach(btn=>{
      btn.addEventListener('click', ()=> copyToClipboard(decodeURIComponent(btn.dataset.copy)));
    });
  }

  function openTop10Detail(idx){
    top10Index = idx;
    renderTop10Detail();
    document.getElementById('top10Overlay').classList.add('open');
  }
  function closeTop10Detail(){
    document.getElementById('top10Overlay').classList.remove('open');
  }

  /* ===================== DB / SESSIONS ===================== */

  function apiRequest(path, options){
    return fetch(API_BASE + path, Object.assign({
      headers: { 'Content-Type': 'application/json' }
    }, options || {})).then(async res => {
      if(!res.ok){
        let msg = res.statusText;
        try{ const j = await res.json(); msg = j.error || msg; }catch(e){}
        throw new Error(msg);
      }
      if(res.status === 204) return null;
      return res.json();
    });
  }

  function checkDb(){
    const ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = ctrl ? setTimeout(()=>ctrl.abort(), 2500) : null;
    return fetch(API_BASE + '/sessions', { signal: ctrl ? ctrl.signal : undefined })
      .then(res => { clearTimeout(timer); return res.ok; })
      .catch(() => { clearTimeout(timer); return false; });
  }

  function loadSavedSessionId(){
    try{ return localStorage.getItem(SESSION_ID_KEY); }catch(e){ return null; }
  }
  function saveSessionId(id){
    try{ id ? localStorage.setItem(SESSION_ID_KEY, id) : localStorage.removeItem(SESSION_ID_KEY); }catch(e){}
  }
  function getSkipFlag(){
    try{ return localStorage.getItem(SKIP_SESSION_KEY) === '1'; }catch(e){ return false; }
  }
  function setSkipFlag(v){
    try{ v ? localStorage.setItem(SKIP_SESSION_KEY, '1') : localStorage.removeItem(SKIP_SESSION_KEY); }catch(e){}
  }

  function updateSessionUI(){
    const chip = document.getElementById('sessionChip');
    const topBtn = document.getElementById('topbarSessionBtn');
    if(!chip || !topBtn) return;
    if(currentSession){
      const done = Object.values(sessionResults).filter(r => r.status && r.status !== 'pending').length;
      const total = allTests().length;
      chip.style.display = 'flex';
      document.getElementById('sessionChipName').textContent = currentSession.name;
      document.getElementById('sessionChipSub').textContent = `${done}/${total}`;
      topBtn.style.display = 'inline-flex';
      topBtn.textContent = `📋 ${currentSession.name}`;
      topBtn.title = t('navSessions');
    } else {
      chip.style.display = 'none';
      topBtn.style.display = dbOnline ? 'inline-flex' : 'none';
      topBtn.textContent = `📂 ${t('navSessions')}`;
    }
  }

  function progressFromResults(results){
    const p = {};
    sessionResults = {};
    (results || []).forEach(r => {
      sessionResults[r.test_id] = r;
      if(r.status && r.status !== 'pending') p[r.test_id] = true;
    });
    return p;
  }

  function openSessionById(id){
    return Promise.all([ apiRequest(`/sessions/${id}`), apiRequest(`/sessions/${id}/results`) ])
      .then(([session, results]) => {
        currentSession = session;
        progress = progressFromResults(results);
        sessionNotes = [];
        saveSessionId(session.id);
        setSkipFlag(false);
        renderSidebar(); renderDashboard();
        if(currentCategoryId) renderTestList();
        updateSessionUI();
        closeSessionGate();
      });
  }

  function renderSessionList(){
    const box = document.getElementById('sessionListBody');
    box.innerHTML = `<div class="search-empty">${escapeHtml(t('loadingSessions'))}</div>`;
    apiRequest('/sessions').then(sessions => {
      if(!sessions.length){
        box.innerHTML = `<div class="search-empty">${escapeHtml(t('noSessionsYet'))}</div>`;
        return;
      }
      box.innerHTML = `<div class="session-list">${sessions.map(s => {
        const total = allTests().length;
        const done = s.completed_tests || 0;
        const pct = total ? Math.round((done/total)*100) : 0;
        const active = currentSession && currentSession.id === s.id;
        return `<div class="session-card" data-id="${s.id}">
          <div class="session-card-top">
            <div>
              <div class="session-card-name">${escapeHtml(s.name)}${active ? ' ✅' : ''}</div>
              <div class="session-card-meta">
                <span>👤 ${escapeHtml(s.tester_name || '—')}</span>
                <span>🎯 ${escapeHtml(s.target_url || '—')}</span>
                <span>📅 ${new Date(s.created_at).toLocaleString(t('dateLocale'))}</span>
              </div>
            </div>
            <span class="session-status-pill ${s.status === 'completed' ? 'completed' : 'active'}">${s.status === 'completed' ? t('statusCompleted') : t('statusActive')}</span>
          </div>
          <div class="session-card-progress">
            <div class="cat-progress-bar" style="flex:1"><div class="cat-progress-fill" style="width:${pct}%"></div></div>
            <div class="cat-progress-text">${done}/${total}</div>
          </div>
          <div class="session-card-actions">
            <button data-action="open" data-id="${s.id}">${t('startTest')}</button>
            <button data-action="delete" data-id="${s.id}" class="danger">🗑️</button>
          </div>
        </div>`;
      }).join('')}</div>`;
    }).catch(err => {
      box.innerHTML = `<div class="search-empty">${escapeHtml(t('sessionsLoadError'))}<br><small>${escapeHtml(String(err.message||err))}</small></div>`;
    });
  }

  function openSessionGate(closable){
    const overlay = document.getElementById('sessionGateOverlay');
    document.getElementById('closeSessionGate').style.display = closable ? '' : 'none';
    document.getElementById('dbStatusLabel').innerHTML = dbOnline
      ? `<span class="db-status online">${t('dbOnline')}</span>`
      : `<span class="db-status offline">${t('dbOffline')}</span>`;
    document.getElementById('newSessionBtn').style.display = dbOnline ? '' : 'none';
    document.getElementById('skipSessionBtn').style.display = dbOnline ? '' : 'none';
    if(dbOnline) renderSessionList();
    else document.getElementById('sessionListBody').innerHTML = '';
    overlay.classList.add('open');
  }
  function closeSessionGate(){
    document.getElementById('sessionGateOverlay').classList.remove('open');
  }

  function openNewSessionOverlay(){
    document.getElementById('sessionNameInput').value = '';
    document.getElementById('testerNameInput').value = '';
    document.getElementById('targetUrlInput').value = '';
    document.getElementById('newSessionOverlay').classList.add('open');
    setTimeout(()=> document.getElementById('sessionNameInput').focus(), 50);
  }
  function closeNewSessionOverlay(){
    document.getElementById('newSessionOverlay').classList.remove('open');
  }

  function createSessionSubmit(){
    const name = document.getElementById('sessionNameInput').value.trim();
    if(!name){ showToast(t('sessionNameRequired')); return; }
    const payload = {
      name,
      tester_name: document.getElementById('testerNameInput').value.trim(),
      target_url: document.getElementById('targetUrlInput').value.trim()
    };
    apiRequest('/sessions', { method: 'POST', body: JSON.stringify(payload) })
      .then(session => {
        closeNewSessionOverlay();
        return openSessionById(session.id);
      })
      .then(()=> showToast(t('sessionCreated')))
      .catch(err => showToast(err.message || t('resultSaveError')));
  }

  function deleteSessionUI(id){
    if(!confirm(t('sessionDeleteConfirm'))) return;
    apiRequest(`/sessions/${id}`, { method: 'DELETE' }).then(()=>{
      if(currentSession && currentSession.id === id){
        currentSession = null;
        sessionResults = {};
        sessionNotes = [];
        saveSessionId(null);
        progress = loadProgress();
        renderSidebar(); renderDashboard();
        updateSessionUI();
      }
      renderSessionList();
      showToast(t('sessionDeleted'));
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  function persistResult(testId, done){
    if(!currentSession) return Promise.resolve();
    const status = done ? 'passed' : 'pending';
    const existing = sessionResults[testId];
    const req = existing
      ? apiRequest(`/sessions/${currentSession.id}/results/${testId}`, { method: 'PUT', body: JSON.stringify({ status }) })
      : apiRequest(`/sessions/${currentSession.id}/results`, { method: 'POST', body: JSON.stringify({ test_id: testId, status }) });
    return req.then(result => { sessionResults[testId] = result; updateSessionUI(); });
  }

  // ========================
  // Dış Araç İçe Aktarma (Nmap / Nikto / WPScan)
  // ========================

  let lastImportFindings = [];

  function testInfoById(id){
    if(!DATA) return null;
    for(const c of DATA.categories){
      for(const tItem of c.tests){
        if(tItem.id === id) return { title: tItem.title, catCode: c.code, catId: c.id };
      }
    }
    return null;
  }

  function maxSeverityLocal(a, b){
    const order = (window.WSTGImport && window.WSTGImport.SEVERITIES) || ["info","low","medium","high","critical"];
    return order.indexOf(b) > order.indexOf(a) ? b : a;
  }

  function openImportModal(){
    document.getElementById('importPreviewWrap').style.display = 'none';
    document.getElementById('importFileInput').value = '';
    const status = document.getElementById('importStatus');
    status.textContent = '';
    status.classList.remove('error');
    lastImportFindings = [];
    document.getElementById('importOverlay').classList.add('open');
  }
  function closeImportModal(){
    document.getElementById('importOverlay').classList.remove('open');
  }

  function analyzeImportFile(){
    const fileInput = document.getElementById('importFileInput');
    const statusEl = document.getElementById('importStatus');
    const file = fileInput.files && fileInput.files[0];
    statusEl.classList.remove('error');
    if(!file){
      statusEl.textContent = t('importNoFile');
      statusEl.classList.add('error');
      return;
    }
    if(!window.WSTGImport){
      statusEl.textContent = t('importParseError');
      statusEl.classList.add('error');
      return;
    }
    statusEl.textContent = t('importAnalyzing');
    const toolHint = document.getElementById('importToolSelect').value;
    const reader = new FileReader();
    reader.onload = () => {
      try{
        const result = window.WSTGImport.parse(String(reader.result), toolHint, file.name);
        lastImportFindings = (result.findings || []).map((f, i) => Object.assign({ _rowId: 'imp' + i, _checked: true }, f));
        renderImportPreview();
        statusEl.textContent = lastImportFindings.length ? '' : t('importNoFindings');
      }catch(err){
        document.getElementById('importPreviewWrap').style.display = 'none';
        statusEl.textContent = t('importParseError') + ': ' + (err && err.message ? err.message : String(err));
        statusEl.classList.add('error');
      }
    };
    reader.onerror = () => {
      statusEl.textContent = t('importParseError');
      statusEl.classList.add('error');
    };
    reader.readAsText(file);
  }

  function renderImportPreview(){
    const wrap = document.getElementById('importPreviewWrap');
    const list = document.getElementById('importPreviewList');
    const countEl = document.getElementById('importPreviewCount');
    if(!lastImportFindings.length){ wrap.style.display = 'none'; return; }
    wrap.style.display = '';
    countEl.textContent = t('importPreviewCount')(lastImportFindings.length);
    list.innerHTML = lastImportFindings.map(f => {
      const idsHtml = (f.testIds || []).map(id => {
        const meta = testInfoById(id);
        return `<span class="import-preview-ids">${escapeHtml(id)}${meta ? ' · ' + escapeHtml(meta.title) : ''}</span>`;
      }).join(' ');
      return `<div class="import-preview-item ${f.unmatched ? 'unmatched' : ''}">
        <input type="checkbox" class="import-check" data-row="${f._rowId}" ${f._checked ? 'checked' : ''}>
        <div class="import-preview-body">
          <div class="import-preview-top">
            <span class="import-preview-title">${escapeHtml(f.title || '')}</span>
            <span class="severity-badge sev-${f.severity || 'info'}">${t('severity_' + (f.severity || 'info'))}</span>
            ${f.unmatched ? `<span class="severity-badge sev-info">${t('importUnmatchedTag')}</span>` : ''}
          </div>
          <div>${idsHtml}</div>
          ${f.detail ? `<div class="import-preview-detail">${escapeHtml(f.detail)}</div>` : ''}
          <div class="import-preview-source">${escapeHtml(f.source || '')}</div>
        </div>
      </div>`;
    }).join('');
  }

  function applyImportSelected(){
    const checked = lastImportFindings.filter(f => f._checked);
    if(!checked.length) return;
    checked.forEach(f => {
      (f.testIds || []).forEach(testId => {
        if(!testInfoById(testId)) return;
        const noteLine = `[${f.source || f.tool}] ${f.title}${f.detail ? '\n' + f.detail : ''}`;
        progress[testId] = true;
        if(currentSession){
          const existing = sessionResults[testId];
          const prevText = existing && existing.finding ? existing.finding + '\n\n' : '';
          const prevSeverity = existing && existing.severity ? existing.severity : 'info';
          persistFinding(testId, prevText + noteLine, maxSeverityLocal(prevSeverity, f.severity));
          persistResult(testId, true).catch(()=>{});
        } else {
          const existing = findings[testId];
          const prevText = existing && existing.text ? existing.text + '\n\n' : '';
          const prevSeverity = existing && existing.severity ? existing.severity : 'info';
          findings[testId] = { text: prevText + noteLine, severity: maxSeverityLocal(prevSeverity, f.severity), updatedAt: new Date().toISOString() };
        }
      });
    });
    if(!currentSession){ saveProgress(); saveFindings(); }
    renderSidebar();
    renderDashboard();
    if(currentCategoryId) renderTestList();
    showToast(t('importAppliedToast')(checked.length));
    closeImportModal();
  }

  // ========================
  // Not Defteri (Notebook)
  // ========================
  const MAX_NOTE_IMAGES = 8;
  const MAX_IMAGE_BYTES = 4 * 1024 * 1024;

  // Şu an aktif not listesini döner: DB oturumu açıksa backend cache'i,
  // değilse yerel (localStorage) not defterini.
  function activeNotes(){
    return currentSession ? sessionNotes : notebook;
  }

  function notebookTestOptionsHtml(selectedId){
    let html = `<option value="">${escapeHtml(t('noteGeneralOption'))}</option>`;
    DATA.categories.forEach(c=>{
      html += `<optgroup label="${escapeHtml(c.code + ' · ' + c.name)}">`;
      c.tests.forEach(test=>{
        html += `<option value="${test.id}" data-cat="${c.id}" ${selectedId===test.id?'selected':''}>${test.id} — ${escapeHtml(test.title)}</option>`;
      });
      html += `</optgroup>`;
    });
    return html;
  }

  function populateNotebookFilter(){
    const sel = document.getElementById('notebookTestFilter');
    if(!sel) return;
    const keepVal = notebookFilterTestId;
    sel.innerHTML = `<option value="">${escapeHtml(t('notebookFilterAll'))}</option><option value="__general__">${escapeHtml(t('notebookFilterGeneral'))}</option>` +
      DATA.categories.map(c => `<optgroup label="${escapeHtml(c.code + ' · ' + c.name)}">` +
        c.tests.map(test => `<option value="${test.id}">${test.id} — ${escapeHtml(test.title)}</option>`).join('') +
        `</optgroup>`).join('');
    sel.value = keepVal || "";
  }

  function formatNoteDate(iso){
    if(!iso) return t('noteJustNow');
    try{ return new Date(iso).toLocaleString(t('dateLocale')); }catch(e){ return iso; }
  }

  function renderNotebookList(){
    const list = document.getElementById('notebookList');
    if(!list) return;
    let notes = activeNotes().slice();
    if(notebookFilterTestId === '__general__') notes = notes.filter(n => !n.test_id);
    else if(notebookFilterTestId) notes = notes.filter(n => n.test_id === notebookFilterTestId);
    notes.sort((a,b) => new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0));

    if(!notes.length){
      list.innerHTML = `<div class="notebook-empty">${escapeHtml(t('noteEmptyList'))}</div>`;
      return;
    }

    list.innerHTML = notes.map(n=>{
      const info = n.test_id ? testInfoById(n.test_id) : null;
      const chip = info
        ? `<span class="note-card-test-chip">${escapeHtml(info.catCode)} · ${escapeHtml(n.test_id)}</span>`
        : `<span class="note-card-general-chip">${escapeHtml(t('noteGeneralBadge'))}</span>`;
      const images = Array.isArray(n.images) ? n.images : [];
      const thumbs = images.slice(0, 3).map(img => `<img src="${img.data}" alt="${escapeHtml(img.name||'')}" data-full="${img.data}">`).join('');
      const more = images.length > 3 ? `<span class="note-more-chip">+${images.length-3}</span>` : '';
      return `<div class="note-card" data-note-id="${n.id}">
        <div class="note-card-top">
          <div class="note-card-title">${escapeHtml(n.title && n.title.trim() ? n.title : t('noteEditorDesc'))}</div>
          <span class="severity-badge sev-${n.severity||'info'}">${t('severity_'+(n.severity||'info'))}</span>
        </div>
        ${chip}
        ${n.content ? `<div class="note-card-content">${escapeHtml(n.content)}</div>` : ''}
        ${images.length ? `<div class="note-card-images">${thumbs}${more}</div>` : ''}
        <div class="note-card-meta"><span>${formatNoteDate(n.updated_at || n.created_at)}</span></div>
      </div>`;
    }).join('');
  }

  function refreshNotebookUI(){
    populateNotebookFilter();
    renderNotebookList();
    const desc = document.getElementById('notebookDesc');
    if(desc) desc.textContent = currentSession ? t('notebookDesc') : t('notebookDescLocal');
  }

  function loadSessionNotes(){
    if(!currentSession) return Promise.resolve();
    return apiRequest(`/sessions/${currentSession.id}/notes`).then(notes=>{
      sessionNotes = notes || [];
    }).catch(()=>{ sessionNotes = []; });
  }

  function openNotebook(){
    notebookFilterTestId = "";
    const doOpen = ()=>{
      refreshNotebookUI();
      document.getElementById('notebookOverlay').classList.add('open');
    };
    if(currentSession){
      loadSessionNotes().then(doOpen);
    } else {
      doOpen();
    }
  }
  function closeNotebook(){
    document.getElementById('notebookOverlay').classList.remove('open');
  }

  function resetNoteImageInputsUI(){
    noteEditorImages = [];
    renderNoteImageThumbs();
    const fileInput = document.getElementById('noteImageInput');
    if(fileInput) fileInput.value = '';
  }

  function renderNoteImageThumbs(){
    const wrap = document.getElementById('noteImageThumbs');
    if(!wrap) return;
    wrap.innerHTML = noteEditorImages.map((img, idx) => `
      <div class="note-image-thumb" data-idx="${idx}">
        <img src="${img.data}" alt="${escapeHtml(img.name||'')}">
        <button type="button" class="remove-img" data-idx="${idx}" title="${escapeHtml(t('deleteNote'))}">&times;</button>
      </div>`).join('');
  }

  function setNoteEditorStatus(msg, isError){
    const el = document.getElementById('noteEditorStatus');
    if(!el) return;
    el.textContent = msg || '';
    el.classList.toggle('error', !!isError);
  }

  function fileToDataUrl(file){
    return new Promise((resolve, reject)=>{
      if(!file.type || file.type.indexOf('image/') !== 0){ reject(new Error('not-image')); return; }
      if(file.size > MAX_IMAGE_BYTES){ reject(new Error('too-big')); return; }
      const reader = new FileReader();
      reader.onload = () => resolve({ name: file.name || 'kanit', data: reader.result });
      reader.onerror = () => reject(new Error('read-error'));
      reader.readAsDataURL(file);
    });
  }

  function addImagesToEditor(files){
    const arr = Array.from(files || []);
    if(!arr.length) return;
    const remaining = MAX_NOTE_IMAGES - noteEditorImages.length;
    if(remaining <= 0){
      setNoteEditorStatus(t('noteTooManyImages')(MAX_NOTE_IMAGES), true);
      return;
    }
    const toAdd = arr.slice(0, remaining);
    Promise.all(toAdd.map(f => fileToDataUrl(f).catch(err => ({ __error: err.message }))))
      .then(results => {
        let hadError = false;
        results.forEach(r => {
          if(r && r.__error){ hadError = true; }
          else if(r) noteEditorImages.push(r);
        });
        renderNoteImageThumbs();
        if(hadError) setNoteEditorStatus(t('noteImageTooBig'), true);
        else if(arr.length > toAdd.length) setNoteEditorStatus(t('noteTooManyImages')(MAX_NOTE_IMAGES), true);
        else setNoteEditorStatus('', false);
      });
  }

  function openNoteEditor(existingNote, prefillTestId){
    const form = document.getElementById('noteEditorForm');
    form.reset();
    setNoteEditorStatus('', false);
    document.getElementById('noteEditId').value = existingNote ? existingNote.id : '';
    document.getElementById('noteEditorTitle').textContent = existingNote ? t('editNote') : t('newNote');
    document.getElementById('noteTitleInput').value = existingNote ? (existingNote.title || '') : '';
    document.getElementById('noteContentInput').value = existingNote ? (existingNote.content || '') : '';
    document.getElementById('noteSeveritySelect').value = existingNote ? (existingNote.severity || 'info') : 'info';
    document.getElementById('noteTestSelect').innerHTML = notebookTestOptionsHtml(existingNote ? existingNote.test_id : (prefillTestId || ''));
    if(!existingNote && prefillTestId) document.getElementById('noteTestSelect').value = prefillTestId;
    noteEditorImages = existingNote && Array.isArray(existingNote.images) ? existingNote.images.slice() : [];
    renderNoteImageThumbs();
    document.getElementById('deleteNoteBtn').style.display = existingNote ? '' : 'none';
    document.getElementById('noteEditorOverlay').classList.add('open');
    setTimeout(()=> document.getElementById('noteTitleInput').focus(), 50);
  }
  function closeNoteEditor(){
    document.getElementById('noteEditorOverlay').classList.remove('open');
  }

  function saveNoteFromEditor(){
    const id = document.getElementById('noteEditId').value;
    const title = document.getElementById('noteTitleInput').value.trim();
    const content = document.getElementById('noteContentInput').value.trim();
    const severity = document.getElementById('noteSeveritySelect').value;
    const testId = document.getElementById('noteTestSelect').value || null;
    const catId = testId ? (testInfoById(testId) || {}).catId || null : null;

    if(!content && !noteEditorImages.length){
      setNoteEditorStatus(t('noteContentRequired'), true);
      return;
    }

    if(currentSession){
      const payload = { title, content, severity, test_id: testId, category_id: catId, images: noteEditorImages };
      const req = id
        ? apiRequest(`/sessions/${currentSession.id}/notes/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
        : apiRequest(`/sessions/${currentSession.id}/notes`, { method: 'POST', body: JSON.stringify(payload) });
      req.then(()=> loadSessionNotes()).then(()=>{
        refreshNotebookUI();
        closeNoteEditor();
        showToast(t('noteSaved'));
      }).catch(err => setNoteEditorStatus(err.message || t('noteSaveError'), true));
      return;
    }

    const now = new Date().toISOString();
    if(id){
      const idx = notebook.findIndex(n => String(n.id) === String(id));
      if(idx > -1){
        notebook[idx] = Object.assign({}, notebook[idx], { title, content, severity, test_id: testId, category_id: catId, images: noteEditorImages, updated_at: now });
      }
    } else {
      notebook.push({ id: 'local' + Date.now() + Math.random().toString(36).slice(2), title, content, severity, test_id: testId, category_id: catId, images: noteEditorImages, created_at: now, updated_at: now });
    }
    saveNotebook();
    refreshNotebookUI();
    closeNoteEditor();
    showToast(t('noteSaved'));
  }

  function deleteNoteFromEditor(){
    const id = document.getElementById('noteEditId').value;
    if(!id) return;
    if(!confirm(t('noteDeleteConfirm'))) return;

    if(currentSession){
      apiRequest(`/sessions/${currentSession.id}/notes/${id}`, { method: 'DELETE' })
        .then(()=> loadSessionNotes())
        .then(()=>{
          refreshNotebookUI();
          closeNoteEditor();
          showToast(t('noteDeleted'));
        }).catch(err => setNoteEditorStatus(err.message || t('noteSaveError'), true));
      return;
    }

    notebook = notebook.filter(n => String(n.id) !== String(id));
    saveNotebook();
    refreshNotebookUI();
    closeNoteEditor();
    showToast(t('noteDeleted'));
  }

  function openLightbox(src){
    document.getElementById('lightboxImg').src = src;
    document.getElementById('imageLightbox').classList.add('open');
  }
  function closeLightbox(){
    document.getElementById('imageLightbox').classList.remove('open');
    document.getElementById('lightboxImg').src = '';
  }

  function bindEvents(){
    document.getElementById('closeOverlay').addEventListener('click', closeCategory);
    document.getElementById('categoryOverlay').addEventListener('click', e=>{
      if(e.target.id === 'categoryOverlay') closeCategory();
    });

    document.getElementById('dashboardNav').addEventListener('click', ()=>{
      window.scrollTo({top:0, behavior:'smooth'});
    });
    document.getElementById('top10NavBtn').addEventListener('click', ()=>{
      document.getElementById('top10Section')?.scrollIntoView({behavior:'smooth', block:'start'});
    });
    document.getElementById('closeTop10Overlay').addEventListener('click', closeTop10Detail);
    document.getElementById('top10Overlay').addEventListener('click', e=>{
      if(e.target.id === 'top10Overlay') closeTop10Detail();
    });

    document.getElementById('themeTrigger').addEventListener('click', openThemeModal);
    document.getElementById('closeThemeOverlay').addEventListener('click', closeThemeModal);
    document.getElementById('themeOverlay').addEventListener('click', e=>{
      if(e.target.id === 'themeOverlay') closeThemeModal();
    });

    document.getElementById('sessionsNavBtn').addEventListener('click', ()=> openSessionGate(true));
    document.getElementById('topbarSessionBtn').addEventListener('click', ()=> openSessionGate(true));
    document.getElementById('closeSessionGate').addEventListener('click', closeSessionGate);
    document.getElementById('sessionGateOverlay').addEventListener('click', e=>{
      if(e.target.id === 'sessionGateOverlay' && document.getElementById('closeSessionGate').style.display !== 'none') closeSessionGate();
    });
    document.getElementById('newSessionBtn').addEventListener('click', openNewSessionOverlay);
    document.getElementById('skipSessionBtn').addEventListener('click', ()=>{
      setSkipFlag(true);
      closeSessionGate();
    });
    document.getElementById('closeNewSessionOverlay').addEventListener('click', closeNewSessionOverlay);
    document.getElementById('newSessionOverlay').addEventListener('click', e=>{
      if(e.target.id === 'newSessionOverlay') closeNewSessionOverlay();
    });
    document.getElementById('createSessionBtn').addEventListener('click', createSessionSubmit);
    document.getElementById('newSessionForm').addEventListener('submit', e=> e.preventDefault());
    document.getElementById('sessionListBody').addEventListener('click', e=>{
      const btn = e.target.closest('button[data-action]');
      if(!btn) return;
      const id = btn.dataset.id;
      if(btn.dataset.action === 'open') openSessionById(id).catch(err => showToast(err.message || t('resultSaveError')));
      if(btn.dataset.action === 'delete') deleteSessionUI(id);
    });

    document.getElementById('notebookNavBtn').addEventListener('click', ()=> openNotebook());
    document.getElementById('closeNotebookOverlay').addEventListener('click', closeNotebook);
    document.getElementById('notebookOverlay').addEventListener('click', e=>{
      if(e.target.id === 'notebookOverlay') closeNotebook();
    });
    document.getElementById('newNoteBtn').addEventListener('click', ()=> openNoteEditor(null));
    document.getElementById('notebookTestFilter').addEventListener('change', e=>{
      notebookFilterTestId = e.target.value;
      renderNotebookList();
    });
    document.getElementById('notebookList').addEventListener('click', e=>{
      const img = e.target.closest('.note-card-images img');
      if(img){ e.stopPropagation(); openLightbox(img.dataset.full || img.src); return; }
      const card = e.target.closest('.note-card');
      if(!card) return;
      const note = activeNotes().find(n => String(n.id) === String(card.dataset.noteId));
      if(note) openNoteEditor(note);
    });

    document.getElementById('closeNoteEditorOverlay').addEventListener('click', closeNoteEditor);
    document.getElementById('noteEditorOverlay').addEventListener('click', e=>{
      if(e.target.id === 'noteEditorOverlay') closeNoteEditor();
    });
    document.getElementById('noteEditorForm').addEventListener('submit', e=> e.preventDefault());
    document.getElementById('saveNoteBtn').addEventListener('click', saveNoteFromEditor);
    document.getElementById('deleteNoteBtn').addEventListener('click', deleteNoteFromEditor);

    const noteImageDrop = document.getElementById('noteImageDrop');
    const noteImageInput = document.getElementById('noteImageInput');
    noteImageInput.addEventListener('change', e=>{ addImagesToEditor(e.target.files); e.target.value = ''; });
    noteImageDrop.addEventListener('dragover', e=>{ e.preventDefault(); noteImageDrop.classList.add('dragover'); });
    noteImageDrop.addEventListener('dragleave', ()=> noteImageDrop.classList.remove('dragover'));
    noteImageDrop.addEventListener('drop', e=>{
      e.preventDefault();
      noteImageDrop.classList.remove('dragover');
      if(e.dataTransfer && e.dataTransfer.files) addImagesToEditor(e.dataTransfer.files);
    });
    document.getElementById('noteEditorForm').addEventListener('paste', e=>{
      const items = (e.clipboardData && e.clipboardData.items) || [];
      const files = [];
      for(const item of items){ if(item.kind === 'file'){ const f = item.getAsFile(); if(f) files.push(f); } }
      if(files.length) addImagesToEditor(files);
    });
    document.getElementById('noteImageThumbs').addEventListener('click', e=>{
      const btn = e.target.closest('.remove-img');
      if(!btn) return;
      noteEditorImages.splice(parseInt(btn.dataset.idx, 10), 1);
      renderNoteImageThumbs();
    });

    document.getElementById('closeLightbox').addEventListener('click', closeLightbox);
    document.getElementById('imageLightbox').addEventListener('click', e=>{
      if(e.target.id === 'imageLightbox') closeLightbox();
    });

    document.getElementById('importNavBtn').addEventListener('click', openImportModal);
    document.getElementById('closeImportOverlay').addEventListener('click', closeImportModal);
    document.getElementById('importOverlay').addEventListener('click', e=>{
      if(e.target.id === 'importOverlay') closeImportModal();
    });
    document.getElementById('importAnalyzeBtn').addEventListener('click', analyzeImportFile);
    document.getElementById('importApplyBtn').addEventListener('click', applyImportSelected);
    document.getElementById('importPreviewList').addEventListener('change', e=>{
      const cb = e.target.closest('.import-check');
      if(!cb) return;
      const row = lastImportFindings.find(f => f._rowId === cb.dataset.row);
      if(row) row._checked = cb.checked;
    });

    document.addEventListener('keydown', e=>{
      if(e.key === 'Escape'){
        closeCategory(); closeThemeModal(); closeNewSessionOverlay(); closeTop10Detail(); closeImportModal();
        closeLightbox(); closeNoteEditor(); closeNotebook();
        if(document.getElementById('closeSessionGate').style.display !== 'none') closeSessionGate();
      }
    });

    document.getElementById('itemSearch').addEventListener('input', renderTestList);
    document.querySelectorAll('.filter-toggle button').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        document.querySelectorAll('.filter-toggle button').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        renderTestList();
      });
    });

    document.getElementById('testList').addEventListener('click', e=>{
      const checkBtn = e.target.closest('.test-check');
      if(checkBtn){ e.stopPropagation(); toggleDone(checkBtn.dataset.id); return; }
      const addNoteBtn = e.target.closest('.add-note-btn');
      if(addNoteBtn){
        e.stopPropagation();
        closeCategory();
        openNoteEditor(null, addNoteBtn.dataset.testId);
        return;
      }
      const copyBtn = e.target.closest('.copy-btn');
      if(copyBtn){ e.stopPropagation(); copyToClipboard(decodeURIComponent(copyBtn.dataset.copy)); return; }
      if(e.target.closest('.finding-block')){ e.stopPropagation(); return; }
      const head = e.target.closest('.test-item-head');
      if(head){
        head.closest('.test-item').classList.toggle('open');
      }
    });
    document.getElementById('testList').addEventListener('input', e=>{
      const ta = e.target.closest('.finding-textarea');
      if(ta){ scheduleFindingSave(ta.dataset.id); }
    });
    document.getElementById('testList').addEventListener('change', e=>{
      const sel = e.target.closest('.severity-select');
      if(sel){ saveFinding(sel.dataset.id); }
    });

    const searchInput = document.getElementById('globalSearch');
    searchInput.addEventListener('input', ()=> doSearch(searchInput.value));
    searchInput.addEventListener('focus', ()=> { if(searchInput.value.trim()) doSearch(searchInput.value); });
    document.addEventListener('click', e=>{
      if(!e.target.closest('.search')) document.getElementById('searchResults').classList.remove('open');
    });
    document.getElementById('searchResults').addEventListener('click', e=>{
      const item = e.target.closest('.search-result-item');
      if(!item) return;
      document.getElementById('searchResults').classList.remove('open');
      searchInput.value = '';
      openCategory(item.dataset.cat, item.dataset.test);
    });

    document.getElementById('exportBtn').addEventListener('click', exportReport);
    document.getElementById('resetBtn').addEventListener('click', resetProgress);
    document.getElementById('startBtn').addEventListener('click', ()=>{
      if(dbOnline && !currentSession){ openSessionGate(true); return; }
      const first = DATA.categories[0];
      if(first) openCategory(first.id);
    });

    document.getElementById('langSelect').addEventListener('change', e=>{
      switchLanguage(e.target.value);
    });
  }

  function switchLanguage(lang){
    if(!DATA_FILES[lang] || lang === currentLang){
      currentLang = lang in DATA_FILES ? lang : currentLang;
      applyI18n();
      return;
    }
    const wasOpen = document.getElementById('categoryOverlay').classList.contains('open');
    const openCatId = currentCategoryId;
    const top10WasOpen = document.getElementById('top10Overlay').classList.contains('open');
    currentLang = lang;
    saveLang(currentLang);
    Promise.all([loadData(), loadTop10Data()]).then(()=>{
      applyI18n();
      renderSidebar();
      renderDashboard();
      renderTop10Grid();
      updateSessionUI();
      if(wasOpen && openCatId){
        openCategory(openCatId);
      }
      if(top10WasOpen){
        renderTop10Detail();
      }
    });
  }

  function loadData(){
    return fetch(DATA_FILES[currentLang] || DATA_FILES.tr)
      .then(r => r.json())
      .then(data => { DATA = data; })
      .catch(err => {
        document.getElementById('categoriesGrid').innerHTML =
          `<div class="search-empty">${t('dataLoadError')}<br><small>${err}</small></div>`;
        console.error(err);
      });
  }

  applyTheme();
  applyI18n();

  Promise.all([loadData(), loadTop10Data()]).then(()=>{
    if(!DATA) return;
    renderSidebar();
    renderDashboard();
    renderTop10Grid();
    bindEvents();
    updateSessionUI();

    checkDb().then(online => {
      dbOnline = online;
      updateSessionUI();
      if(!online) return; // no backend -> behave exactly like the original local-only app

      const savedId = loadSavedSessionId();
      if(savedId){
        openSessionById(savedId).then(()=>{
          showToast(`${currentSession.name} ${t('sessionResumed')}`);
        }).catch(()=>{
          saveSessionId(null);
          if(!getSkipFlag()) openSessionGate(false);
        });
      } else if(!getSkipFlag()){
        openSessionGate(false);
      }
    });
  });
})();
