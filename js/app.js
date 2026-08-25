(function(){
  "use strict";

  const STORAGE_KEY = "wstg_progress_v1";
  const FINDINGS_KEY = "wstg_findings_v1";
  const LANG_KEY = "wstg_lang_v1";
  const THEME_KEY = "wstg_theme_v1";
  const SESSION_ID_KEY = "wstg_session_id_v1";
  const SKIP_SESSION_KEY = "wstg_skip_session_v1";
  const RECON_PRIORITY_KEY = "wstg_recon_priority_v1";
  const API_BASE = "http://localhost:5000/api";

  const DATA_FILES = {
    tr: "data/wstg-checklist.tr.json",
    en: "data/wstg-checklist.en.json"
  };

  const FRAMEWORK_DATA_FILES = {
    wstg: { tr: "data/wstg-checklist.tr.json", en: "data/wstg-checklist.en.json" },
    "llm-security": { tr: "data/llm-security-checklist.tr.json", en: "data/llm-security-checklist.en.json" }
  };
  const FRAMEWORK_KEY = "wstg_framework_v1";

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
      frameworkLabel: "Checklist",
      frameworkWstg: "OWASP WSTG (Web)",
      frameworkLlm: "OWASP LLM Top 10 (AI Security)",
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

      navRecon: "Attack Surface Discovery",
      reconModalTitle: "Attack Surface Discovery",
      reconModalDesc: "Bir hedef domain girin: subdomain, endpoint, teknoloji ve API yüzeyi pasif/hafif yöntemlerle çıkarılır ve otomatik olarak ilgili WSTG testleriyle ilişkilendirilir.",
      reconTargetLabel: "Hedef Domain",
      reconAuthLabel: "Bu hedefi test etmeye yetkili olduğumu onaylıyorum.",
      reconRunBtn: "Keşfet",
      reconRunning: "Keşif çalışıyor (crt.sh + hedefe tek istek + bilinen yol kontrolü)...",
      reconAuthRequired: "Devam etmek için yetkilendirme onay kutusunu işaretlemelisiniz.",
      reconTargetRequired: "Lütfen bir hedef domain girin.",
      reconError: "Keşif başarısız oldu",
      reconSubdomainsLabel: "Subdomains",
      reconTechLabel: "Technologies",
      reconEndpointsLabel: "Endpoints & Interesting Paths",
      reconSuggestionsLabel: "Önerilen Test Önceliği",
      reconApplyBtn: "Checklist'i Önceliklendir",
      reconNoSuggestions: "Önerilecek bir test önceliği bulunamadı.",
      reconAppliedToast: n => `${n} test maddesi önceliklendirildi`,
      reconBackendOffline: "Bu özellik backend gerektirir — lütfen backend/app.py'yi çalıştırın.",
      reconPriorityBadge_high: "🎯 Yüksek Öncelik",
      reconPriorityBadge_medium: "🎯 Orta Öncelik",
      reconPriorityBadge_low: "🎯 Düşük Öncelik",
      reconPriorityBadge_info: "🎯 Önerilen",

      navPlanner: "Test Planı",
      plannerModalTitle: "Test Planı",
      plannerModalDesc: "Attack Surface Discovery'den gelen önceliklendirilmiş maddeler; kanıt sayısı ve WSTG metodoloji sırasına göre şeffaf bir skorla sıralanır. Her önerinin yanında nedeni gösterilir.",
      plannerEmpty: "Henüz bir test planı yok. Önce Attack Surface Discovery ile bir hedef tarayıp bulguları önceliklendirin.",
      plannerReasonLabel: "Neden",
      plannerGotoBtn: "Bu maddeye git",
      plannerScoreNote: "Skor: kanıt sayısı + öncelik seviyesi + WSTG metodoloji sırasına göre hesaplanır (sabit kurallar, model çağrısı yapılmaz).",

      navProjects: "Projeler",
      projectsModalTitle: "Projeler",
      projectsModalDesc: "Her pentest çalışmasını bir Project/Engagement altında yönetin: kapsam, recon, test planı, WSTG testleri, bulgular ve timeline tek yerde.",
      newProjectBtn: "+ Yeni Proje",
      projectsCountLabel: n => `${n} proje`,
      noProjectsYet: "Henüz proje yok. Başlamak için 'Yeni Proje' butonuna tıklayın.",
      projectsLoadError: "Projeler yüklenemedi",
      projectsBackendOffline: "Bu özellik backend gerektirir — lütfen backend/app.py'yi çalıştırın.",
      newProjectModalTitle: "Yeni Proje",
      editProjectModalTitle: "Projeyi Düzenle",
      projectNameLabel: "Proje Adı *",
      projectClientLabel: "Müşteri / Kurum",
      projectDescLabel: "Açıklama",
      projectStatusLabel: "Durum",
      projectStatus_planning: "Planlama",
      projectStatus_active: "Aktif",
      projectStatus_paused: "Duraklatıldı",
      projectStatus_completed: "Tamamlandı",
      projectStatus_archived: "Arşivlendi",
      projectStartLabel: "Başlangıç Tarihi",
      projectEndLabel: "Bitiş Tarihi",
      saveBtn: "Kaydet",
      editBtn: "Düzenle",
      projectNameRequired: "Proje adı zorunludur.",
      projectSaved: "Proje kaydedildi",
      projectDeleteConfirm: "Bu projeyi silmek istediğinize emin misiniz? (Test oturumları silinmez, sadece projeyle bağlantısı kalkar.)",
      projectDeleted: "Proje silindi",
      openProjectBtn: "Aç",
      projectSessionsLabel: n => `${n} oturum`,

      pwTabOverview: "Overview", pwTabScope: "Scope", pwTabAssets: "Assets", pwTabRecon: "Recon",
      pwTabTestPlan: "Test Plan", pwTabWstg: "WSTG Tests", pwTabFindings: "Findings",
      pwTabTimeline: "Timeline", pwTabReports: "Reports",

      pwStatAssets: "Assets", pwStatTests: "Tests", pwStatCompleted: "Completed", pwStatFindings: "Findings",
      pwSeverityDistLabel: "Severity Dağılımı",
      pwOverviewLoadError: "Dashboard yüklenemedi",
      pwCoverageLabel: "Framework Coverage",
      pwCoverage_wstg: "OWASP WSTG",
      pwCoverage_llm: "OWASP LLM Top 10",
      pwCoverage_custom: "Custom Tests",
      pwFindingsByCategoryLabel: "Kategoriye Göre Bulgular",
      pwTopEndpointsLabel: "En Çok Bulgu İçeren Endpoint'ler",
      pwEndpointFindingsSuffix: "bulgu",

      pwScopeInScope: "In Scope", pwScopeOutOfScope: "Out of Scope",
      pwScopeValuePlaceholder: "*.example.com, api.example.com, 192.168.1.10 ...",
      pwScopeAddBtn: "Ekle", pwScopeEmpty: "Henüz kapsam kaydı yok.",
      pwScopeType_domain: "Domain", pwScopeType_subdomain: "Subdomain", pwScopeType_ip: "IP", pwScopeType_cidr: "CIDR",
      pwScopeValueRequired: "Değer zorunludur.",

      pwAssetsEmpty: "Henüz asset yok — Recon sekmesinden Attack Surface Discovery çalıştırın.",
      pwAssetsSubdomains: "Subdomains", pwAssetsTechnologies: "Technologies", pwAssetsEndpoints: "Endpoints",
      pwAssetsViewList: "📋 Liste",
      pwAssetsViewMap: "🗺️ Harita",
      pwAssetsMapFindingsLabel: "İlişkili Findings",
      pwAssetsMapNoFindings: "Bu endpoint'e bağlı bir finding yok.",

      pwReconDesc: "Bu proje için Attack Surface Discovery çalıştırın; sonuçlar otomatik olarak Assets sekmesine ve Timeline'a işlenir.",
      pwReconOpenBtn: "Attack Surface Discovery'yi Aç",

      pwTabTools: "Tools",
      pwToolsDesc: "Gerçek keşif araçlarını (nmap, httpx, whatweb, subfinder, dnsx) kendi makinenizde çalıştırın. Her çalıştırmadan önce tam komutu görür ve onaylarsınız.",
      pwToolsExcludedNote: "Not: nuclei ve ffuf bilerek dahil edilmedi — nuclei aktif zafiyet doğrulama şablonları içeriyor, ffuf agresif dizin fuzzing yapıyor. İkisi de ayrı, daha sıkı kapsamlı bir iterasyon gerektirir.",
      toolSelectLabel: "Araç",
      toolTargetLabel: "Hedef",
      toolNotInstalled: "⚠️ Sisteminizde kurulu değil",
      toolPreviewLabel: "Çalıştırılacak komut:",
      toolAuthLabel: "Bu hedefi test etmeye yetkili olduğumu onaylıyorum.",
      toolPreviewBtn: "Komutu Önizle",
      toolRunBtn: "Onayla ve Çalıştır",
      toolRunning: "Çalışıyor... (bu birkaç dakika sürebilir)",
      toolRunError: "Araç çalıştırılamadı",
      toolTargetRequired: "Lütfen bir hedef girin.",
      toolAuthRequired: "Devam etmek için yetkilendirme onay kutusunu işaretlemelisiniz.",
      toolStatus_completed: "✅ Tamamlandı",
      toolStatus_failed: "❌ Başarısız",
      toolStatus_timeout: "⏱️ Zaman Aşımı",
      toolHistoryLabel: "Geçmiş Çalıştırmalar",
      toolHistoryEmpty: "Henüz bir araç çalıştırılmadı.",
      toolExitCodeLabel: "Çıkış kodu",

      findingModalTitleNew: "Yeni Finding",
      findingModalTitleEdit: "Finding Düzenle",
      findingModalDesc: "Profesyonel bulgu kaydı: CVSS v3.1, CWE, endpoint/parametre, remediation ve retest takibi.",
      findingTitleLabel: "Başlık *",
      findingTestIdLabel: "İlişkili WSTG/LLM Test ID (opsiyonel)",
      findingEndpointLabel: "Endpoint",
      findingParameterLabel: "Parametre",
      findingCweLabel: "CWE",
      findingOwaspCatLabel: "OWASP Kategorisi",
      findingDescLabel: "Açıklama",
      findingImpactLabel: "Etki",
      findingRemediationLabel: "Remediation",
      findingReferencesLabel: "Referanslar (her satıra bir URL)",
      findingStatusLabel: "Durum",
      findingAssignedLabel: "Atanan Kişi",
      findingRetestResultLabel: "Retest Sonucu",
      findingRetest_not_tested: "Henüz test edilmedi",
      findingRetest_fixed: "Düzeltildi ✓",
      findingRetest_not_fixed: "Düzeltilmedi ✗",
      findingRetestNotesLabel: "Retest Notları",
      findingCvssTitle: "CVSS v3.1 Hesaplayıcı",
      findingStatus_open: "Open", findingStatus_confirmed: "Confirmed", findingStatus_fixed: "Fixed",
      findingStatus_retest_pending: "Retest Pending", findingStatus_resolved: "Resolved",
      findingStatus_wont_fix: "Won't Fix", findingStatus_accepted_risk: "Accepted Risk",
      findingTitleRequired: "Başlık zorunludur.",
      findingSaved: "Finding kaydedildi",
      findingDeleteConfirm: "Bu finding'i silmek istediğinize emin misiniz?",
      findingDeleted: "Finding silindi",
      newFindingBtn: "+ Yeni Finding",
      promoteFindingBtn: "Professional Finding'e Yükselt",
      pwFindingsProLabel: "Professional Findings",
      pwFindingsProEmpty: "Henüz professional finding yok.",
      pwFindingsQuickLabel: "Hızlı Bulgular (Checklist Notları)",
      cvssAV: "Attack Vector", cvssAC: "Attack Complexity", cvssPR: "Privileges Required",
      cvssUI: "User Interaction", cvssS: "Scope", cvssC: "Confidentiality", cvssI: "Integrity", cvssA: "Availability",
      cvssAV_N: "Network", cvssAV_A: "Adjacent", cvssAV_L: "Local", cvssAV_P: "Physical",
      cvssAC_L: "Low", cvssAC_H: "High",
      cvssPR_N: "None", cvssPR_L: "Low", cvssPR_H: "High",
      cvssUI_N: "None", cvssUI_R: "Required",
      cvssS_U: "Unchanged", cvssS_C: "Changed",
      cvssCIA_N: "None", cvssCIA_L: "Low", cvssCIA_H: "High",

      pwTestPlanDesc: "Recon önceliklendirmelerinden oluşan, şeffaf skorlamalı test planını görüntüleyin.",
      pwTestPlanOpenBtn: "Test Planını Aç",
      pwWstgDesc: "Bu proje için bir test oturumu başlatın veya kaldığınız yerden devam edin; WSTG checklist'i buradan yönetilir.",
      pwWstgOpenBtn: "Checklist'i Aç",

      pwFindingsEmpty: "Henüz bulgu yok.",
      pwFindingsNoSession: "Bu projede henüz bir test oturumu yok. Önce WSTG Tests sekmesinden bir oturum başlatın.",

      pwTabChains: "Attack Chains",
      pwChainsDesc: "Projedeki bulgular, bilinen saldırı zinciri kalıplarıyla eşleştirilir (sabit kurallar, model çağrısı yapılmaz).",
      pwChainsEmpty: "Şu an eşleşen bir saldırı zinciri yok. En az 2 adımı eşleşen bulgu gerekir.",
      pwChainsCompleteness: n => `${n}% tamamlanmış`,
      pwChainsRiskScore: "Risk Skoru",
      pwChainsStepMatched: "Eşleşen bulgu",
      pwChainsStepMissing: "Bu adımda henüz bulgu yok",

      lifecycleRemediationRate: "Remediation Oranı",
      lifecycleStatusUpdated: "Bulgu durumu güncellendi",
      lifecycleStatus_open: "🔴 Open",
      lifecycleStatus_retesting: "🔵 Retesting",
      lifecycleStatus_fixed: "🟡 Fixed",
      lifecycleStatus_resolved: "🟢 Resolved",
      lifecycleStatus_wont_fix: "⚪ Won't Fix",
      lifecycleStatus_accepted_risk: "⚪ Accepted Risk",

      customTestsCategoryName: "Custom Tests",
      customTestsCategoryDesc: "Bu projeye özel, kuruluşunuza ait ek test maddeleri (resmi WSTG veri setinden gelmez).",
      customTestsLabel: "Özel Testler (Custom Tests)",
      customTestsDesc: "WSTG 5.0 henüz yayınlanmadığı için resmi içerik eklenemiyor — ama kuruluşunuza özel test maddeleri ekleyebilirsiniz. Bunlar checklist'te ayrı bir 'Custom Tests' kategorisi altında normal bir WSTG testi gibi görünür.",
      customTestTitlePlaceholder: "Test başlığı (ör. İç ağ admin paneli erişimi)",
      customTestDescPlaceholder: "Açıklama (opsiyonel)",
      customTestAddBtn: "Ekle",
      customTestTitleRequired: "Başlık zorunludur.",
      customTestsEmpty: "Henüz özel test eklenmedi.",

      pwTabEvidence: "Evidence",
      pwEvidenceUploadLabel: "Ekran Görüntüsü Yükle",
      pwEvidenceUploadBtn: "Yükle",
      pwEvidenceUploading: "Yükleniyor...",
      pwEvidenceEmpty: "Henüz kanıt yüklenmedi.",
      pwEvidenceUploadError: "Yükleme başarısız",
      pwEvidenceAiOff: "🔌 AI analizi devre dışı — etkinleştirmek için backend/.env dosyasına ANTHROPIC_API_KEY ekleyin.",
      pwEvidenceAiError: "AI analizi başarısız",
      pwEvidenceAiConfidence: "Güven",
      pwEvidenceSuggested: "Önerilen WSTG testleri",
      pwEvidenceAccept: "Kabul Et",
      pwEvidenceReject: "Reddet",
      pwEvidenceLinkedTo: "Bağlı",
      pwEvidenceLinkFindingLabel: "Bir Finding'e bağla:",
      pwEvidenceLinkFindingNone: "— Bağlı değil —",
      pwEvidenceLinkedToFinding: "Kanıt finding'e bağlandı",
      pwEvidenceDelete: "Sil",
      pwEvidenceAddHttpLabel: "HTTP Request/Response Ekle",
      pwEvidenceHttpLabelField: "Etiket (opsiyonel)",
      pwEvidenceHttpRequestLabel: "HTTP Request",
      pwEvidenceHttpResponseLabel: "HTTP Response",
      pwEvidenceRedactionNote: "Authorization/Cookie/JWT/API key/parola/e-posta/kredi kartı gibi hassas veriler kaydedilirken otomatik olarak maskelenir (redaction). Ham metin sadece 'Ham Metni Göster' ile açıkça görüntülenir.",
      pwEvidenceHttpRequired: "En az bir request veya response girilmelidir.",
      pwEvidenceShowRaw: "🔓 Ham Metni Göster/Gizle",
      pwEvidenceRawWarning: "⚠️ Ham (redakte edilmemiş) metin — hassas veri içerebilir, dikkatli paylaşın.",
      pwEvidenceReviewPending: "İnceleme bekliyor",
      pwEvidenceReviewAccepted: "Kabul edildi",
      pwEvidenceReviewRejected: "Reddedildi",
      pwEvidenceDeleteConfirm: "Bu kanıtı silmek istediğinize emin misiniz?",

      pwTimelineEmpty: "Henüz bir aktivite kaydı yok.",

      pwReportsNoSession: "Bu projede henüz bir test oturumu yok.",
      pwReportsOpenBtn: "Raporu Aç ve İndir",
      pwProReportsLabel: "Profesyonel Raporlar",
      pwProReportsDesc: "Projedeki tüm oturumların bulgularını birleştiren, indirilebilir Word (.docx) raporları.",
      pwReportTypeTechnical: "Technical Report",
      pwReportTypeTechnicalDesc: "Tüm test sonuçları ve bulguların tam detaylı dökümü — pentester/QA için.",
      pwReportTypeExecutive: "Executive Summary",
      pwReportTypeExecutiveDesc: "Genel risk postürü, sayılar ve öne çıkan bulgular — yönetim için.",
      pwReportTypeDeveloper: "Developer Remediation",
      pwReportTypeDeveloperDesc: "Problem / Neden Önemli / Nasıl Düzeltilir formatında somut aksiyon rehberi.",
      pwReportsSessionExportLabel: "Basit JSON Dışa Aktarım (oturum bazlı)",

      pwEventType_project_created: "🆕 Proje oluşturuldu",
      pwEventType_session_created: "📋 Oturum oluşturuldu",
      pwEventType_session_completed: "✅ Oturum tamamlandı",
      pwEventType_test_completed: "☑️ Test tamamlandı",
      pwEventType_finding_created: "🚩 Yeni bulgu",
      pwEventType_scope_updated: "🎯 Kapsam güncellendi",
      pwEventType_recon_run: "🌐 Recon çalıştırıldı"
    },
    en: {
      navWorkspace: "Workspace",
      navDashboard: "Dashboard",
      navCategories: "WSTG Categories",
      exportReport: "Export Report",
      resetProgress: "Reset Progress",
      langLabel: "Language",
      frameworkLabel: "Checklist",
      frameworkWstg: "OWASP WSTG (Web)",
      frameworkLlm: "OWASP LLM Top 10 (AI Security)",
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

      navRecon: "Attack Surface Discovery",
      reconModalTitle: "Attack Surface Discovery",
      reconModalDesc: "Enter a target domain: subdomains, endpoints, technologies, and API surface are extracted with passive/light methods and automatically linked to the relevant WSTG tests.",
      reconTargetLabel: "Target Domain",
      reconAuthLabel: "I confirm that I am authorized to test this target.",
      reconRunBtn: "Discover",
      reconRunning: "Running discovery (crt.sh + one request to the target + known-path check)...",
      reconAuthRequired: "You must check the authorization box to continue.",
      reconTargetRequired: "Please enter a target domain.",
      reconError: "Discovery failed",
      reconSubdomainsLabel: "Subdomains",
      reconTechLabel: "Technologies",
      reconEndpointsLabel: "Endpoints & Interesting Paths",
      reconSuggestionsLabel: "Suggested Test Priority",
      reconApplyBtn: "Prioritize Checklist",
      reconNoSuggestions: "No test priority suggestions found.",
      reconAppliedToast: n => `${n} test items prioritized`,
      reconBackendOffline: "This feature requires the backend — please run backend/app.py.",
      reconPriorityBadge_high: "🎯 High Priority",
      reconPriorityBadge_medium: "🎯 Medium Priority",
      reconPriorityBadge_low: "🎯 Low Priority",
      reconPriorityBadge_info: "🎯 Suggested",

      navPlanner: "Test Plan",
      plannerModalTitle: "Test Plan",
      plannerModalDesc: "Prioritized items from Attack Surface Discovery, ranked by a transparent score based on evidence count and WSTG methodology order. The reason is shown next to each suggestion.",
      plannerEmpty: "No test plan yet. Run Attack Surface Discovery against a target first and prioritize the findings.",
      plannerReasonLabel: "Reason",
      plannerGotoBtn: "Go to this item",
      plannerScoreNote: "Score is computed from evidence count + priority level + WSTG methodology order (fixed rules, no model call involved).",

      navProjects: "Projects",
      projectsModalTitle: "Projects",
      projectsModalDesc: "Manage each pentest engagement under a Project: scope, recon, test plan, WSTG tests, findings, and timeline in one place.",
      newProjectBtn: "+ New Project",
      projectsCountLabel: n => `${n} projects`,
      noProjectsYet: "No projects yet. Click 'New Project' to get started.",
      projectsLoadError: "Could not load projects",
      projectsBackendOffline: "This feature requires the backend — please run backend/app.py.",
      newProjectModalTitle: "New Project",
      editProjectModalTitle: "Edit Project",
      projectNameLabel: "Project Name *",
      projectClientLabel: "Client / Organization",
      projectDescLabel: "Description",
      projectStatusLabel: "Status",
      projectStatus_planning: "Planning",
      projectStatus_active: "Active",
      projectStatus_paused: "Paused",
      projectStatus_completed: "Completed",
      projectStatus_archived: "Archived",
      projectStartLabel: "Start Date",
      projectEndLabel: "End Date",
      saveBtn: "Save",
      editBtn: "Edit",
      projectNameRequired: "Project name is required.",
      projectSaved: "Project saved",
      projectDeleteConfirm: "Are you sure you want to delete this project? (Test sessions are not deleted, only unlinked from the project.)",
      projectDeleted: "Project deleted",
      openProjectBtn: "Open",
      projectSessionsLabel: n => `${n} sessions`,

      pwTabOverview: "Overview", pwTabScope: "Scope", pwTabAssets: "Assets", pwTabRecon: "Recon",
      pwTabTestPlan: "Test Plan", pwTabWstg: "WSTG Tests", pwTabFindings: "Findings",
      pwTabTimeline: "Timeline", pwTabReports: "Reports",

      pwStatAssets: "Assets", pwStatTests: "Tests", pwStatCompleted: "Completed", pwStatFindings: "Findings",
      pwSeverityDistLabel: "Severity Distribution",
      pwOverviewLoadError: "Could not load dashboard",
      pwCoverageLabel: "Framework Coverage",
      pwCoverage_wstg: "OWASP WSTG",
      pwCoverage_llm: "OWASP LLM Top 10",
      pwCoverage_custom: "Custom Tests",
      pwFindingsByCategoryLabel: "Findings by Category",
      pwTopEndpointsLabel: "Most Tested Endpoints",
      pwEndpointFindingsSuffix: "findings",

      pwScopeInScope: "In Scope", pwScopeOutOfScope: "Out of Scope",
      pwScopeValuePlaceholder: "*.example.com, api.example.com, 192.168.1.10 ...",
      pwScopeAddBtn: "Add", pwScopeEmpty: "No scope entries yet.",
      pwScopeType_domain: "Domain", pwScopeType_subdomain: "Subdomain", pwScopeType_ip: "IP", pwScopeType_cidr: "CIDR",
      pwScopeValueRequired: "A value is required.",

      pwAssetsEmpty: "No assets yet — run Attack Surface Discovery from the Recon tab.",
      pwAssetsSubdomains: "Subdomains", pwAssetsTechnologies: "Technologies", pwAssetsEndpoints: "Endpoints",
      pwAssetsViewList: "📋 List",
      pwAssetsViewMap: "🗺️ Map",
      pwAssetsMapFindingsLabel: "Associated Findings",
      pwAssetsMapNoFindings: "No findings linked to this endpoint.",

      pwReconDesc: "Run Attack Surface Discovery for this project; results are automatically fed into Assets and the Timeline.",
      pwReconOpenBtn: "Open Attack Surface Discovery",

      pwTabTools: "Tools",
      pwToolsDesc: "Run real discovery tools (nmap, httpx, whatweb, subfinder, dnsx) on your own machine. You see and approve the exact command before it runs.",
      pwToolsExcludedNote: "Note: nuclei and ffuf are deliberately not included — nuclei's templates include active exploit-verification checks, and ffuf performs aggressive directory fuzzing. Both would need a separate, more tightly-scoped iteration.",
      toolSelectLabel: "Tool",
      toolTargetLabel: "Target",
      toolNotInstalled: "⚠️ Not installed on your system",
      toolPreviewLabel: "Command that will run:",
      toolAuthLabel: "I confirm that I am authorized to test this target.",
      toolPreviewBtn: "Preview Command",
      toolRunBtn: "Approve & Run",
      toolRunning: "Running... (this can take a few minutes)",
      toolRunError: "Tool execution failed",
      toolTargetRequired: "Please enter a target.",
      toolAuthRequired: "You must check the authorization box to continue.",
      toolStatus_completed: "✅ Completed",
      toolStatus_failed: "❌ Failed",
      toolStatus_timeout: "⏱️ Timed Out",
      toolHistoryLabel: "Run History",
      toolHistoryEmpty: "No tool has been run yet.",
      toolExitCodeLabel: "Exit code",

      findingModalTitleNew: "New Finding",
      findingModalTitleEdit: "Edit Finding",
      findingModalDesc: "Professional finding record: CVSS v3.1, CWE, endpoint/parameter, remediation, and retest tracking.",
      findingTitleLabel: "Title *",
      findingTestIdLabel: "Linked WSTG/LLM Test ID (optional)",
      findingEndpointLabel: "Endpoint",
      findingParameterLabel: "Parameter",
      findingCweLabel: "CWE",
      findingOwaspCatLabel: "OWASP Category",
      findingDescLabel: "Description",
      findingImpactLabel: "Impact",
      findingRemediationLabel: "Remediation",
      findingReferencesLabel: "References (one URL per line)",
      findingStatusLabel: "Status",
      findingAssignedLabel: "Assigned To",
      findingRetestResultLabel: "Retest Result",
      findingRetest_not_tested: "Not yet tested",
      findingRetest_fixed: "Fixed ✓",
      findingRetest_not_fixed: "Not Fixed ✗",
      findingRetestNotesLabel: "Retest Notes",
      findingCvssTitle: "CVSS v3.1 Calculator",
      findingStatus_open: "Open", findingStatus_confirmed: "Confirmed", findingStatus_fixed: "Fixed",
      findingStatus_retest_pending: "Retest Pending", findingStatus_resolved: "Resolved",
      findingStatus_wont_fix: "Won't Fix", findingStatus_accepted_risk: "Accepted Risk",
      findingTitleRequired: "Title is required.",
      findingSaved: "Finding saved",
      findingDeleteConfirm: "Are you sure you want to delete this finding?",
      findingDeleted: "Finding deleted",
      newFindingBtn: "+ New Finding",
      promoteFindingBtn: "Promote to Professional Finding",
      pwFindingsProLabel: "Professional Findings",
      pwFindingsProEmpty: "No professional findings yet.",
      pwFindingsQuickLabel: "Quick Findings (Checklist Notes)",
      cvssAV: "Attack Vector", cvssAC: "Attack Complexity", cvssPR: "Privileges Required",
      cvssUI: "User Interaction", cvssS: "Scope", cvssC: "Confidentiality", cvssI: "Integrity", cvssA: "Availability",
      cvssAV_N: "Network", cvssAV_A: "Adjacent", cvssAV_L: "Local", cvssAV_P: "Physical",
      cvssAC_L: "Low", cvssAC_H: "High",
      cvssPR_N: "None", cvssPR_L: "Low", cvssPR_H: "High",
      cvssUI_N: "None", cvssUI_R: "Required",
      cvssS_U: "Unchanged", cvssS_C: "Changed",
      cvssCIA_N: "None", cvssCIA_L: "Low", cvssCIA_H: "High",

      pwTestPlanDesc: "View the transparently-scored test plan built from recon prioritizations.",
      pwTestPlanOpenBtn: "Open Test Plan",
      pwWstgDesc: "Start or resume a test session for this project; the WSTG checklist is managed from here.",
      pwWstgOpenBtn: "Open Checklist",

      pwFindingsEmpty: "No findings yet.",
      pwFindingsNoSession: "This project has no test session yet. Start one from the WSTG Tests tab first.",

      pwTabChains: "Attack Chains",
      pwChainsDesc: "Findings in the project are matched against known attack-chain patterns (fixed rules, no model call involved).",
      pwChainsEmpty: "No matching attack chains right now. At least 2 matching steps are required.",
      pwChainsCompleteness: n => `${n}% complete`,
      pwChainsRiskScore: "Risk Score",
      pwChainsStepMatched: "Matched finding",
      pwChainsStepMissing: "No finding for this step yet",

      lifecycleRemediationRate: "Remediation Rate",
      lifecycleStatusUpdated: "Finding status updated",
      lifecycleStatus_open: "🔴 Open",
      lifecycleStatus_retesting: "🔵 Retesting",
      lifecycleStatus_fixed: "🟡 Fixed",
      lifecycleStatus_resolved: "🟢 Resolved",
      lifecycleStatus_wont_fix: "⚪ Won't Fix",
      lifecycleStatus_accepted_risk: "⚪ Accepted Risk",

      customTestsCategoryName: "Custom Tests",
      customTestsCategoryDesc: "Additional test items specific to this project/organization (not from the official WSTG dataset).",
      customTestsLabel: "Custom Tests",
      customTestsDesc: "WSTG 5.0 has not been released yet, so official content can't be added — but you can add your own organization-specific test items. They appear in the checklist under a separate 'Custom Tests' category, behaving like any other WSTG test.",
      customTestTitlePlaceholder: "Test title (e.g. Internal admin panel access)",
      customTestDescPlaceholder: "Description (optional)",
      customTestAddBtn: "Add",
      customTestTitleRequired: "Title is required.",
      customTestsEmpty: "No custom tests added yet.",

      pwTabEvidence: "Evidence",
      pwEvidenceUploadLabel: "Upload Screenshot",
      pwEvidenceUploadBtn: "Upload",
      pwEvidenceUploading: "Uploading...",
      pwEvidenceEmpty: "No evidence uploaded yet.",
      pwEvidenceUploadError: "Upload failed",
      pwEvidenceAiOff: "🔌 AI analysis disabled — add ANTHROPIC_API_KEY to backend/.env to enable it.",
      pwEvidenceAiError: "AI analysis failed",
      pwEvidenceAiConfidence: "Confidence",
      pwEvidenceSuggested: "Suggested WSTG tests",
      pwEvidenceAccept: "Accept",
      pwEvidenceReject: "Reject",
      pwEvidenceLinkedTo: "Linked",
      pwEvidenceLinkFindingLabel: "Link to a Finding:",
      pwEvidenceLinkFindingNone: "— Not linked —",
      pwEvidenceLinkedToFinding: "Evidence linked to finding",
      pwEvidenceDelete: "Delete",
      pwEvidenceAddHttpLabel: "Add HTTP Request/Response",
      pwEvidenceHttpLabelField: "Label (optional)",
      pwEvidenceHttpRequestLabel: "HTTP Request",
      pwEvidenceHttpResponseLabel: "HTTP Response",
      pwEvidenceRedactionNote: "Sensitive data (Authorization/Cookie/JWT/API keys/passwords/emails/credit cards) is automatically masked (redacted) on save. Raw text is only shown when you explicitly click 'Show Raw Text'.",
      pwEvidenceHttpRequired: "At least a request or a response must be entered.",
      pwEvidenceShowRaw: "🔓 Show/Hide Raw Text",
      pwEvidenceRawWarning: "⚠️ Raw (unredacted) text — may contain sensitive data, share carefully.",
      pwEvidenceReviewPending: "Pending review",
      pwEvidenceReviewAccepted: "Accepted",
      pwEvidenceReviewRejected: "Rejected",
      pwEvidenceDeleteConfirm: "Are you sure you want to delete this evidence?",

      pwTimelineEmpty: "No activity recorded yet.",

      pwReportsNoSession: "This project has no test session yet.",
      pwReportsOpenBtn: "Open & Download Report",
      pwProReportsLabel: "Professional Reports",
      pwProReportsDesc: "Downloadable Word (.docx) reports combining findings from all sessions in this project.",
      pwReportTypeTechnical: "Technical Report",
      pwReportTypeTechnicalDesc: "Full detail of every test result and finding — for pentesters/QA.",
      pwReportTypeExecutive: "Executive Summary",
      pwReportTypeExecutiveDesc: "Overall risk posture, numbers, and top findings — for management.",
      pwReportTypeDeveloper: "Developer Remediation",
      pwReportTypeDeveloperDesc: "Problem / Why It Matters / How To Fix format with concrete action steps.",
      pwReportsSessionExportLabel: "Simple JSON Export (per session)",

      pwEventType_project_created: "🆕 Project created",
      pwEventType_session_created: "📋 Session created",
      pwEventType_session_completed: "✅ Session completed",
      pwEventType_test_completed: "☑️ Test completed",
      pwEventType_finding_created: "🚩 New finding",
      pwEventType_scope_updated: "🎯 Scope updated",
      pwEventType_recon_run: "🌐 Recon run"
    }
  };

  let DATA = null;
  let TOP10 = null;
  let top10Index = 0;
  let progress = loadProgress();
  let findings = loadFindings();
  let reconPriority = loadReconPriority(); // test_id -> { level, reasons: [...] }
  let saveTimers = {};
  let currentCategoryId = null;
  let currentFilter = "all"; // all | done | pending
  let currentLang = loadLang();
  let currentFramework = loadFramework(); // 'wstg' | 'llm-security'
  let currentTheme = loadTheme();
  let dbOnline = false;
  let currentSession = null;   // {id, name, tester_name, target_url, status, ...}
  let sessionResults = {};     // test_id -> backend result row (only when a session is active)
  let currentProjectId = null; // Project/Engagement Management: açık olan proje
  let currentProjectObj = null;
  let editingProjectId = null; // newProjectOverlay create/edit modunu ayırt eder
  let activePwTab = 'overview';
  let customTests = []; // aktif projenin özel (Custom) test maddeleri

  function loadLang(){
    try{ return localStorage.getItem(LANG_KEY) || "tr"; }catch(e){ return "tr"; }
  }
  function saveLang(l){
    try{ localStorage.setItem(LANG_KEY, l); }catch(e){}
  }
  function loadFramework(){
    try{ const f = localStorage.getItem(FRAMEWORK_KEY); return f && FRAMEWORK_DATA_FILES[f] ? f : "wstg"; }catch(e){ return "wstg"; }
  }
  function saveFramework(f){
    try{ localStorage.setItem(FRAMEWORK_KEY, f); }catch(e){}
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

  function loadReconPriority(){
    try{ return JSON.parse(localStorage.getItem(RECON_PRIORITY_KEY)) || {}; }
    catch(e){ return {}; }
  }
  function saveReconPriority(){
    try{ localStorage.setItem(RECON_PRIORITY_KEY, JSON.stringify(reconPriority)); }catch(e){}
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

  function getEffectiveCategories(){
    if(!customTests.length) return DATA.categories;
    const customCategory = {
      id: 'custom-tests', code: 'CUSTOM', name: t('customTestsCategoryName'),
      description: t('customTestsCategoryDesc'),
      tests: customTests.map(ct => ({ id: ct.test_id, title: ct.title, description: ct.description || '', how_to_test: '', how_to_fix: '' }))
    };
    return DATA.categories.concat([customCategory]);
  }

  function allTests(){
    const arr = [];
    getEffectiveCategories().forEach(c => c.tests.forEach(t => arr.push({...t, catId:c.id, catCode:c.code, catName:c.name})));
    return arr;
  }

  function stats(){
    const tests = allTests();
    const total = tests.length;
    const done = tests.filter(t => progress[t.id]).length;
    return { total, done, pending: total-done, categories: getEffectiveCategories().length,
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
    const frameworkSelect = document.getElementById('frameworkSelect');
    if(frameworkSelect) frameworkSelect.value = currentFramework;
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
    nav.innerHTML = getEffectiveCategories().map(c => {
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
    grid.innerHTML = getEffectiveCategories().map(c => {
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
    const rp = reconPriority[test.id];
    return `<div class="test-item ${done?'done':''}" data-id="${test.id}">
      <div class="test-item-head">
        <button class="test-check ${done?'checked':''}" data-id="${test.id}" title="${t('testEditedTitle')}">
          ${icon('code').replace('code','')}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M4 12l5 5L20 6"/></svg>
        </button>
        <span class="test-item-code">${test.id}</span>
        <span class="test-item-title">${escapeHtml(test.title)}</span>
        ${hasFinding ? `<span class="severity-badge sev-${fd.severity}">${t('severity_'+fd.severity)}</span>` : ''}
        ${rp ? `<span class="recon-priority-badge prio-${rp.level}" title="${escapeHtml((rp.reasons||[]).join(' · '))}">${t('reconPriorityBadge_'+rp.level)}</span>` : ''}
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
          </div>
        </div>
      </div>
    </div>`;
  }

  function openCategory(catId, focusTestId){
    const cat = getEffectiveCategories().find(c=>c.id===catId);
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
    const cat = getEffectiveCategories().find(c=>c.id===currentCategoryId);
    if(!cat) return;
    const q = document.getElementById('itemSearch').value.trim().toLowerCase();
    let items = cat.tests;
    if(currentFilter === 'done') items = items.filter(t=>progress[t.id]);
    if(currentFilter === 'pending') items = items.filter(t=>!progress[t.id]);
    if(q) items = items.filter(x => x.title.toLowerCase().includes(q) || x.id.toLowerCase().includes(q) || x.description.toLowerCase().includes(q));
    const prioOrder = { high: 3, medium: 2, low: 1, info: 0 };
    items = items.slice().sort((a, b) => {
      const pa = reconPriority[a.id] ? (prioOrder[reconPriority[a.id].level] ?? 0) + 1 : 0;
      const pb = reconPriority[b.id] ? (prioOrder[reconPriority[b.id].level] ?? 0) + 1 : 0;
      return pb - pa;
    });
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
    getEffectiveCategories().forEach(c=>{
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
    const cats = getEffectiveCategories();
    for(let ci = 0; ci < cats.length; ci++){
      const c = cats[ci];
      for(const tItem of c.tests){
        if(tItem.id === id) return { title: tItem.title, catCode: c.code, catId: c.id, catIndex: ci };
      }
    }
    return null;
  }

  function maxSeverityLocal(a, b){
    const order = (window.WSTGImport && window.WSTGImport.SEVERITIES) || ["info","low","medium","high","critical"];
    return order.indexOf(b) > order.indexOf(a) ? b : a;
  }

  // ========================
  // CVSS v3.1 Calculator (client-side, birebir backend/cvss.py ile aynı
  // dogrulanmis formul — bkz. FIRST.org CVSS v3.1 Equations). CVSS v4.0
  // KASITLI OLARAK yok: skorlama sistemi buyuk bir lookup-table'a dayanir,
  // bellekten guvenilir sekilde yeniden uretilemez.
  // ========================
  const CVSS_AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
  const CVSS_AC = { L: 0.77, H: 0.44 };
  const CVSS_PR_U = { N: 0.85, L: 0.62, H: 0.27 };
  const CVSS_PR_C = { N: 0.85, L: 0.68, H: 0.50 };
  const CVSS_UI = { N: 0.85, R: 0.62 };
  const CVSS_CIA = { H: 0.56, L: 0.22, N: 0.0 };
  const CVSS_METRIC_OPTIONS = {
    AV: [['N','cvssAV_N'],['A','cvssAV_A'],['L','cvssAV_L'],['P','cvssAV_P']],
    AC: [['L','cvssAC_L'],['H','cvssAC_H']],
    PR: [['N','cvssPR_N'],['L','cvssPR_L'],['H','cvssPR_H']],
    UI: [['N','cvssUI_N'],['R','cvssUI_R']],
    S:  [['U','cvssS_U'],['C','cvssS_C']],
    C:  [['N','cvssCIA_N'],['L','cvssCIA_L'],['H','cvssCIA_H']],
    I:  [['N','cvssCIA_N'],['L','cvssCIA_L'],['H','cvssCIA_H']],
    A:  [['N','cvssCIA_N'],['L','cvssCIA_L'],['H','cvssCIA_H']],
  };
  const CVSS_DEFAULT_METRICS = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };

  function cvssRoundup(x){
    const intInput = Math.round(x * 100000);
    if(intInput % 10000 === 0) return intInput / 100000;
    return (Math.floor(intInput / 10000) + 1) / 10;
  }
  function cvssSeverityLabel(score){
    if(score <= 0) return 'info';
    if(score < 4.0) return 'low';
    if(score < 7.0) return 'medium';
    if(score < 9.0) return 'high';
    return 'critical';
  }
  function computeCvss(m){
    const av = CVSS_AV[m.AV], ac = CVSS_AC[m.AC], ui = CVSS_UI[m.UI];
    const pr = m.S === 'C' ? CVSS_PR_C[m.PR] : CVSS_PR_U[m.PR];
    const c = CVSS_CIA[m.C], i = CVSS_CIA[m.I], a = CVSS_CIA[m.A];
    const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
    let impact;
    if(m.S === 'C') impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    else impact = 6.42 * iscBase;
    const exploitability = 8.22 * av * ac * pr * ui;
    let baseScore;
    if(impact <= 0) baseScore = 0;
    else if(m.S === 'C') baseScore = cvssRoundup(Math.min(1.08 * (impact + exploitability), 10));
    else baseScore = cvssRoundup(Math.min(impact + exploitability, 10));
    const vector = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
    return {
      base_score: Math.round(baseScore * 10) / 10,
      severity: cvssSeverityLabel(baseScore),
      vector,
      impact_subscore: Math.round(Math.max(impact, 0) * 10) / 10,
      exploitability_subscore: Math.round(exploitability * 10) / 10,
    };
  }
  function parseCvssVector(vectorStr){
    if(!vectorStr) return null;
    const out = {};
    vectorStr.split('/').forEach(part => {
      const [k, v] = part.split(':');
      if(CVSS_DEFAULT_METRICS.hasOwnProperty(k)) out[k] = v;
    });
    return Object.keys(out).length === 8 ? out : null;
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
  // Attack Surface Discovery (Recon)
  // ========================

  let lastReconResult = null;

  function openReconModal(){
    document.getElementById('reconResultsWrap').style.display = 'none';
    document.getElementById('reconTargetInput').value = '';
    document.getElementById('reconAuthCheck').checked = false;
    const status = document.getElementById('reconStatus');
    status.textContent = '';
    status.classList.remove('error');
    lastReconResult = null;
    document.getElementById('reconOverlay').classList.add('open');
  }
  function closeReconModal(){
    document.getElementById('reconOverlay').classList.remove('open');
  }

  function runRecon(){
    const statusEl = document.getElementById('reconStatus');
    statusEl.classList.remove('error');
    const target = document.getElementById('reconTargetInput').value.trim();
    const authorized = document.getElementById('reconAuthCheck').checked;

    if(!target){
      statusEl.textContent = t('reconTargetRequired');
      statusEl.classList.add('error');
      return;
    }
    if(!authorized){
      statusEl.textContent = t('reconAuthRequired');
      statusEl.classList.add('error');
      return;
    }
    if(!dbOnline){
      statusEl.textContent = t('reconBackendOffline');
      statusEl.classList.add('error');
      return;
    }

    statusEl.textContent = t('reconRunning');
    document.getElementById('reconResultsWrap').style.display = 'none';

    apiRequest('/recon', {
      method: 'POST',
      body: JSON.stringify({ target, confirm_authorized: true, project_id: currentProjectId || undefined })
    }).then(result => {
      lastReconResult = result;
      statusEl.textContent = '';
      renderReconResults(result);
    }).catch(err => {
      statusEl.textContent = (t('reconError') + ': ') + (err && err.message ? err.message : String(err));
      statusEl.classList.add('error');
    });
  }

  function renderReconResults(result){
    document.getElementById('reconResultsWrap').style.display = '';

    const subEl = document.getElementById('reconSubdomains');
    subEl.innerHTML = (result.subdomains || []).map(s => `<span class="tool-chip">${escapeHtml(s)}</span>`).join('') || `<span class="import-preview-source">—</span>`;

    const techEl = document.getElementById('reconTech');
    techEl.innerHTML = (result.technologies || []).map(s => `<span class="tool-chip">${escapeHtml(s)}</span>`).join('') || `<span class="import-preview-source">—</span>`;

    const epEl = document.getElementById('reconEndpoints');
    const allPaths = Array.from(new Set([
      ...(result.endpoints || []),
      ...((result.interestingPaths || []).map(p => p.path))
    ]));
    epEl.innerHTML = allPaths.map(p => `<span class="tool-chip">${escapeHtml(p)}</span>`).join('') || `<span class="import-preview-source">—</span>`;

    const suggList = document.getElementById('reconSuggestionsList');
    const entries = Object.entries(result.suggestions || {});
    if(!entries.length){
      suggList.innerHTML = `<div class="search-empty">${t('reconNoSuggestions')}</div>`;
      return;
    }
    const prioOrder = { high: 3, medium: 2, low: 1, info: 0 };
    entries.sort((a, b) => (prioOrder[b[1].level] ?? 0) - (prioOrder[a[1].level] ?? 0));
    suggList.innerHTML = entries.map(([testId, info]) => {
      const meta = testInfoById(testId);
      return `<div class="import-preview-item">
        <input type="checkbox" class="recon-check" data-test="${testId}" checked>
        <div class="import-preview-body">
          <div class="import-preview-top">
            <span class="import-preview-title">${escapeHtml(testId)}${meta ? ' — ' + escapeHtml(meta.title) : ''}</span>
            <span class="recon-priority-badge prio-${info.level}">${t('reconPriorityBadge_'+info.level)}</span>
          </div>
          <div class="import-preview-detail">${escapeHtml((info.reasons || []).join('\n'))}</div>
        </div>
      </div>`;
    }).join('');
  }

  function applyReconPriorities(){
    if(!lastReconResult) return;
    const checks = Array.from(document.querySelectorAll('#reconSuggestionsList .recon-check'));
    let count = 0;
    checks.forEach(cb => {
      if(!cb.checked) return;
      const testId = cb.dataset.test;
      const info = lastReconResult.suggestions[testId];
      if(!info || !testInfoById(testId)) return;
      reconPriority[testId] = { level: info.level, reasons: info.reasons, target: lastReconResult.target, updatedAt: new Date().toISOString() };
      count++;
    });
    saveReconPriority();
    renderSidebar();
    renderDashboard();
    if(currentCategoryId) renderTestList();
    showToast(t('reconAppliedToast')(count));
    closeReconModal();
  }

  // ========================
  // Test Planı (AI Pentest Planner) — kural tabanlı, şeffaf skorlama
  //
  // Bilinçli tasarım kararı: bu bir model/LLM çağrısı yapmaz. Attack
  // Surface Discovery'nin ürettiği kanıtları (reconPriority) sabit,
  // izlenebilir bir formülle sıralar: öncelik seviyesi + kanıt sayısı +
  // WSTG'nin kendi kategori sırası (Identity → Authn → Authz → Session
  // → Input Validation → ... ) klasik pentest metodolojisini yansıtır.
  // ========================

  const PLAN_LEVEL_WEIGHT = { high: 100, medium: 60, low: 30, info: 10 };

  function computePlanScore(testId, info, meta){
    const levelWeight = PLAN_LEVEL_WEIGHT[info.level] || 10;
    const evidenceBonus = Math.min((info.reasons || []).length * 8, 24);
    const categoryCount = (DATA && DATA.categories) ? DATA.categories.length : 12;
    const methodologyBonus = meta ? (categoryCount - meta.catIndex) : 0;
    return levelWeight + evidenceBonus + methodologyBonus;
  }

  function buildTestPlan(){
    const rows = Object.entries(reconPriority).map(([testId, info]) => {
      const meta = testInfoById(testId);
      if(!meta) return null;
      return { testId, info, meta, score: computePlanScore(testId, info, meta) };
    }).filter(Boolean);
    rows.sort((a, b) => b.score - a.score);
    return rows;
  }

  function openPlannerModal(){
    renderPlanner();
    document.getElementById('plannerOverlay').classList.add('open');
  }
  function closePlannerModal(){
    document.getElementById('plannerOverlay').classList.remove('open');
  }

  function renderPlanner(){
    const list = document.getElementById('plannerList');
    const rows = buildTestPlan();
    if(!rows.length){
      list.innerHTML = `<div class="search-empty">${t('plannerEmpty')}</div>`;
      return;
    }
    const maxScore = rows[0].score || 1;
    list.innerHTML = rows.map((row, i) => {
      const pct = Math.max(8, Math.round((row.score / maxScore) * 100));
      return `<div class="planner-row">
        <div class="planner-rank">#${i + 1}</div>
        <div class="planner-body">
          <div class="planner-top">
            <span class="planner-id">${escapeHtml(row.testId)}</span>
            <span class="planner-title">${escapeHtml(row.meta.title)}</span>
            <span class="recon-priority-badge prio-${row.info.level}">${t('reconPriorityBadge_'+row.info.level)}</span>
          </div>
          <div class="planner-bar-track"><div class="planner-bar-fill prio-${row.info.level}" style="width:${pct}%"></div></div>
          <div class="planner-reason"><strong>${t('plannerReasonLabel')}:</strong> ${escapeHtml((row.info.reasons || []).join(' · '))}</div>
          <button type="button" class="planner-goto-btn" data-cat="${row.meta.catId}" data-test="${row.testId}">${t('plannerGotoBtn')}</button>
        </div>
      </div>`;
    }).join('') + `<div class="planner-score-note">${t('plannerScoreNote')}</div>`;
  }

  // ========================
  // Project / Engagement Management
  //
  // Tasarım notu: bu modül, mevcut Recon/Test Planı/WSTG Checklist/Rapor
  // özelliklerini YENİDEN YAZMAZ — bir proje bağlamı (currentProjectId)
  // set eder ve o özelliklerin mevcut overlay'lerini açar. Örn. "WSTG
  // Tests" sekmesi, projeye bağlı bir Session oluşturup/seçip mevcut
  // openSessionById() akışına devrediyor. Böylece proje sistemi olmadan
  // kullanan biri için hiçbir davranış değişmiyor.
  // ========================

  function updateProjectChip(){
    const chip = document.getElementById('projectChip');
    if(!chip) return;
    if(currentProjectObj){
      chip.style.display = 'flex';
      document.getElementById('projectChipName').textContent = currentProjectObj.name;
      document.getElementById('projectChipSub').textContent = currentProjectObj.client || t('navProjects');
    } else {
      chip.style.display = 'none';
    }
  }

  function openProjectsModal(){
    document.getElementById('projectsOverlay').classList.add('open');
    renderProjectList();
  }
  function closeProjectsModal(){
    document.getElementById('projectsOverlay').classList.remove('open');
  }

  function renderProjectList(){
    const body = document.getElementById('projectListBody');
    const countLabel = document.getElementById('projectsCountLabel');
    if(!dbOnline){
      countLabel.textContent = '';
      body.innerHTML = `<div class="search-empty">${t('projectsBackendOffline')}</div>`;
      return;
    }
    body.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest('/projects').then(projects => {
      countLabel.textContent = t('projectsCountLabel')(projects.length);
      if(!projects.length){
        body.innerHTML = `<div class="search-empty">${t('noProjectsYet')}</div>`;
        return;
      }
      body.innerHTML = projects.map(p => `
        <div class="project-card" data-id="${p.id}">
          <div class="project-card-top">
            <div>
              <div class="project-card-name">${escapeHtml(p.name)}</div>
              <div class="project-card-meta">
                ${p.client ? `<span>🏢 ${escapeHtml(p.client)}</span>` : ''}
                <span>📁 ${t('projectSessionsLabel')(p.session_count || 0)}</span>
                ${p.start_date ? `<span>📅 ${escapeHtml(p.start_date)}${p.end_date ? ' → ' + escapeHtml(p.end_date) : ''}</span>` : ''}
              </div>
            </div>
            <span class="project-status-pill ${p.status}">${t('projectStatus_'+p.status)}</span>
          </div>
          ${p.description ? `<div class="import-preview-source">${escapeHtml(p.description)}</div>` : ''}
          <div class="project-card-actions">
            <button data-action="open" data-id="${p.id}">${t('openProjectBtn')}</button>
            <button data-action="edit" data-id="${p.id}">${t('editBtn')}</button>
            <button data-action="delete" data-id="${p.id}" class="danger">🗑️</button>
          </div>
        </div>`).join('');
    }).catch(err => {
      body.innerHTML = `<div class="search-empty">${t('projectsLoadError')}<br><small>${escapeHtml(String(err.message||err))}</small></div>`;
    });
  }

  function openNewProjectModal(project){
    editingProjectId = project ? project.id : null;
    document.getElementById('newProjectTitle').textContent = project ? t('editProjectModalTitle') : t('newProjectModalTitle');
    document.getElementById('projectNameInput').value = project ? project.name : '';
    document.getElementById('projectClientInput').value = project ? (project.client || '') : '';
    document.getElementById('projectDescInput').value = project ? (project.description || '') : '';
    document.getElementById('projectStatusInput').value = project ? project.status : 'planning';
    document.getElementById('projectStartInput').value = project ? (project.start_date || '') : '';
    document.getElementById('projectEndInput').value = project ? (project.end_date || '') : '';
    document.getElementById('newProjectOverlay').classList.add('open');
    setTimeout(()=> document.getElementById('projectNameInput').focus(), 50);
  }
  function closeNewProjectModal(){
    document.getElementById('newProjectOverlay').classList.remove('open');
  }

  function submitProjectForm(){
    const name = document.getElementById('projectNameInput').value.trim();
    if(!name){ showToast(t('projectNameRequired')); return; }
    const payload = {
      name,
      client: document.getElementById('projectClientInput').value.trim(),
      description: document.getElementById('projectDescInput').value.trim(),
      status: document.getElementById('projectStatusInput').value,
      start_date: document.getElementById('projectStartInput').value || null,
      end_date: document.getElementById('projectEndInput').value || null
    };
    const req = editingProjectId
      ? apiRequest(`/projects/${editingProjectId}`, { method: 'PUT', body: JSON.stringify(payload) })
      : apiRequest('/projects', { method: 'POST', body: JSON.stringify(payload) });
    req.then(project => {
      closeNewProjectModal();
      showToast(t('projectSaved'));
      if(document.getElementById('projectsOverlay').classList.contains('open')) renderProjectList();
      if(currentProjectId === project.id){
        currentProjectObj = project;
        updateProjectChip();
        renderProjectWorkspaceHeader();
      }
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  function deleteProjectUI(id){
    if(!confirm(t('projectDeleteConfirm'))) return;
    apiRequest(`/projects/${id}`, { method: 'DELETE' }).then(()=>{
      if(currentProjectId === id){
        currentProjectId = null;
        currentProjectObj = null;
        customTests = [];
        updateProjectChip();
        closeProjectWorkspace();
        renderSidebar(); renderDashboard();
      }
      renderProjectList();
      showToast(t('projectDeleted'));
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  function renderProjectWorkspaceHeader(){
    if(!currentProjectObj) return;
    document.getElementById('pwName').textContent = currentProjectObj.name;
    document.getElementById('pwClient').textContent = currentProjectObj.client || '';
    const pill = document.getElementById('pwStatusPill');
    pill.textContent = t('projectStatus_'+currentProjectObj.status);
    pill.className = `project-status-pill ${currentProjectObj.status}`;
  }

  function openProjectWorkspace(projectId){
    apiRequest(`/projects/${projectId}`).then(project => {
      currentProjectId = project.id;
      currentProjectObj = project;
      updateProjectChip();
      closeProjectsModal();
      renderProjectWorkspaceHeader();
      switchPwTab('overview');
      document.getElementById('projectWorkspaceOverlay').classList.add('open');
      return apiRequest(`/projects/${projectId}/custom-tests`);
    }).then(items => {
      customTests = items || [];
      renderSidebar(); renderDashboard();
    }).catch(err => showToast(err.message || t('projectsLoadError')));
  }
  function closeProjectWorkspace(){
    document.getElementById('projectWorkspaceOverlay').classList.remove('open');
  }

  function switchPwTab(tabName){
    activePwTab = tabName;
    document.querySelectorAll('#pwTabs .pw-tab').forEach(btn=>{
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    renderPwTab();
  }

  function renderPwTab(){
    const map = {
      overview: renderPwOverview, scope: renderPwScope, assets: renderPwAssets,
      recon: renderPwRecon, tools: renderPwTools, testplan: renderPwTestPlan, wstg: renderPwWstg,
      findings: renderPwFindings, evidence: renderPwEvidence, chains: renderPwChains,
      timeline: renderPwTimeline, reports: renderPwReports
    };
    const fn = map[activePwTab];
    if(fn) fn();
  }

  function renderPwOverview(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest(`/projects/${currentProjectId}/dashboard`).then(d => {
      const sevOrder = ['critical','high','medium','low','info'];
      const sevColors = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#94a3b8' };
      const maxSev = Math.max(1, ...sevOrder.map(k => d.severity_counts[k] || 0));

      const coverageHtml = d.coverage ? `
        <h5 class="pw-section-heading">${t('pwCoverageLabel')}</h5>
        <div class="pw-coverage-row">
          ${['wstg','llm','custom'].map(fw => {
            const cov = d.coverage[fw];
            return `<div class="pw-coverage-item">
              <div class="pw-coverage-top"><span>${t('pwCoverage_'+fw)}</span><span>${cov.completed}/${cov.total}</span></div>
              <div class="cat-progress-bar"><div class="cat-progress-fill" style="width:${cov.pct}%"></div></div>
            </div>`;
          }).join('')}
        </div>` : '';

      const catEntries = d.findings_by_category ? Object.entries(d.findings_by_category).sort((a,b)=>b[1]-a[1]) : [];
      const maxCat = Math.max(1, ...catEntries.map(([,c])=>c));
      const categoryHtml = catEntries.length ? `
        <h5 class="pw-section-heading">${t('pwFindingsByCategoryLabel')}</h5>
        <div class="pw-severity-row" style="margin-bottom:22px">
          ${catEntries.map(([cat,count]) => `
            <div class="pw-severity-item">
              <span class="sev-label" style="width:180px" title="${escapeHtml(cat)}">${escapeHtml(cat)}</span>
              <div class="sev-track"><div class="sev-fill" style="width:${Math.round((count/maxCat)*100)}%;background:var(--primary)"></div></div>
              <span class="sev-count">${count}</span>
            </div>`).join('')}
        </div>` : '';

      const topEndpoints = d.top_endpoints || [];
      const endpointsHtml = topEndpoints.length ? `
        <h5 class="pw-section-heading">${t('pwTopEndpointsLabel')}</h5>
        <div class="pw-endpoint-list">
          ${topEndpoints.map(e => `
            <div class="pw-endpoint-row">
              <span class="pw-endpoint-path">${escapeHtml(e.endpoint)}</span>
              <span class="pw-endpoint-count">${e.count} ${t('pwEndpointFindingsSuffix')}</span>
            </div>`).join('')}
        </div>` : '';

      content.innerHTML = `
        <div class="pw-stats-grid">
          <div class="pw-stat-card"><div class="label">${t('pwStatAssets')}</div><div class="value">${d.asset_count}</div></div>
          <div class="pw-stat-card"><div class="label">${t('pwStatTests')}</div><div class="value">${d.total_tests}</div></div>
          <div class="pw-stat-card"><div class="label">${t('pwStatCompleted')}</div><div class="value">${d.completed_tests}</div></div>
          <div class="pw-stat-card"><div class="label">${t('pwStatFindings')}</div><div class="value">${d.pro_finding_count !== undefined ? d.pro_finding_count : d.finding_count}</div></div>
        </div>
        <div class="cat-progress-row" style="margin-bottom:22px">
          <div class="cat-progress-bar" style="flex:1"><div class="cat-progress-fill" style="width:${d.progress_pct}%"></div></div>
          <div class="cat-progress-text">${d.progress_pct}%</div>
        </div>
        ${coverageHtml}
        <h5 class="pw-section-heading">${t('pwSeverityDistLabel')}</h5>
        <div class="pw-severity-row" style="margin-bottom:22px">
          ${sevOrder.map(k => {
            const count = d.severity_counts[k] || 0;
            const pct = Math.round((count / maxSev) * 100);
            return `<div class="pw-severity-item">
              <span class="sev-label">${t('severity_'+k)}</span>
              <div class="sev-track"><div class="sev-fill" style="width:${pct}%;background:${sevColors[k]}"></div></div>
              <span class="sev-count">${count}</span>
            </div>`;
          }).join('')}
        </div>
        ${categoryHtml}
        ${endpointsHtml}`;
    }).catch(err => {
      content.innerHTML = `<div class="search-empty">${t('pwOverviewLoadError')}<br><small>${escapeHtml(String(err.message||err))}</small></div>`;
    });
  }

  function renderPwScope(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `
      <div class="pw-scope-form">
        <select id="pwScopeType">
          <option value="domain">${t('pwScopeType_domain')}</option>
          <option value="subdomain">${t('pwScopeType_subdomain')}</option>
          <option value="ip">${t('pwScopeType_ip')}</option>
          <option value="cidr">${t('pwScopeType_cidr')}</option>
        </select>
        <input type="text" id="pwScopeValue" placeholder="${t('pwScopeValuePlaceholder')}">
        <select id="pwScopeInOut">
          <option value="1">${t('pwScopeInScope')}</option>
          <option value="0">${t('pwScopeOutOfScope')}</option>
        </select>
        <button type="button" class="btn btn-primary btn-sm" id="pwScopeAddBtn">${t('pwScopeAddBtn')}</button>
      </div>
      <div class="pw-scope-list" id="pwScopeList"><div class="search-empty">${t('loadingSessions')}</div></div>`;

    document.getElementById('pwScopeAddBtn').addEventListener('click', ()=>{
      const value = document.getElementById('pwScopeValue').value.trim();
      if(!value){ showToast(t('pwScopeValueRequired')); return; }
      const payload = {
        type: document.getElementById('pwScopeType').value,
        value,
        in_scope: document.getElementById('pwScopeInOut').value === '1'
      };
      apiRequest(`/projects/${currentProjectId}/scope`, { method:'POST', body: JSON.stringify(payload) })
        .then(()=>{ document.getElementById('pwScopeValue').value = ''; loadPwScopeList(); })
        .catch(err => showToast(err.message || t('resultSaveError')));
    });

    loadPwScopeList();
  }

  function loadPwScopeList(){
    const list = document.getElementById('pwScopeList');
    apiRequest(`/projects/${currentProjectId}/scope`).then(items => {
      if(!items.length){
        list.innerHTML = `<div class="search-empty">${t('pwScopeEmpty')}</div>`;
        return;
      }
      list.innerHTML = items.map(i => `
        <div class="pw-scope-row ${i.in_scope ? '' : 'out-of-scope'}">
          <span class="scope-type">${t('pwScopeType_'+i.type)}</span>
          <span class="scope-value">${escapeHtml(i.value)}</span>
          ${i.description ? `<span class="import-preview-source">${escapeHtml(i.description)}</span>` : ''}
          <button data-id="${i.id}" title="Sil">✕</button>
        </div>`).join('');
      list.querySelectorAll('button[data-id]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          apiRequest(`/projects/${currentProjectId}/scope/${btn.dataset.id}`, { method:'DELETE' })
            .then(loadPwScopeList).catch(err => showToast(err.message || t('resultSaveError')));
        });
      });
    });
  }

  let assetsViewMode = 'list'; // 'list' | 'map'
  let lastAssetsData = null;
  let lastFindingsForMap = [];

  function renderPwAssets(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    Promise.all([
      apiRequest(`/projects/${currentProjectId}/assets`),
      apiRequest(`/projects/${currentProjectId}/findings`)
    ]).then(([a, findings])=>{
      lastAssetsData = a;
      lastFindingsForMap = findings;
      if(!a.subdomains.length && !a.technologies.length && !a.endpoints.length){
        content.innerHTML = `<div class="search-empty">${t('pwAssetsEmpty')}</div>`;
        return;
      }
      renderAssetsView();
    });
  }

  function renderAssetsView(){
    const content = document.getElementById('pwContent');
    const a = lastAssetsData;
    const toggleHtml = `
      <div class="asm-view-toggle">
        <button type="button" class="asm-toggle-btn ${assetsViewMode==='list'?'active':''}" data-mode="list">${t('pwAssetsViewList')}</button>
        <button type="button" class="asm-toggle-btn ${assetsViewMode==='map'?'active':''}" data-mode="map">${t('pwAssetsViewMap')}</button>
      </div>`;

    if(assetsViewMode === 'list'){
      const chipRow = arr => arr.length ? arr.map(v => `<span class="tool-chip">${escapeHtml(v)}</span>`).join('') : `<span class="import-preview-source">—</span>`;
      content.innerHTML = toggleHtml + `
        <div class="recon-section" style="margin-top:14px">
          <h5>${t('pwAssetsSubdomains')}</h5>
          <div class="recon-chip-row">${chipRow(a.subdomains)}</div>
        </div>
        <div class="recon-section">
          <h5>${t('pwAssetsTechnologies')}</h5>
          <div class="recon-chip-row">${chipRow(a.technologies)}</div>
        </div>
        <div class="recon-section">
          <h5>${t('pwAssetsEndpoints')}</h5>
          <div class="recon-chip-row">${chipRow(a.endpoints)}</div>
        </div>`;
    } else {
      const rootLabel = (a.runs && a.runs[0] && a.runs[0].target) || (currentProjectObj && currentProjectObj.name) || '—';
      content.innerHTML = toggleHtml + `
        <div class="asm-tree" style="margin-top:16px">
          <div class="asm-root">🌐 ${escapeHtml(rootLabel)}</div>
          <div class="asm-branches">
            <div class="asm-branch">
              <div class="asm-branch-title">${t('pwAssetsSubdomains')} (${a.subdomains.length})</div>
              <div class="asm-nodes">
                ${a.subdomains.length ? a.subdomains.map(s => `<div class="asm-node">${escapeHtml(s)}</div>`).join('') : `<div class="asm-node muted">—</div>`}
              </div>
            </div>
            <div class="asm-branch">
              <div class="asm-branch-title">${t('pwAssetsEndpoints')} (${a.endpoints.length})</div>
              <div class="asm-nodes">
                ${a.endpoints.length ? a.endpoints.map(ep => `<div class="asm-node asm-node-clickable" data-endpoint="${escapeHtml(ep)}">${escapeHtml(ep)}</div>`).join('') : `<div class="asm-node muted">—</div>`}
              </div>
            </div>
          </div>
        </div>
        <div id="asmEndpointDetail" class="asm-endpoint-detail" style="display:none"></div>`;

      content.querySelectorAll('.asm-node-clickable').forEach(node => {
        node.addEventListener('click', ()=>{
          content.querySelectorAll('.asm-node-clickable').forEach(n => n.classList.remove('selected'));
          node.classList.add('selected');
          renderEndpointDetail(node.dataset.endpoint);
        });
      });
    }

    content.querySelectorAll('.asm-toggle-btn').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        assetsViewMode = btn.dataset.mode;
        renderAssetsView();
      });
    });
  }

  function renderEndpointDetail(endpoint){
    const box = document.getElementById('asmEndpointDetail');
    const matched = lastFindingsForMap.filter(f => f.endpoint && f.endpoint.includes(endpoint));
    box.style.display = '';
    box.innerHTML = `
      <div class="asm-endpoint-detail-top">
        <span class="asm-endpoint-path">${escapeHtml(endpoint)}</span>
        <button type="button" class="btn btn-primary btn-sm" id="asmCreateFindingBtn">${t('newFindingBtn')}</button>
      </div>
      <div class="asm-endpoint-findings-label">${t('pwAssetsMapFindingsLabel')}</div>
      ${matched.length ? matched.map(f => `
        <div class="asm-endpoint-finding-row">
          <span class="finding-code">${f.finding_code}</span>
          <span class="severity-badge sev-${f.severity}">${t('severity_'+f.severity)}</span>
          <span>${escapeHtml(f.title)}</span>
        </div>`).join('') : `<div class="import-preview-source">${t('pwAssetsMapNoFindings')}</div>`}
    `;
    document.getElementById('asmCreateFindingBtn').addEventListener('click', ()=>{
      openFindingModal(null, { title: endpoint, endpoint });
    });
  }

  function renderPwRecon(){
    document.getElementById('pwContent').innerHTML = `
      <div class="pw-shortcut-card">
        <p>${t('pwReconDesc')}</p>
        <button type="button" class="btn btn-primary" id="pwOpenReconBtn">${t('pwReconOpenBtn')}</button>
      </div>`;
    document.getElementById('pwOpenReconBtn').addEventListener('click', ()=>{
      closeProjectWorkspace();
      openReconModal();
    });
  }

  // ========================
  // Tool Integration (nmap / httpx / whatweb / subfinder / dnsx)
  // Gercek CLI araclarini kullanicinin kendi makinesinde calistirir.
  // Guvenlik: backend/tool_runner.py -- argv-list subprocess, shell=True yok,
  // sabit komut sablonlari, SSRF korumali hedef dogrulama. nuclei/ffuf
  // bilerek dahil edilmedi (bkz. pwToolsExcludedNote).
  // ========================

  let lastToolPreview = null;

  function renderPwTools(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `
      <p class="import-preview-source" style="margin-bottom:6px">${t('pwToolsDesc')}</p>
      <p class="import-preview-source" style="margin-bottom:16px;font-style:italic">${t('pwToolsExcludedNote')}</p>
      <div class="import-form">
        <label>${t('toolSelectLabel')}</label>
        <select id="toolSelect"></select>
        <div id="toolInstallWarning" class="import-status error" style="display:none"></div>
        <label>${t('toolTargetLabel')}</label>
        <input type="text" id="toolTargetInput" placeholder="example.com">
        <div id="toolPreviewBox" style="display:none;margin-top:10px">
          <div class="import-preview-source">${t('toolPreviewLabel')}</div>
          <code class="tool-command-preview" id="toolCommandPreview"></code>
        </div>
        <label class="recon-auth-check">
          <input type="checkbox" id="toolAuthCheck">
          <span>${t('toolAuthLabel')}</span>
        </label>
        <div class="hero-actions" style="margin-top:10px;gap:8px">
          <button type="button" class="btn btn-secondary" id="toolPreviewBtn">${t('toolPreviewBtn')}</button>
          <button type="button" class="btn btn-primary" id="toolRunBtn" disabled>${t('toolRunBtn')}</button>
        </div>
        <div class="import-status" id="toolStatus"></div>
      </div>
      <div id="toolResultBox"></div>
      <div class="recon-section">
        <h5>${t('toolHistoryLabel')}</h5>
        <div id="toolHistoryList"></div>
      </div>`;

    apiRequest('/tools').then(tools => {
      const sel = document.getElementById('toolSelect');
      sel.innerHTML = tools.map(tool =>
        `<option value="${tool.id}" data-available="${tool.available}">${tool.label}${tool.available ? '' : ' — ' + t('toolNotInstalled')}</option>`
      ).join('');
      updateToolInstallWarning(tools);
      sel.addEventListener('change', ()=> updateToolInstallWarning(tools));
    }).catch(()=>{});

    function updateToolInstallWarning(tools){
      const sel = document.getElementById('toolSelect');
      const warn = document.getElementById('toolInstallWarning');
      const tool = tools.find(x => x.id === sel.value);
      if(tool && !tool.available){
        warn.style.display = '';
        warn.textContent = t('toolNotInstalled');
      } else {
        warn.style.display = 'none';
      }
    }

    document.getElementById('toolPreviewBtn').addEventListener('click', ()=>{
      const statusEl = document.getElementById('toolStatus');
      const target = document.getElementById('toolTargetInput').value.trim();
      const tool = document.getElementById('toolSelect').value;
      statusEl.classList.remove('error');
      if(!target){ statusEl.textContent = t('toolTargetRequired'); statusEl.classList.add('error'); return; }
      apiRequest('/tools/preview', { method: 'POST', body: JSON.stringify({ tool, target }) })
        .then(preview => {
          lastToolPreview = preview;
          statusEl.textContent = '';
          document.getElementById('toolPreviewBox').style.display = '';
          document.getElementById('toolCommandPreview').textContent = preview.command;
          document.getElementById('toolRunBtn').disabled = !document.getElementById('toolAuthCheck').checked || !preview.available;
        })
        .catch(err => {
          statusEl.textContent = err.message || t('toolRunError');
          statusEl.classList.add('error');
          document.getElementById('toolPreviewBox').style.display = 'none';
          lastToolPreview = null;
        });
    });

    document.getElementById('toolAuthCheck').addEventListener('change', e=>{
      document.getElementById('toolRunBtn').disabled = !e.target.checked || !lastToolPreview || !lastToolPreview.available;
    });

    document.getElementById('toolRunBtn').addEventListener('click', ()=>{
      const statusEl = document.getElementById('toolStatus');
      statusEl.classList.remove('error');
      if(!document.getElementById('toolAuthCheck').checked){
        statusEl.textContent = t('toolAuthRequired'); statusEl.classList.add('error'); return;
      }
      if(!lastToolPreview){ return; }
      statusEl.textContent = t('toolRunning');
      document.getElementById('toolRunBtn').disabled = true;
      apiRequest(`/projects/${currentProjectId}/tools/run`, {
        method: 'POST',
        body: JSON.stringify({ tool: lastToolPreview.tool, target: lastToolPreview.target, confirm_authorized: true })
      }).then(run => {
        statusEl.textContent = '';
        renderToolResult(run);
        loadToolHistory();
      }).catch(err => {
        statusEl.textContent = err.message || t('toolRunError');
        statusEl.classList.add('error');
      }).finally(()=>{
        document.getElementById('toolRunBtn').disabled = false;
      });
    });

    loadToolHistory();
  }

  function renderToolResult(run){
    const box = document.getElementById('toolResultBox');
    if(!box) return;
    box.innerHTML = `
      <div class="tool-result-card">
        <div class="tool-result-top">
          <span class="tool-command-preview">${escapeHtml(run.command)}</span>
          <span class="tool-status-badge status-${run.status}">${t('toolStatus_'+run.status)}</span>
        </div>
        ${run.exit_code !== null && run.exit_code !== undefined ? `<div class="import-preview-source">${t('toolExitCodeLabel')}: ${run.exit_code}</div>` : ''}
        ${run.stdout ? `<pre class="tool-output">${escapeHtml(run.stdout)}</pre>` : ''}
        ${run.stderr ? `<pre class="tool-output tool-output-err">${escapeHtml(run.stderr)}</pre>` : ''}
      </div>`;
  }

  function loadToolHistory(){
    const list = document.getElementById('toolHistoryList');
    if(!list) return;
    apiRequest(`/projects/${currentProjectId}/tools/runs`).then(runs => {
      if(!runs.length){
        list.innerHTML = `<div class="search-empty">${t('toolHistoryEmpty')}</div>`;
        return;
      }
      list.innerHTML = runs.map(r => `
        <div class="tool-history-row" data-id="${r.id}">
          <span class="tool-status-badge status-${r.status}">${t('toolStatus_'+r.status)}</span>
          <span class="scope-value">${escapeHtml(r.tool)} → ${escapeHtml(r.target)}</span>
          <span class="import-preview-source">${new Date(r.created_at).toLocaleString(t('dateLocale'))}</span>
        </div>`).join('');
      list.querySelectorAll('.tool-history-row').forEach(row=>{
        row.addEventListener('click', ()=>{
          const run = runs.find(r => String(r.id) === row.dataset.id);
          if(run) renderToolResult(run);
        });
      });
    }).catch(()=>{
      list.innerHTML = `<div class="search-empty">${t('toolHistoryEmpty')}</div>`;
    });
  }

  function renderPwTestPlan(){
    document.getElementById('pwContent').innerHTML = `
      <div class="pw-shortcut-card">
        <p>${t('pwTestPlanDesc')}</p>
        <button type="button" class="btn btn-primary" id="pwOpenPlannerBtn">${t('pwTestPlanOpenBtn')}</button>
      </div>`;
    document.getElementById('pwOpenPlannerBtn').addEventListener('click', ()=>{
      closeProjectWorkspace();
      openPlannerModal();
    });
  }

  function ensureProjectPrimarySession(projectId){
    return apiRequest(`/sessions?project_id=${projectId}`).then(sessions => {
      if(sessions && sessions.length) return sessions[0];
      return apiRequest('/sessions', {
        method: 'POST',
        body: JSON.stringify({ name: `${currentProjectObj.name} — Test Oturumu`, project_id: projectId })
      });
    });
  }

  function renderPwWstg(){
    document.getElementById('pwContent').innerHTML = `
      <div class="pw-shortcut-card">
        <p>${t('pwWstgDesc')}</p>
        <button type="button" class="btn btn-primary" id="pwOpenWstgBtn">${t('pwWstgOpenBtn')}</button>
      </div>
      <div class="custom-tests-section">
        <h5>${t('customTestsLabel')}</h5>
        <p class="import-preview-source" style="margin-bottom:14px">${t('customTestsDesc')}</p>
        <div class="pw-scope-form">
          <input type="text" id="customTestTitleInput" placeholder="${t('customTestTitlePlaceholder')}">
          <button type="button" class="btn btn-primary btn-sm" id="addCustomTestBtn">${t('customTestAddBtn')}</button>
        </div>
        <input type="text" id="customTestDescInput" placeholder="${t('customTestDescPlaceholder')}" style="width:100%;margin-bottom:14px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:10px;font-size:.85rem;font-family:inherit">
        <div id="customTestsList" class="pw-scope-list"></div>
      </div>`;
    document.getElementById('pwOpenWstgBtn').addEventListener('click', ()=>{
      ensureProjectPrimarySession(currentProjectId).then(session => {
        closeProjectWorkspace();
        return openSessionById(session.id);
      }).catch(err => showToast(err.message || t('resultSaveError')));
    });
    document.getElementById('addCustomTestBtn').addEventListener('click', ()=>{
      const title = document.getElementById('customTestTitleInput').value.trim();
      if(!title){ showToast(t('customTestTitleRequired')); return; }
      const description = document.getElementById('customTestDescInput').value.trim();
      apiRequest(`/projects/${currentProjectId}/custom-tests`, {
        method: 'POST', body: JSON.stringify({ title, description })
      }).then(()=>{
        document.getElementById('customTestTitleInput').value = '';
        document.getElementById('customTestDescInput').value = '';
        return loadCustomTestsList();
      }).catch(err => showToast(err.message || t('resultSaveError')));
    });
    loadCustomTestsList();
  }

  function loadCustomTestsList(){
    return apiRequest(`/projects/${currentProjectId}/custom-tests`).then(items => {
      customTests = items || [];
      renderSidebar(); renderDashboard();
      const list = document.getElementById('customTestsList');
      if(!list) return; // kullanıcı sekmeyi değiştirmiş olabilir
      if(!items.length){
        list.innerHTML = `<div class="search-empty">${t('customTestsEmpty')}</div>`;
        return;
      }
      list.innerHTML = items.map(ct => `
        <div class="pw-scope-row">
          <span class="scope-type">${escapeHtml(ct.test_id)}</span>
          <span class="scope-value">${escapeHtml(ct.title)}</span>
          ${ct.description ? `<span class="import-preview-source">${escapeHtml(ct.description)}</span>` : ''}
          <button data-test="${ct.test_id}" title="Sil">✕</button>
        </div>`).join('');
      list.querySelectorAll('button[data-test]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          apiRequest(`/projects/${currentProjectId}/custom-tests/${btn.dataset.test}`, { method: 'DELETE' })
            .then(loadCustomTestsList).catch(err => showToast(err.message || t('resultSaveError')));
        });
      });
    });
  }

  const FINDING_STATUS_LABELS = {
    open: 'lifecycleStatus_open', retesting: 'lifecycleStatus_retesting', fixed: 'lifecycleStatus_fixed',
    resolved: 'lifecycleStatus_resolved', wont_fix: 'lifecycleStatus_wont_fix', accepted_risk: 'lifecycleStatus_accepted_risk'
  };

  const FINDING_MODEL_STATUS_ORDER = ['open','confirmed','fixed','retest_pending','resolved','wont_fix','accepted_risk'];
  let editingFindingId = null;
  let currentCvssMetrics = Object.assign({}, CVSS_DEFAULT_METRICS);

  function renderCvssCalculator(){
    const grid = document.getElementById('cvssCalcGrid');
    grid.innerHTML = Object.keys(CVSS_METRIC_OPTIONS).map(key => `
      <div class="cvss-metric-group">
        <label>${t('cvss'+key)}</label>
        <div class="cvss-btn-row" data-metric="${key}">
          ${CVSS_METRIC_OPTIONS[key].map(([val, labelKey]) => `
            <button type="button" class="cvss-btn ${currentCvssMetrics[key]===val ? 'active' : ''}" data-value="${val}">${t(labelKey)}</button>
          `).join('')}
        </div>
      </div>`).join('');
    grid.querySelectorAll('.cvss-btn-row').forEach(row => {
      row.querySelectorAll('.cvss-btn').forEach(btn => {
        btn.addEventListener('click', ()=>{
          currentCvssMetrics[row.dataset.metric] = btn.dataset.value;
          renderCvssCalculator();
          updateCvssScoreDisplay();
        });
      });
    });
    updateCvssScoreDisplay();
  }

  function updateCvssScoreDisplay(){
    const result = computeCvss(currentCvssMetrics);
    const valEl = document.getElementById('cvssScoreValue');
    const sevEl = document.getElementById('cvssScoreSeverity');
    const vecEl = document.getElementById('cvssVectorString');
    valEl.textContent = result.base_score.toFixed(1);
    valEl.className = 'cvss-score-value sev-' + result.severity;
    sevEl.textContent = t('severity_' + result.severity);
    sevEl.className = 'cvss-score-severity sev-' + result.severity;
    vecEl.textContent = result.vector;
  }

  function openFindingModal(finding, prefill){
    editingFindingId = finding ? finding.id : null;
    document.getElementById('findingModalTitle').textContent = finding ? t('findingModalTitleEdit') : t('findingModalTitleNew');

    const f = finding || prefill || {};
    document.getElementById('findingTitleInput').value = f.title || '';
    document.getElementById('findingTestIdInput').value = f.test_id || '';
    document.getElementById('findingEndpointInput').value = f.endpoint || '';
    document.getElementById('findingParameterInput').value = f.parameter || '';
    document.getElementById('findingCweInput').value = f.cwe || '';
    document.getElementById('findingOwaspCatInput').value = f.owasp_category || '';
    document.getElementById('findingDescInput').value = f.description || '';
    document.getElementById('findingImpactInput').value = f.impact || '';
    document.getElementById('findingRemediationInput').value = f.remediation || '';
    document.getElementById('findingReferencesInput').value = f.references || '';
    document.getElementById('findingStatusInput').value = f.status || 'open';
    document.getElementById('findingAssignedInput').value = f.assigned_to || '';

    const retestSection = document.getElementById('findingRetestSection');
    if(finding){
      retestSection.style.display = '';
      document.getElementById('findingRetestResultInput').value = finding.retest_result || 'not_tested';
      document.getElementById('findingRetestNotesInput').value = finding.retest_notes || '';
    } else {
      retestSection.style.display = 'none';
    }

    currentCvssMetrics = (finding && parseCvssVector(finding.cvss_vector)) || Object.assign({}, CVSS_DEFAULT_METRICS);
    renderCvssCalculator();

    document.getElementById('findingModalOverlay').classList.add('open');
    setTimeout(()=> document.getElementById('findingTitleInput').focus(), 50);
  }
  function closeFindingModal(){
    document.getElementById('findingModalOverlay').classList.remove('open');
  }

  function submitFindingForm(){
    const title = document.getElementById('findingTitleInput').value.trim();
    if(!title){ showToast(t('findingTitleRequired')); return; }
    const cvssResult = computeCvss(currentCvssMetrics);
    const payload = {
      title,
      test_id: document.getElementById('findingTestIdInput').value.trim() || null,
      endpoint: document.getElementById('findingEndpointInput').value.trim(),
      parameter: document.getElementById('findingParameterInput').value.trim(),
      cwe: document.getElementById('findingCweInput').value.trim(),
      owasp_category: document.getElementById('findingOwaspCatInput').value.trim(),
      description: document.getElementById('findingDescInput').value.trim(),
      impact: document.getElementById('findingImpactInput').value.trim(),
      remediation: document.getElementById('findingRemediationInput').value.trim(),
      references: document.getElementById('findingReferencesInput').value.trim(),
      status: document.getElementById('findingStatusInput').value,
      assigned_to: document.getElementById('findingAssignedInput').value.trim(),
      cvss_score: cvssResult.base_score > 0 ? cvssResult.base_score : null,
      cvss_vector: cvssResult.base_score > 0 ? cvssResult.vector : null,
    };
    if(editingFindingId){
      payload.retest_result = document.getElementById('findingRetestResultInput').value;
      payload.retest_notes = document.getElementById('findingRetestNotesInput').value.trim();
    }

    const req = editingFindingId
      ? apiRequest(`/projects/${currentProjectId}/findings/${editingFindingId}`, { method: 'PUT', body: JSON.stringify(payload) })
      : apiRequest(`/projects/${currentProjectId}/findings`, { method: 'POST', body: JSON.stringify(payload) });

    req.then(()=>{
      showToast(t('findingSaved'));
      closeFindingModal();
      renderPwFindings();
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  function deleteFindingUI(id){
    if(!confirm(t('findingDeleteConfirm'))) return;
    apiRequest(`/projects/${currentProjectId}/findings/${id}`, { method: 'DELETE' })
      .then(()=>{ showToast(t('findingDeleted')); renderPwFindings(); })
      .catch(err => showToast(err.message || t('resultSaveError')));
  }

  function renderPwFindings(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;

    Promise.all([
      apiRequest(`/projects/${currentProjectId}/findings`),
      apiRequest(`/sessions?project_id=${currentProjectId}`),
      apiRequest(`/projects/${currentProjectId}/lifecycle`)
    ]).then(([proFindings, sessions, lifecycle])=>{
      const statusOrder = ['open','retesting','fixed','resolved','wont_fix','accepted_risk'];
      const summaryHtml = `
        <div class="lifecycle-summary">
          <div class="lifecycle-rate">
            <div class="lifecycle-rate-value">${lifecycle.remediation_rate}%</div>
            <div class="lifecycle-rate-label">${t('lifecycleRemediationRate')}</div>
          </div>
          <div class="lifecycle-status-chips">
            ${statusOrder.map(s => `<span class="lifecycle-chip status-${s}">${t(FINDING_STATUS_LABELS[s])}: ${lifecycle.status_counts[s] || 0}</span>`).join('')}
          </div>
        </div>`;

      // --- Professional Findings ---
      const proHeaderHtml = `
        <div class="filter-bar" style="padding:14px 0 10px">
          <h5 style="margin:0">${t('pwFindingsProLabel')}</h5>
          <button type="button" class="btn btn-primary btn-sm" id="newFindingBtn">${t('newFindingBtn')}</button>
        </div>`;
      const proListHtml = proFindings.length ? proFindings.map(f => `
        <div class="finding-card" data-id="${f.id}">
          <div class="finding-card-top">
            <span class="finding-code">${f.finding_code}</span>
            <span class="severity-badge sev-${f.severity}">${t('severity_'+f.severity)}</span>
            ${f.cvss_score !== null && f.cvss_score !== undefined ? `<span class="cvss-mini-badge">CVSS ${f.cvss_score.toFixed(1)}</span>` : ''}
            <span class="finding-status-badge status-${f.status}">${t('findingStatus_'+f.status)}</span>
          </div>
          <div class="finding-card-title">${escapeHtml(f.title)}</div>
          <div class="finding-card-meta">
            ${f.test_id ? `<span>🔗 ${escapeHtml(f.test_id)}</span>` : ''}
            ${f.endpoint ? `<span>🌐 ${escapeHtml(f.endpoint)}</span>` : ''}
            ${f.assigned_to ? `<span>👤 ${escapeHtml(f.assigned_to)}</span>` : ''}
          </div>
          <div class="project-card-actions">
            <button data-action="edit" data-id="${f.id}">${t('editBtn')}</button>
            <button data-action="delete" data-id="${f.id}" class="danger">🗑️</button>
          </div>
        </div>`).join('') : `<div class="search-empty">${t('pwFindingsProEmpty')}</div>`;

      // --- Quick Findings (checklist text notes) ---
      let quickHtml = '';
      if(sessions.length){
        const sessionId = sessions[0].id;
        apiRequest(`/sessions/${sessionId}/results`).then(results => {
          const withFindings = results.filter(r => r.finding && r.finding.trim());
          const quickListEl = document.getElementById('pwQuickFindingsList');
          if(!quickListEl) return;
          if(!withFindings.length){
            quickListEl.innerHTML = `<div class="search-empty">${t('pwFindingsEmpty')}</div>`;
            return;
          }
          quickListEl.innerHTML = withFindings.map(r => {
            const meta = testInfoById(r.test_id);
            const fs = r.finding_status || 'open';
            return `<div class="import-preview-item">
              <div class="import-preview-body">
                <div class="import-preview-top">
                  <span class="import-preview-title">${escapeHtml(r.test_id)}${meta ? ' — ' + escapeHtml(meta.title) : ''}</span>
                  <span class="severity-badge sev-${r.severity || 'info'}">${t('severity_'+(r.severity || 'info'))}</span>
                  <select class="lifecycle-status-select status-${fs}" data-test="${r.test_id}">
                    ${statusOrder.map(s => `<option value="${s}" ${s===fs?'selected':''}>${t(FINDING_STATUS_LABELS[s])}</option>`).join('')}
                  </select>
                </div>
                <div class="import-preview-detail">${escapeHtml(r.finding)}</div>
                <button type="button" class="planner-goto-btn" data-promote-test="${r.test_id}" data-promote-severity="${r.severity||'info'}" data-promote-desc="${escapeHtml(r.finding)}" style="margin-top:8px">${t('promoteFindingBtn')}</button>
              </div>
            </div>`;
          }).join('');

          quickListEl.querySelectorAll('.lifecycle-status-select').forEach(sel => {
            sel.addEventListener('change', ()=>{
              apiRequest(`/sessions/${sessionId}/results/${sel.dataset.test}`, {
                method: 'PUT', body: JSON.stringify({ finding_status: sel.value })
              }).then(()=>{ showToast(t('lifecycleStatusUpdated')); renderPwFindings(); })
                .catch(err => showToast(err.message || t('resultSaveError')));
            });
          });
          quickListEl.querySelectorAll('[data-promote-test]').forEach(btn => {
            btn.addEventListener('click', ()=>{
              openFindingModal(null, {
                title: btn.dataset.promoteTest,
                test_id: btn.dataset.promoteTest,
                description: btn.dataset.promoteDesc,
              });
            });
          });
        }).catch(()=>{});
      }

      content.innerHTML = summaryHtml + proHeaderHtml + `<div id="pwProFindingsList">${proListHtml}</div>` +
        `<div class="filter-bar" style="padding:20px 0 10px"><h5 style="margin:0">${t('pwFindingsQuickLabel')}</h5></div>` +
        (sessions.length ? `<div id="pwQuickFindingsList"><div class="search-empty">${t('loadingSessions')}</div></div>`
                          : `<div class="search-empty">${t('pwFindingsNoSession')}</div>`);

      document.getElementById('newFindingBtn').addEventListener('click', ()=> openFindingModal(null, null));
      document.getElementById('pwProFindingsList').addEventListener('click', e=>{
        const btn = e.target.closest('button[data-action]');
        if(!btn) return;
        if(btn.dataset.action === 'edit'){
          const f = proFindings.find(x => String(x.id) === btn.dataset.id);
          if(f) openFindingModal(f, null);
        }
        if(btn.dataset.action === 'delete') deleteFindingUI(btn.dataset.id);
      });
    }).catch(err => {
      content.innerHTML = `<div class="search-empty">${escapeHtml(String(err.message||err))}</div>`;
    });
  }

  function renderPwTimeline(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest(`/projects/${currentProjectId}/timeline`).then(events => {
      if(!events.length){
        content.innerHTML = `<div class="search-empty">${t('pwTimelineEmpty')}</div>`;
        return;
      }
      content.innerHTML = events.map(e => `
        <div class="pw-tl-item">
          <div class="pw-tl-time">${new Date(e.created_at).toLocaleString(t('dateLocale'))}</div>
          <div>${t('pwEventType_'+e.event_type) || e.event_type} — ${escapeHtml(e.message)}</div>
        </div>`).join('');
    });
  }

  function renderPwReports(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest(`/sessions?project_id=${currentProjectId}`).then(sessions => {
      const proReportsHtml = `
        <div class="pro-reports-section">
          <h5>${t('pwProReportsLabel')}</h5>
          <p class="import-preview-source" style="margin-bottom:14px">${t('pwProReportsDesc')}</p>
          <div class="pro-report-cards">
            <a class="pro-report-card" href="${API_BASE}/projects/${currentProjectId}/reports/technical" target="_blank">
              <div class="pro-report-icon">📋</div>
              <div class="pro-report-name">${t('pwReportTypeTechnical')}</div>
              <div class="pro-report-desc">${t('pwReportTypeTechnicalDesc')}</div>
            </a>
            <a class="pro-report-card" href="${API_BASE}/projects/${currentProjectId}/reports/executive" target="_blank">
              <div class="pro-report-icon">📊</div>
              <div class="pro-report-name">${t('pwReportTypeExecutive')}</div>
              <div class="pro-report-desc">${t('pwReportTypeExecutiveDesc')}</div>
            </a>
            <a class="pro-report-card" href="${API_BASE}/projects/${currentProjectId}/reports/developer" target="_blank">
              <div class="pro-report-icon">🛠️</div>
              <div class="pro-report-name">${t('pwReportTypeDeveloper')}</div>
              <div class="pro-report-desc">${t('pwReportTypeDeveloperDesc')}</div>
            </a>
          </div>
        </div>`;

      if(!sessions.length){
        content.innerHTML = proReportsHtml + `<div class="search-empty">${t('pwReportsNoSession')}</div>`;
        return;
      }
      content.innerHTML = proReportsHtml +
        `<h5 style="margin-top:24px">${t('pwReportsSessionExportLabel')}</h5>` +
        sessions.map(s => `
        <div class="session-card" data-id="${s.id}">
          <div class="session-card-top">
            <div>
              <div class="session-card-name">${escapeHtml(s.name)}</div>
              <div class="session-card-meta">
                <span>👤 ${escapeHtml(s.tester_name || '—')}</span>
                <span>📅 ${new Date(s.created_at).toLocaleString(t('dateLocale'))}</span>
              </div>
            </div>
            <span class="session-status-pill ${s.status === 'completed' ? 'completed' : 'active'}">${s.status === 'completed' ? t('statusCompleted') : t('statusActive')}</span>
          </div>
          <div class="project-card-actions">
            <button data-action="report" data-id="${s.id}">${t('pwReportsOpenBtn')}</button>
          </div>
        </div>`).join('');
      content.querySelectorAll('button[data-action="report"]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          openSessionById(btn.dataset.id).then(()=>{
            closeProjectWorkspace();
            exportReport();
          });
        });
      });
    });
  }

  function renderPwEvidence(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `
      <div class="evidence-upload-row">
        <label class="evidence-upload-btn" for="evidenceFileInput">📎 ${t('pwEvidenceUploadLabel')}</label>
        <input type="file" id="evidenceFileInput" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none">
        <button type="button" class="evidence-upload-btn" id="toggleHttpEvidenceBtn">🌐 ${t('pwEvidenceAddHttpLabel')}</button>
        <span class="import-status" id="evidenceUploadStatus"></span>
      </div>
      <div id="httpEvidenceForm" class="http-evidence-form" style="display:none">
        <label>${t('pwEvidenceHttpLabelField')}</label>
        <input type="text" id="httpEvidenceLabelInput" placeholder="Login IDOR test">
        <div class="finding-form-row">
          <div>
            <label>${t('pwEvidenceHttpRequestLabel')}</label>
            <textarea id="httpEvidenceRequestInput" rows="8" placeholder="GET /api/users/42 HTTP/1.1&#10;Host: example.com&#10;Authorization: Bearer ..."></textarea>
          </div>
          <div>
            <label>${t('pwEvidenceHttpResponseLabel')}</label>
            <textarea id="httpEvidenceResponseInput" rows="8" placeholder="HTTP/1.1 200 OK&#10;&#10;{...}"></textarea>
          </div>
        </div>
        <p class="import-preview-source">${t('pwEvidenceRedactionNote')}</p>
        <div class="hero-actions" style="margin-top:8px">
          <button type="button" class="btn btn-primary" id="saveHttpEvidenceBtn">${t('saveBtn')}</button>
        </div>
      </div>
      <div id="evidenceGallery" class="evidence-gallery"><div class="search-empty">${t('loadingSessions')}</div></div>`;

    document.getElementById('evidenceFileInput').addEventListener('change', (e)=>{
      const file = e.target.files[0];
      if(!file) return;
      const statusEl = document.getElementById('evidenceUploadStatus');
      statusEl.textContent = t('pwEvidenceUploading');
      statusEl.classList.remove('error');
      const formData = new FormData();
      formData.append('file', file);
      fetch(`${API_BASE}/projects/${currentProjectId}/evidence`, { method: 'POST', body: formData })
        .then(async res => {
          if(!res.ok){ const j = await res.json().catch(()=>({})); throw new Error(j.error || res.statusText); }
          return res.json();
        })
        .then(()=>{
          statusEl.textContent = '';
          e.target.value = '';
          loadEvidenceGallery();
        })
        .catch(err => {
          statusEl.textContent = t('pwEvidenceUploadError') + ': ' + (err.message || err);
          statusEl.classList.add('error');
        });
    });

    document.getElementById('toggleHttpEvidenceBtn').addEventListener('click', ()=>{
      const form = document.getElementById('httpEvidenceForm');
      form.style.display = form.style.display === 'none' ? '' : 'none';
    });
    document.getElementById('saveHttpEvidenceBtn').addEventListener('click', ()=>{
      const statusEl = document.getElementById('evidenceUploadStatus');
      const httpRequest = document.getElementById('httpEvidenceRequestInput').value.trim();
      const httpResponse = document.getElementById('httpEvidenceResponseInput').value.trim();
      if(!httpRequest && !httpResponse){ statusEl.textContent = t('pwEvidenceHttpRequired'); statusEl.classList.add('error'); return; }
      statusEl.classList.remove('error');
      apiRequest(`/projects/${currentProjectId}/evidence/http`, {
        method: 'POST',
        body: JSON.stringify({
          label: document.getElementById('httpEvidenceLabelInput').value.trim() || undefined,
          http_request: httpRequest, http_response: httpResponse
        })
      }).then(()=>{
        document.getElementById('httpEvidenceLabelInput').value = '';
        document.getElementById('httpEvidenceRequestInput').value = '';
        document.getElementById('httpEvidenceResponseInput').value = '';
        document.getElementById('httpEvidenceForm').style.display = 'none';
        loadEvidenceGallery();
      }).catch(err => { statusEl.textContent = err.message || t('pwEvidenceUploadError'); statusEl.classList.add('error'); });
    });

    loadEvidenceGallery();
  }

  function loadEvidenceGallery(){
    const gallery = document.getElementById('evidenceGallery');
    Promise.all([
      apiRequest(`/projects/${currentProjectId}/evidence`),
      apiRequest(`/projects/${currentProjectId}/findings`)
    ]).then(([items, findings])=>{
      if(!items.length){
        gallery.innerHTML = `<div class="search-empty">${t('pwEvidenceEmpty')}</div>`;
        return;
      }
      const findingOptions = findings.map(f => `<option value="${f.id}">${f.finding_code} — ${escapeHtml(f.title)}</option>`).join('');
      gallery.innerHTML = items.map(ev => {
        const statusClass = ev.review_status;
        const statusLabel = { pending: t('pwEvidenceReviewPending'), accepted: t('pwEvidenceReviewAccepted'), rejected: t('pwEvidenceReviewRejected'), manual: t('pwEvidenceReviewAccepted') }[ev.review_status] || ev.review_status;

        const linkFooter = `
            ${ev.linked_test_id ? `<div class="evidence-linked">🔗 ${t('pwEvidenceLinkedTo')}: ${escapeHtml(ev.linked_test_id)}</div>` : ''}
            <label class="evidence-finding-link-label">${t('pwEvidenceLinkFindingLabel')}</label>
            <select class="evidence-finding-select" data-id="${ev.id}">
              <option value="">${t('pwEvidenceLinkFindingNone')}</option>
              ${findingOptions}
            </select>
            <div class="evidence-actions">
              <button class="evidence-delete-btn" data-id="${ev.id}">🗑️ ${t('pwEvidenceDelete')}</button>
            </div>`;

        if(ev.evidence_type === 'http_transaction'){
          return `
          <div class="evidence-card http-evidence-card" data-id="${ev.id}">
            <div class="evidence-body">
              <div class="evidence-top">
                <span class="evidence-filename">🌐 ${escapeHtml(ev.filename)}</span>
                <span class="evidence-status-badge status-${statusClass}">${statusLabel}</span>
              </div>
              ${ev.http_request_redacted ? `<div class="http-evidence-label">${t('pwEvidenceHttpRequestLabel')}</div><pre class="tool-output">${escapeHtml(ev.http_request_redacted)}</pre>` : ''}
              ${ev.http_response_redacted ? `<div class="http-evidence-label">${t('pwEvidenceHttpResponseLabel')}</div><pre class="tool-output">${escapeHtml(ev.http_response_redacted)}</pre>` : ''}
              <button type="button" class="evidence-suggest-chip show-raw-btn" data-id="${ev.id}">${t('pwEvidenceShowRaw')}</button>
              <div class="raw-http-box" id="rawHttpBox-${ev.id}" style="display:none"></div>
              ${linkFooter}
            </div>
          </div>`;
        }

        let aiBlock;
        if(ev.ai_analysis){
          aiBlock = `
            <div class="evidence-ai-analysis">${escapeHtml(ev.ai_analysis)}</div>
            <div class="evidence-ai-meta">${t('pwEvidenceAiConfidence')}: ${Math.round(ev.ai_confidence||0)}%</div>
            ${ev.ai_suggested_test_ids.length ? `
              <div class="evidence-suggested-label">${t('pwEvidenceSuggested')}:</div>
              <div class="evidence-suggested-chips">
                ${ev.ai_suggested_test_ids.map(tid => `<button class="evidence-suggest-chip" data-evidence="${ev.id}" data-test="${tid}">${escapeHtml(tid)} ✓</button>`).join('')}
              </div>` : ''}`;
        } else if(ev.ai_error){
          aiBlock = `<div class="evidence-ai-off">⚠️ ${t('pwEvidenceAiError')}: ${escapeHtml(ev.ai_error)}</div>`;
        } else {
          aiBlock = `<div class="evidence-ai-off">${t('pwEvidenceAiOff')}</div>`;
        }
        return `
        <div class="evidence-card" data-id="${ev.id}">
          <img class="evidence-thumb" src="${API_BASE}/evidence/${ev.id}/file" alt="${escapeHtml(ev.filename)}">
          <div class="evidence-body">
            <div class="evidence-top">
              <span class="evidence-filename">${escapeHtml(ev.filename)}</span>
              <span class="evidence-status-badge status-${statusClass}">${statusLabel}</span>
            </div>
            ${aiBlock}
            ${linkFooter}
          </div>
        </div>`;
      }).join('');

      gallery.querySelectorAll('.show-raw-btn').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          const box = document.getElementById('rawHttpBox-' + btn.dataset.id);
          if(box.style.display !== 'none'){ box.style.display = 'none'; return; }
          apiRequest(`/evidence/${btn.dataset.id}/raw`).then(raw => {
            box.style.display = '';
            box.innerHTML = `
              <div class="http-evidence-label">${t('pwEvidenceRawWarning')}</div>
              ${raw.http_request ? `<pre class="tool-output tool-output-err">${escapeHtml(raw.http_request)}</pre>` : ''}
              ${raw.http_response ? `<pre class="tool-output tool-output-err">${escapeHtml(raw.http_response)}</pre>` : ''}`;
          }).catch(err => showToast(err.message || t('resultSaveError')));
        });
      });

      gallery.querySelectorAll('.evidence-finding-select').forEach(sel => {
        const ev = items.find(x => String(x.id) === sel.dataset.id);
        if(ev && ev.linked_finding_id) sel.value = String(ev.linked_finding_id);
        sel.addEventListener('change', ()=>{
          apiRequest(`/evidence/${sel.dataset.id}`, {
            method: 'PUT',
            body: JSON.stringify({ linked_finding_id: sel.value ? parseInt(sel.value, 10) : null })
          }).then(()=> showToast(t('pwEvidenceLinkedToFinding'))).catch(err => showToast(err.message || t('resultSaveError')));
        });
      });
      gallery.querySelectorAll('.evidence-suggest-chip').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          apiRequest(`/evidence/${btn.dataset.evidence}`, {
            method: 'PUT',
            body: JSON.stringify({ review_status: 'accepted', linked_test_id: btn.dataset.test })
          }).then(loadEvidenceGallery).catch(err => showToast(err.message || t('resultSaveError')));
        });
      });
      gallery.querySelectorAll('.evidence-delete-btn').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          if(!confirm(t('pwEvidenceDeleteConfirm'))) return;
          apiRequest(`/evidence/${btn.dataset.id}`, { method: 'DELETE' })
            .then(loadEvidenceGallery).catch(err => showToast(err.message || t('resultSaveError')));
        });
      });
    }).catch(err => {
      gallery.innerHTML = `<div class="search-empty">${escapeHtml(String(err.message||err))}</div>`;
    });
  }

  function renderPwChains(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest(`/projects/${currentProjectId}/attack-chains`).then(data => {
      const chains = data.chains || [];
      if(!chains.length){
        content.innerHTML = `<p class="import-preview-source" style="margin-bottom:14px">${t('pwChainsDesc')}</p><div class="search-empty">${t('pwChainsEmpty')}</div>`;
        return;
      }
      content.innerHTML = `<p class="import-preview-source" style="margin-bottom:16px">${t('pwChainsDesc')}</p>` +
        chains.map(c => `
        <div class="chain-card">
          <div class="chain-card-top">
            <span class="chain-card-name">${escapeHtml(c.name)}</span>
            <span class="chain-risk-badge">${t('pwChainsRiskScore')}: ${c.risk_score}</span>
          </div>
          <div class="chain-completeness-track"><div class="chain-completeness-fill" style="width:${c.completeness_pct}%"></div></div>
          <div class="import-preview-source" style="margin:4px 0 12px">${t('pwChainsCompleteness')(c.completeness_pct)}</div>
          <div class="chain-flow">
            ${c.steps.map((s, i) => `
              ${i > 0 ? `<span class="chain-arrow">→</span>` : ''}
              <div class="chain-step ${s.matched ? 'matched' : 'missing'}">
                <div class="chain-step-label">${escapeHtml(s.label)}</div>
                ${s.matched
                  ? `<div class="chain-step-test">${escapeHtml(s.matched_test_id)} <span class="severity-badge sev-${s.severity||'info'}">${t('severity_'+(s.severity||'info'))}</span></div>`
                  : `<div class="chain-step-test muted">${t('pwChainsStepMissing')}</div>`}
              </div>`).join('')}
          </div>
        </div>`).join('');
    }).catch(err => {
      content.innerHTML = `<div class="search-empty">${escapeHtml(String(err.message||err))}</div>`;
    });
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

    document.getElementById('reconNavBtn').addEventListener('click', openReconModal);
    document.getElementById('closeReconOverlay').addEventListener('click', closeReconModal);
    document.getElementById('reconOverlay').addEventListener('click', e=>{
      if(e.target.id === 'reconOverlay') closeReconModal();
    });
    document.getElementById('reconRunBtn').addEventListener('click', runRecon);
    document.getElementById('reconApplyBtn').addEventListener('click', applyReconPriorities);

    document.getElementById('plannerNavBtn').addEventListener('click', openPlannerModal);
    document.getElementById('closePlannerOverlay').addEventListener('click', closePlannerModal);
    document.getElementById('plannerOverlay').addEventListener('click', e=>{
      if(e.target.id === 'plannerOverlay') closePlannerModal();
    });
    document.getElementById('plannerList').addEventListener('click', e=>{
      const btn = e.target.closest('.planner-goto-btn');
      if(!btn) return;
      closePlannerModal();
      openCategory(btn.dataset.cat, btn.dataset.test);
    });

    document.getElementById('projectsNavBtn').addEventListener('click', openProjectsModal);
    document.getElementById('closeProjectsOverlay').addEventListener('click', closeProjectsModal);
    document.getElementById('projectsOverlay').addEventListener('click', e=>{
      if(e.target.id === 'projectsOverlay') closeProjectsModal();
    });
    document.getElementById('newProjectBtn').addEventListener('click', ()=> openNewProjectModal(null));
    document.getElementById('closeNewProjectOverlay').addEventListener('click', closeNewProjectModal);
    document.getElementById('newProjectOverlay').addEventListener('click', e=>{
      if(e.target.id === 'newProjectOverlay') closeNewProjectModal();
    });
    document.getElementById('submitProjectBtn').addEventListener('click', submitProjectForm);
    document.getElementById('projectListBody').addEventListener('click', e=>{
      const btn = e.target.closest('button[data-action]');
      if(!btn) return;
      const id = btn.dataset.id;
      if(btn.dataset.action === 'open') openProjectWorkspace(id);
      if(btn.dataset.action === 'delete') deleteProjectUI(id);
      if(btn.dataset.action === 'edit') apiRequest(`/projects/${id}`).then(openNewProjectModal).catch(err => showToast(err.message || t('resultSaveError')));
    });
    document.getElementById('closeProjectWorkspace').addEventListener('click', closeProjectWorkspace);
    document.getElementById('projectWorkspaceOverlay').addEventListener('click', e=>{
      if(e.target.id === 'projectWorkspaceOverlay') closeProjectWorkspace();
    });
    document.getElementById('pwEditBtn').addEventListener('click', ()=> currentProjectObj && openNewProjectModal(currentProjectObj));

    document.getElementById('closeFindingModal').addEventListener('click', closeFindingModal);
    document.getElementById('findingModalOverlay').addEventListener('click', e=>{
      if(e.target.id === 'findingModalOverlay') closeFindingModal();
    });
    document.getElementById('submitFindingBtn').addEventListener('click', submitFindingForm);
    document.getElementById('pwTabs').addEventListener('click', e=>{
      const btn = e.target.closest('.pw-tab');
      if(!btn) return;
      switchPwTab(btn.dataset.tab);
    });
    document.getElementById('projectChip').addEventListener('click', ()=>{
      if(currentProjectId) openProjectWorkspace(currentProjectId);
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
        closeCategory(); closeThemeModal(); closeNewSessionOverlay(); closeTop10Detail(); closeImportModal(); closeReconModal(); closePlannerModal();
        closeProjectsModal(); closeNewProjectModal(); closeProjectWorkspace(); closeFindingModal();
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
    document.getElementById('frameworkSelect').addEventListener('change', e=>{
      switchFramework(e.target.value);
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
    const files = FRAMEWORK_DATA_FILES[currentFramework] || FRAMEWORK_DATA_FILES.wstg;
    return fetch(files[currentLang] || files.tr)
      .then(r => r.json())
      .then(data => { DATA = data; })
      .catch(err => {
        document.getElementById('categoriesGrid').innerHTML =
          `<div class="search-empty">${t('dataLoadError')}<br><small>${err}</small></div>`;
        console.error(err);
      });
  }

  function switchFramework(framework){
    if(!FRAMEWORK_DATA_FILES[framework] || framework === currentFramework) return;
    currentFramework = framework;
    saveFramework(currentFramework);
    customTests = []; // farklı framework'e geçerken proje bazlı özel testler bu oturumda tekrar açılana kadar temizlenir
    closeCategory();
    loadData().then(()=>{
      renderSidebar();
      renderDashboard();
      updateSessionUI();
      if(currentProjectId) return apiRequest(`/projects/${currentProjectId}/custom-tests`).then(items=>{
        customTests = items || [];
        renderSidebar(); renderDashboard();
      }).catch(()=>{});
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
