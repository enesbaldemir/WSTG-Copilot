(function(){
  "use strict";

  const STORAGE_KEY = "wstg_progress_v1";
  const FINDINGS_KEY = "wstg_findings_v1";
  const LANG_KEY = "wstg_lang_v1";
  const THEME_KEY = "wstg_theme_v1";
  const SESSION_ID_KEY = "wstg_session_id_v1";
  const SKIP_SESSION_KEY = "wstg_skip_session_v1";
  const RECON_PRIORITY_KEY = "wstg_recon_priority_v1";
  const RECON_CACHE_KEY = "wstg_recon_cache_v1";
  // Sayfanın açıldığı host'a göre (127.0.0.1:8000 -> 127.0.0.1:5000); oturum
  // çerezi SameSite=Strict olduğundan API aynı host'ta olmalı (bkz. js/auth.js).
  const API_BASE = window.WSTGAuth.apiBaseFor(window.location);

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

  const THEME_MODES = ['light', 'dark', 'system'];

  const I18N = {
    tr: {
      navWorkspace: "Çalışma Alanı",
      navDashboard: "Dashboard",
      navCategories: "WSTG Kategorileri",
      exportReport: "Raporu Dışa Aktar",
      resetProgress: "İlerlemeyi Sıfırla",
      langLabel: "Dil",
      frameworkLabel: "Checklist",
      frameworkWstg: "OWASP WSTG (Web)",
      frameworkLlm: "OWASP LLM Top 10 (AI Güvenliği)",
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
      sortByPriorityBtn: "Önceliğe Göre Sırala",
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
      exportProHint: "İpucu: AI destekli PDF/HTML profesyonel rapor (bulgu seçimi, yönetici özeti) için bir Proje açıp 'Raporlar' sekmesini kullanın.",
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
      dbOnline: "Veritabanı bağlı",
      dbOffline: "Veritabanı yok — backend/app.py çalıştırın (yerel modda devam edilecek)",
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

      navNotebook: "Not Defteri",
      navStudyMetrics: "Çalışma Metrikleri",
      notebookTitle: "Not Defteri",
      notebookDesc: (name) => `“${name}” oturumunun notları. Bir test maddesine bağlayabilir ya da genel not olarak bırakabilirsin.`,
      notebookNeedSession: "Not defteri için önce bir test oturumu aç.",
      notebookNeedBackend: "Not defteri backend bağlantısı gerektirir.",
      notebookSearchPlaceholder: "Notlarda ara…",
      notebookFilterAll: "Tüm notlar",
      notebookFilterGeneral: "Genel notlar",
      newNote: "+ Yeni Not",
      editNote: "Notu düzenle",
      noteEditorDesc: "Gözlemini kısa ve net yaz; istersen ekran görüntüsü ekle (yapıştırma da çalışır).",
      noteTitleLabel: "Başlık",
      noteTitlePlaceholder: "Örn: Login formunda SQL injection",
      noteUntitled: "Başlıksız not",
      noteLinkedTestLabel: "İlgili test maddesi (opsiyonel)",
      noteGeneralOption: "— Genel not (teste bağlı değil) —",
      noteGeneralBadge: "Genel",
      noteFpLabel: "Doğrulama",
      noteFpUnknown: "Değerlendirilmedi",
      noteFpValid: "Geçerli bulgu",
      noteFpFalse: "False positive",
      noteContentLabel: "Not / bulgu",
      noteAddImage: "Görsel ekle",
      noteImageHint: (n, max) => `${n}/${max} görsel · PNG, JPEG, GIF, WebP · en fazla 3 MB`,
      noteImageTypeError: "Yalnızca PNG, JPEG, GIF veya WebP eklenebilir.",
      noteImageSizeError: "Görsel 3 MB'tan büyük olamaz.",
      noteImageCountError: (max) => `En fazla ${max} görsel eklenebilir.`,
      noteImagePayloadError: "Görsellerin toplam boyutu çok büyük; birkaçını kaldır.",
      noteImageReadError: "Görsel okunamadı.",
      noteImageRemove: "Görseli kaldır",
      noteUnsafeImagesDropped: (n) => `${n} eski görsel güvenli biçimde olmadığı için gösterilmiyor; kaydedersen kaldırılır.`,
      noteCweNameLabel: "CWE adı",
      noteCweSuggested: (id) => `${id} için önerilen CWE'ler:`,
      noteCvssLabel: "CVSS 3.1 vektörü (opsiyonel)",
      noteCvssInvalid: "Geçersiz vektör",
      noteAiAnalyze: "AI ile analiz et",
      noteAiRationale: "Değerlendirme",
      noteAiFp: "False positive olasılığı",
      noteAiSuggestCwe: "Önerilen CWE",
      noteAiSuggestSeverity: "Önerilen önem",
      noteAiSuggestCvss: "Önerilen CVSS",
      noteAiApply: "Uygula",
      noteAiApplied: "Öneri forma uygulandı",
      noteAiNoSuggestion: "AI bir öneri döndürmedi.",
      fpLikelihood_low: "Düşük",
      fpLikelihood_medium: "Orta",
      fpLikelihood_high: "Yüksek",
      noteContentRequired: "Not içeriği veya en az bir görsel gerekli.",
      saveNote: "Kaydet",
      deleteNote: "Sil",
      noteSaved: "Not kaydedildi",
      noteDeleted: "Not silindi",
      noteDeleteConfirm: "Bu not silinsin mi?",
      noteEmptyList: "Henüz not yok. “+ Yeni Not” ile ekleyebilirsin.",
      noteEmptyFiltered: "Bu filtreye uyan not yok.",
      noteAddForTest: "Not ekle",
      noteCountForTest: (n) => `${n} not`,
      controlGroupBanner: "Bu oturum kontrol grubunda: AI özellikleri kapalı.",
      studyGroupLabel: "Çalışma Grubu (opsiyonel)",
      studyGroupNone: "— Seçilmedi —",
      studyGroupAi: "AI Destekli",
      studyGroupControl: "Kontrol (yalnızca checklist)",
      studyGroupHintAi: "AI özellikleri açık; bu oturumdaki AI çağrıları metriklere yazılır.",
      studyGroupHintControl: "Bu oturum açıkken AI düğmeleri gizlenir (yalnızca checklist).",
      studyGroupBadge_ai_assisted: "AI destekli",
      studyGroupBadge_control: "Kontrol",
      sessionCompleteBtn: "Tamamla",
      sessionReopenBtn: "Yeniden aç",
      sessionCompletedToast: "Oturum tamamlandı olarak işaretlendi",
      sessionReopenedToast: "Oturum yeniden açıldı",
      studyMetricsTitle: "Çalışma Metrikleri",
      studyMetricsDesc: "“AI destekli” ve “kontrol” grubuna atanmış oturumların ortalamaları. Değerler açıklayıcıdır; grup başına oturum sayısı (n) küçükse dikkatli yorumla.",
      studyMetricsColAi: "AI destekli",
      studyMetricsColControl: "Kontrol",
      studyMetricsColDiff: "Fark",
      studyMetricMinutes: "Tamamlama süresi (dk)",
      studyMetricCompletedTests: "Tamamlanan test",
      studyMetricCompletionPct: "Tamamlanma (%)",
      studyMetricFindings: "Bulgu sayısı",
      studyMetricFpRate: "False positive oranı (%)",
      studyMetricAiCalls: "AI çağrısı",
      studyMetricAiLatency: "Ort. AI yanıt süresi (ms)",
      studyMetricReportGenerated: "AI rapor taslağı üretilen oturum (%)",
      studyMetricsEmpty: "Henüz bir çalışma grubuna atanmış oturum yok. Yeni oturum oluştururken “Çalışma Grubu” seçebilirsin.",
      studyMetricsUnassigned: (n) => `${n} oturum bir gruba atanmadığı için hesaba katılmadı.`,
      studyMetricsDiffNote: "Fark = (AI − Kontrol) / Kontrol. Yeşil, o metrikte AI grubunun daha iyi olduğunu gösterir. Süre yalnızca “Tamamla” ile kapatılmış oturumlarda hesaplanır.",
      studyMetricsSessions: "Oturumlar",
      studyMetricsColSession: "Oturum",
      studyMetricsColGroup: "Grup",
      studyMetricsCopyCsv: "CSV olarak kopyala",
      loadingGeneric: "Yükleniyor…",
      studyMetricsLoadError: "Metrikler yüklenemedi.",
      studyMetricsNeedBackend: "Çalışma metrikleri backend bağlantısı gerektirir.",
      importModalTitle: "Bulgu İçe Aktar",
      importModalDesc: "Nmap, Nikto, WPScan, Burp Suite veya OWASP ZAP çıktısını yükleyin; eşleşen bulgular ilgili WSTG maddelerine not olarak eklenir. Burp/ZAP bulguları ayrıca projede profesyonel bulgu olarak oluşturulabilir.",
      importOptNotes: "Eşleşen checklist maddelerine not olarak ekle ve tamamlandı işaretle",
      importOptPro: (name) => `“${name}” projesinde profesyonel bulgu olarak oluştur (endpoint, CWE, çözüm önerisi dolu)`,
      importOptHttp: "HTTP istek/yanıtını bulguya kanıt olarak ekle (çerez, Authorization ve token'lar otomatik maskelenir)",
      importProNeedProject: "Profesyonel bulgu oluşturmak için önce üst çubuktan bir proje seçin.",
      importProDedupeHint: "Projede aynı başlık ve endpoint'e sahip bir bulgu varsa yeniden oluşturulmaz.",
      importNothingSelected: "Uygulanacak bir işlem seçilmedi.",
      importCreatingFindings: (i, n) => `Bulgular oluşturuluyor… ${i}/${n}`,
      importProResult: (created, skipped, failed) => `${created} bulgu oluşturuldu` + (skipped ? `, ${skipped} zaten vardı` : '') + (failed ? `, ${failed} oluşturulamadı` : ''),
      importHttpBadge: "HTTP",
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

      navRecon: "Saldırı Yüzeyi Keşfi",
      reconModalTitle: "Saldırı Yüzeyi Keşfi",
      reconModalDesc: "Bir hedef domain girin: subdomain, endpoint, teknoloji ve API yüzeyi pasif/hafif yöntemlerle çıkarılır ve otomatik olarak ilgili WSTG testleriyle ilişkilendirilir.",
      reconTargetLabel: "Hedef Domain",
      reconAuthLabel: "Bu hedefi test etmeye yetkili olduğumu onaylıyorum.",
      reconRunBtn: "Keşfet",
      reconRunning: "Keşif çalışıyor (crt.sh + hedefe tek istek + bilinen yol kontrolü)...",
      reconAuthRequired: "Devam etmek için yetkilendirme onay kutusunu işaretlemelisiniz.",
      reconTargetRequired: "Lütfen bir hedef domain girin.",
      reconError: "Keşif başarısız oldu",
      reconSubdomainsLabel: "Alt Alan Adları",
      reconTechLabel: "Teknolojiler",
      reconEndpointsLabel: "Endpoint'ler ve İlginç Yollar",
      reconSuggestionsLabel: "Önerilen Test Önceliği",
      reconApplyBtn: "Checklist'i Önceliklendir",
      reconNoSuggestions: "Önerilecek bir test önceliği bulunamadı.",
      reconAppliedToast: n => `${n} test maddesi önceliklendirildi`,
      reconBackendOffline: "Bu özellik backend gerektirir — lütfen backend/app.py'yi çalıştırın.",
      reconResetBtn: "Sıfırla / Yeniden Tara",
      reconResetConfirm: "Bu proje/oturum için kayıtlı tarama sonuçları ve öncelik verisi silinsin mi? Bu işlem geri alınamaz.",
      reconResetToast: "Tarama verisi sıfırlandı",
      reconCachedNotice: (target, when) => `Son tarama: <b>${target}</b>${when ? ' · ' + when : ''} — yeniden taramadan gösteriliyor.`,
      reconPriorityBadge_high: "Yüksek Öncelik",
      reconPriorityBadge_medium: "Orta Öncelik",
      reconPriorityBadge_low: "Düşük Öncelik",
      reconPriorityBadge_info: "Önerilen",

      navPlanner: "Test Planı",
      plannerModalTitle: "Test Planı",
      plannerModalDesc: "Saldırı Yüzeyi Keşfi'nden gelen önceliklendirilmiş maddeler; kanıt sayısı ve WSTG metodoloji sırasına göre şeffaf bir skorla sıralanır. Her önerinin yanında nedeni gösterilir.",
      plannerEmpty: "Henüz bir test planı yok. Önce Saldırı Yüzeyi Keşfi ile bir hedef tarayıp bulguları önceliklendirin.",
      plannerReasonLabel: "Neden",
      plannerGotoBtn: "Bu maddeye git",
      plannerScoreNote: "Skor: kanıt sayısı + öncelik seviyesi + WSTG metodoloji sırasına göre hesaplanır (sabit kurallar, model çağrısı yapılmaz).",

      navAiNextTest: "AI: Sırada Ne Var?",
      aiNextTestTitle: "AI: Sırada Ne Var?",
      aiNextTestDesc: "Şu ana kadar tamamladığınız testlere ve kaydettiğiniz bulgulara bakarak, AI bir sonraki mantıklı adımı gerekçesiyle birlikte önerir. Test Planı'ndan farkı: recon kanıtı gerekmez, sabit kural yerine AI akıl yürütmesi kullanır — bu yüzden her zaman bir öneri taslağıdır, kesin doğru kabul etmeyin.",
      aiNextTestAskBtn: "Öner",
      aiNextTestAllDone: "Tüm testler tamamlanmış görünüyor — önerecek bir şey yok!",
      aiNextTestNoSuggestion: "AI bir öneri üretemedi. Tekrar deneyin.",
      aiNextTestUngrounded: "AI'ın önerdiği test ID'si beklenmeyen bir değer — lütfen dikkatli değerlendirin.",
      aiNextTestAltsLabel: "Alternatif adaylar",

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

      pwTabOverview: "Genel Bakış", pwTabScope: "Kapsam", pwTabAssets: "Assets", pwTabRecon: "Keşif",
      pwTabTestPlan: "Test Planı", pwTabWstg: "WSTG Testleri", pwTabFindings: "Bulgular",
      pwTabRetest: "Yeniden Test",
      rtDesc: "Müşterinin düzelttiğini bildirdiği bulguları yeniden test edin: her biri için \"Düzeldi\" ya da \"Hâlâ açık\" işaretleyin, not ve kanıt ekleyin. Düzeldi → durum Kapatıldı; Hâlâ açık → bulgu yeniden Açık. Bir bulguyu yeniden teste almak için durumunu Düzeltildi / Yeniden Test Bekliyor yapın ya da \"Diğer açık\" listesinden ekleyin.",
      rtState_pending: "Yeniden test bekliyor",
      rtState_still_open: "Hâlâ açık",
      rtState_verified: "Düzeldi (doğrulandı)",
      rtFilter_pending: "Bekleyen",
      rtFilter_still_open: "Hâlâ açık",
      rtFilter_verified: "Doğrulandı",
      rtFilter_other: "Diğer açık",
      rtFilter_all: "Tümü",
      rtEmpty_pending: "Yeniden test bekleyen bulgu yok.",
      rtEmpty_still_open: "Yeniden testte açık kalan bulgu yok.",
      rtEmpty_verified: "Henüz doğrulanmış düzeltme yok.",
      rtEmpty_other: "Yeniden test kapsamı dışında açık bulgu yok.",
      rtEmpty_all: "Bu projede bulgu yok.",
      rtLastRetest: "Son yeniden test",
      rtResult_fixed: "düzeldi",
      rtResult_not_fixed: "hâlâ açık",
      rtNotePlaceholder: "Yeniden test notu (ör. payload artık 400 dönüyor)",
      rtMarkFixed: "✓ Düzeldi",
      rtMarkOpen: "✗ Hâlâ açık",
      rtAddEvidence: "Kanıt ekle",
      rtRequest: "Yeniden teste ekle",
      rtReportPdf: "Yeniden test raporu (PDF)",
      rtReportHtml: "Raporu aç (HTML)",
      rtIncludePending: "Bekleyenleri de rapora ekle",
      rtFileSuffix: "yeniden-test",
      rtToastFixed: "Düzeldi olarak işaretlendi; bulgu kapatıldı",
      rtToastOpen: "Hâlâ açık olarak işaretlendi; bulgu yeniden açıldı",
      rtToastRequested: "Bulgu yeniden teste eklendi",
      rtToastEvidence: "Kanıt bulguya eklendi",
      pwTabAuthz: "Yetki Matrisi",
      azDesc: "Her rolün her endpoint'e erişip erişmemesi gerektiğini (beklenen) ve kendi denemenizin sonucunu (gözlenen) işaretleyin. Beklenen \"Yasak\" iken \"Erişti\" olan hücreler yetkilendirme açığıdır (WSTG-ATHZ-02/03/04). Uygulama hedefe istek göndermez.",
      azEmptyTitle: "Henüz rol tanımlanmadı",
      azEmptyDesc: "Rolleri (ör. Anonim, Kullanıcı, Yönetici) sütun, endpoint'leri satır olarak ekleyin.",
      azDefaultRolesBtn: "Anonim / Kullanıcı / Yönetici ile başla",
      azEndpointCol: "Endpoint",
      azNoEndpoints: "Henüz endpoint yok. Yukarıdan ekleyin ya da Saldırı Yüzeyi'nden alın.",
      azNewRolePlaceholder: "Yeni rol adı",
      azAddRole: "+ Rol",
      azAddEndpoint: "+ Endpoint",
      azFromSurface: "Saldırı Yüzeyi'nden endpoint al",
      azCopyCsv: "CSV olarak kopyala",
      azCreateFindingsBtn: (n) => n ? `Uyumsuzluklardan bulgu oluştur (${n})` : "Bulgu oluşturulacak uyumsuzluk yok",
      azCreateOneFinding: "Bu uyumsuzluk için bulgu oluştur",
      azFindingsResult: (c, l, f) => `${c} bulgu oluşturuldu` + (l ? `, ${l} mevcut bulguya bağlandı` : '') + (f ? `, ${f} oluşturulamadı` : ''),
      azSumCells: (n) => `${n} hücre`,
      azSumTested: (n) => `${n} denendi`,
      azSumViolations: (n) => `${n} izinsiz erişim`,
      azSumOver: (n) => `${n} fazla kısıtlı`,
      azSumUntested: (n) => `${n} denenmedi`,
      azExpected: "Beklenen",
      azObserved: "Gözlenen",
      azExpAllow: "İzinli",
      azExpDeny: "Yasak",
      azObsAllowed: "Erişti",
      azObsDenied: "Engellendi",
      azObsNone: "Denenmedi",
      azObsNoneShort: "?",
      azStViolation: "İzinsiz erişim: bu rol erişmemesi gereken kaynağa erişebildi.",
      azStOver: "Fazla kısıtlı: bu rolün erişmesi gerekiyordu ama engellendi.",
      azStOk: "Beklenen davranış.",
      azStObserved: "Sonuç girildi; beklenen erişimi de işaretleyin.",
      azStUntested: "Henüz denenmedi.",
      azNote: "Not",
      azNotePlaceholder: "Ör. 200 OK, başka kullanıcının siparişi döndü",
      azNextCell: "Sonraki hücre →",
      azEditorHint: "Bir hücreye tıklayıp beklenen ve gözlenen erişimi işaretleyin. Rol ya da endpoint adına tıklayarak düzenleyebilirsiniz.",
      azRoleTitle: "Rol",
      azRoleNameLabel: "Rol adı",
      azEndpointTitle: "Endpoint",
      azMethod: "Metot",
      azPath: "Yol",
      azDelete: "Sil",
      azDeleteRoleConfirm: (n) => `"${n}" rolü ve bu sütundaki tüm sonuçlar silinsin mi?`,
      azDeleteEndpointConfirm: (n) => `${n} ve bu satırdaki tüm sonuçlar silinsin mi?`,
      azTooManyRoles: (n) => `En fazla ${n} rol eklenebilir.`,
      azRoleExists: "Bu adla bir rol zaten var.",
      azEndpointExists: "Bu metot ve yol zaten ekli (ya da yol boş).",
      azNoSurfaceEndpoints: "Saldırı Yüzeyi'nde kayıtlı endpoint yok. Önce Saldırı Yüzeyi Keşfi çalıştırın.",
      azSurfaceAdded: (a, s) => `${a} endpoint eklendi` + (s ? `, ${s} zaten vardı` : ''),
      azSaving: "Kaydediliyor…",
      azSaved: "Kaydedildi",
      azLastSaved: (d) => `Son kayıt: ${d}`,
      azLoadError: "Yetki matrisi yüklenemedi.",
      pwTabTimeline: "Zaman Çizelgesi", pwTabKanban: "Kanban", pwTabReports: "Raporlar",

      pwStatAssets: "Varlık", pwStatTests: "Test", pwStatCompleted: "Tamamlanan", pwStatFindings: "Bulgu",
      pwSeverityDistLabel: "Önem Dağılımı",
      pwOverviewLoadError: "Genel bakış yüklenemedi",
      pwCoverageLabel: "Test Çerçevesi Kapsamı",
      pwCoverage_wstg: "OWASP WSTG",
      pwCoverage_llm: "OWASP LLM Top 10",
      pwCoverage_custom: "Özel Testler",
      pwFindingsByCategoryLabel: "Kategoriye Göre Bulgular",
      pwTopEndpointsLabel: "En Çok Bulgu İçeren Endpoint'ler",
      pwEndpointFindingsSuffix: "bulgu",

      pwScopeInScope: "Kapsam İçi", pwScopeOutOfScope: "Kapsam Dışı",
      pwScopeValuePlaceholder: "*.example.com, api.example.com, 192.168.1.10 ...",
      pwScopeAddBtn: "Ekle", pwScopeEmpty: "Henüz kapsam kaydı yok.",
      pwScopeType_domain: "Alan adı", pwScopeType_subdomain: "Alt alan adı", pwScopeType_ip: "IP", pwScopeType_cidr: "CIDR",
      pwScopeValueRequired: "Değer zorunludur.",

      pwAssetsEmpty: "Henüz varlık yok — Keşif sekmesinden Saldırı Yüzeyi Keşfi çalıştırın.",
      pwAssetsSubdomains: "Alt Alan Adları", pwAssetsTechnologies: "Teknolojiler", pwAssetsEndpoints: "Endpoint'ler",
      pwAssetsViewList: "Liste",
      pwAssetsViewMap: "Harita",
      pwAssetsMapFindingsLabel: "İlişkili Bulgular",
      pwAssetsMapNoFindings: "Bu endpoint'e bağlı bir finding yok.",

      pwReconDesc: "Bu proje için Saldırı Yüzeyi Keşfi çalıştırın; sonuçlar otomatik olarak Saldırı Yüzeyi sekmesine ve Zaman Çizelgesi'ne işlenir.",
      pwReconOpenBtn: "Saldırı Yüzeyi Keşfi'ni Aç",

      pwTabTools: "Araçlar",
      pwToolsDesc: "Gerçek keşif araçlarını (nmap, httpx, whatweb, subfinder, dnsx) kendi makinenizde çalıştırın. Her çalıştırmadan önce tam komutu görür ve onaylarsınız.",
      pwToolsExcludedNote: "Not: nuclei ve ffuf bilerek dahil edilmedi — nuclei aktif zafiyet doğrulama şablonları içeriyor, ffuf agresif dizin fuzzing yapıyor. İkisi de ayrı, daha sıkı kapsamlı bir iterasyon gerektirir.",
      toolSelectLabel: "Araç",
      toolTargetLabel: "Hedef",
      toolNotInstalled: "Sisteminizde kurulu değil",
      toolPreviewLabel: "Çalıştırılacak komut:",
      toolAuthLabel: "Bu hedefi test etmeye yetkili olduğumu onaylıyorum.",
      toolPreviewBtn: "Komutu Önizle",
      toolRunBtn: "Onayla ve Çalıştır",
      toolRunning: "Çalışıyor... (bu birkaç dakika sürebilir)",
      toolRunError: "Araç çalıştırılamadı",
      toolTargetRequired: "Lütfen bir hedef girin.",
      toolAuthRequired: "Devam etmek için yetkilendirme onay kutusunu işaretlemelisiniz.",
      toolStatus_completed: "Tamamlandı",
      toolStatus_failed: "Başarısız",
      toolStatus_timeout: "Zaman Aşımı",
      toolHistoryLabel: "Geçmiş Çalıştırmalar",
      toolHistoryEmpty: "Henüz bir araç çalıştırılmadı.",
      toolExitCodeLabel: "Çıkış kodu",

      findingModalTitleNew: "Yeni Bulgu",
      findingModalTitleEdit: "Bulguyu Düzenle",
      findingModalDesc: "Profesyonel bulgu kaydı: CVSS v3.1, CWE, endpoint/parametre, remediation ve retest takibi.",
      findingTitleLabel: "Başlık *",
      findingTestIdLabel: "İlişkili WSTG/LLM Test ID (opsiyonel)",
      findingEndpointLabel: "Endpoint",
      findingParameterLabel: "Parametre",
      findingCweLabel: "CWE",
      findingOwaspCatLabel: "OWASP Kategorisi",
      findingDescLabel: "Açıklama",
      findingImpactLabel: "Etki",
      findingRemediationLabel: "Çözüm Önerisi",
      findingReferencesLabel: "Referanslar (her satıra bir URL)",
      findingStatusLabel: "Durum",
      findingAssignedLabel: "Atanan Kişi",
      findingRetestResultLabel: "Yeniden Test Sonucu",
      findingRetest_not_tested: "Henüz test edilmedi",
      findingRetest_fixed: "Düzeltildi ✓",
      findingRetest_not_fixed: "Düzeltilmedi ✗",
      findingRetestNotesLabel: "Yeniden Test Notları",
      findingCvssTitle: "CVSS v3.1 Hesaplayıcı",
      findingStatus_open: "Açık", findingStatus_confirmed: "Doğrulandı", findingStatus_fixed: "Düzeltildi",
      findingStatus_retest_pending: "Yeniden Test Bekliyor", findingStatus_resolved: "Kapatıldı",
      findingStatus_wont_fix: "Düzeltilmeyecek", findingStatus_accepted_risk: "Kabul Edilen Risk",
      findingTitleRequired: "Başlık zorunludur.",
      findingSaved: "Bulgu kaydedildi",

      aiAssistantTitle: "AI Asistanı",
      aiGenDescBtn: "Açıklama Oluştur",
      aiGenRemediationBtn: "Çözüm Önerisi Oluştur",
      aiRewriteBtn: "Daha Profesyonel Yap",
      aiFindSimilarBtn: "Benzer Bulguları Bul",
      aiSuggestCweBtn: "CWE/Önem Öner",
      aiWorking: "AI çalışıyor…",
      aiRequestTimeout: "AI yanıtı zaman aşımına uğradı (45 sn). İnternet bağlantınızı, kullandığınız API key'i ve sağlayıcının durumunu kontrol edip tekrar deneyin.",
      aiDone: "Tamamlandı",
      aiSaveFirst: "AI asistanını kullanmadan önce finding'i bir kez kaydedin.",
      aiNotConfigured: "AI sağlayıcısı yapılandırılmamış (.env dosyasını kontrol edin).",
      aiNoTextToRewrite: "Önce bir açıklama metni girin.",

      navAiSettings: "AI Ayarları",
      aiSettingsTitle: "AI Ayarları",
      aiSettingsDesc: "API key'lerinizi buradan ekleyin, düzenleyin, test edin ve hangi sağlayıcının aktif olacağını seçin. Key'ler şifreli saklanır ve hiçbir zaman tam olarak gösterilmez.",
      aiApiKeyLabel: "API Key",
      aiModelLabel: "Model",
      aiBaseUrlLabel: "Base URL",
      aiKeySavedPlaceholder: "Kayıtlı: {key} — değiştirmek için yeni bir key girin",
      aiKeyEmptyPlaceholder: "API key girin...",
      aiToggleVisibility: "Göster/Gizle",
      aiActiveLabel: "Aktif",
      aiTestBtn: "Test Et",
      aiActivateBtn: "Aktif Yap",
      aiDeleteBtn: "Sil",
      aiSettingsSaved: "AI ayarı kaydedildi",
      aiSettingsDeleted: "AI ayarı silindi",
      aiProviderActivated: "Sağlayıcı aktif edildi",
      aiDeleteConfirm: "Bu sağlayıcının kayıtlı key'ini silmek istediğinize emin misiniz?",
      aiTestSuccess: "Bağlantı başarılı",
      aiTestFailed: "Bağlantı başarısız",
      aiStatusWorkingWith: "ile çalışıyor",
      aiStatusNotConfigured: "AI yapılandırılmamış",

      byokTopbarLabel: "Kendi Key'im",
      byokTitle: "Kendi API Key'inle Kullan",
      byokDesc: "Buraya girdiğiniz key yalnızca bu tarayıcı sekmesinde tutulur; sunucuya hiçbir zaman kaydedilmez ve sekmeyi kapattığınızda otomatik olarak silinir. Aktif ettiğinizde tüm AI istekleriniz bu key ve modelle çalışır — paylaşılan/varsayılan AI Ayarları etkilenmez.",
      byokStatusOff: "Şu anda paylaşılan/varsayılan AI sağlayıcısı kullanılıyor.",
      byokStatusOn: "Bu oturumda aktif: {provider} {model}",
      byokProviderLabel: "Sağlayıcı",
      byokKeyLabel: "API Key",
      byokModelLabel: "Model (opsiyonel — boş bırakılırsa varsayılan kullanılır)",
      byokBaseUrlLabel: "Ollama Base URL",
      byokHint: "İpucu: Key'iniz tarayıcınızın oturum belleğinde (sessionStorage) tutulur; sayfayı yenilediğinizde kalır ama sekmeyi kapatınca kaybolur.",
      byokActivateBtn: "Bu Oturumda Aktif Et",
      byokClearBtn: "Devre Dışı Bırak",
      byokActivatedToast: "Kendi API key'iniz bu oturum için aktif edildi",
      byokClearedToast: "Kendi API key'iniz devre dışı bırakıldı, paylaşılan ayara dönüldü",
      byokMissingKey: "Lütfen bir API key girin",
      byokMissingProvider: "Lütfen bir sağlayıcı seçin",

      dupAlertTitle: "Olası Tekrarlanan Bulgu Tespit Edildi",
      dupAlertDesc: "Bu bulguya benzer, projede zaten kayıtlı bulgular var.",
      dupMergeBtn: "Seçilenleri Birleştir",
      dupCreateAnywayBtn: "Yine de Oluştur",
      dupSelectAtLeastTwo: "Birleştirmek için en az 2 bulgu seçin.",
      dupMergeSuccess: "Bulgular birleştirildi",
      dupNoneFound: "Benzer bir bulgu bulunamadı.",
      dupReasonSimilarTitle: "benzer başlık",
      dupReasonSimilarDescription: "benzer açıklama",
      dupReasonSameEndpoint: "aynı endpoint",
      dupReasonSameCwe: "aynı CWE",
      dupReasonSameTestId: "aynı test ID",
      dupReasonSameRootCause: "muhtemelen aynı kök neden",
      viewDetailsBtn: "Detayları Gör",
      findingDeleteConfirm: "Bu finding'i silmek istediğinize emin misiniz?",
      findingDeleted: "Bulgu silindi",
      newFindingBtn: "+ Yeni Bulgu",
      promoteFindingBtn: "Profesyonel Bulguya Yükselt",
      pwFindingsProLabel: "Profesyonel Bulgular",
      pwFindingsProEmpty: "Henüz professional finding yok.",
      pwFindingsQuickLabel: "Hızlı Bulgular (Checklist Notları)",
      cvssAV: "Saldırı Vektörü", cvssAC: "Saldırı Karmaşıklığı", cvssPR: "Gereken Yetki",
      cvssUI: "Kullanıcı Etkileşimi", cvssS: "Kapsam", cvssC: "Gizlilik", cvssI: "Bütünlük", cvssA: "Erişilebilirlik",
      cvssAV_N: "Ağ", cvssAV_A: "Bitişik ağ", cvssAV_L: "Yerel", cvssAV_P: "Fiziksel",
      cvssAC_L: "Düşük", cvssAC_H: "Yüksek",
      cvssPR_N: "Yok", cvssPR_L: "Düşük", cvssPR_H: "Yüksek",
      cvssUI_N: "Yok", cvssUI_R: "Gerekli",
      cvssS_U: "Değişmez", cvssS_C: "Değişir",
      cvssCIA_N: "Yok", cvssCIA_L: "Düşük", cvssCIA_H: "Yüksek",

      pwTestPlanDesc: "Recon önceliklendirmelerinden oluşan, şeffaf skorlamalı test planını görüntüleyin.",
      pwTestPlanOpenBtn: "Test Planını Aç",
      pwWstgDesc: "Bu proje için bir test oturumu başlatın veya kaldığınız yerden devam edin; WSTG checklist'i buradan yönetilir.",
      pwWstgOpenBtn: "Checklist'i Aç",

      pwFindingsEmpty: "Henüz bulgu yok.",
      pwFindingsNoSession: "Bu projede henüz bir test oturumu yok. Önce WSTG Testleri sekmesinden bir oturum başlatın.",

      pwTabChains: "Saldırı Zincirleri",
      pwChainsDesc: "Projedeki bulgular, bilinen saldırı zinciri kalıplarıyla eşleştirilir (sabit kurallar, model çağrısı yapılmaz).",
      pwChainsEmpty: "Şu an eşleşen bir saldırı zinciri yok. En az 2 adımı eşleşen bulgu gerekir.",
      pwChainsCompleteness: n => `${n}% tamamlanmış`,
      pwChainsRiskScore: "Risk Skoru",
      pwChainsStepMatched: "Eşleşen bulgu",
      pwChainsStepMissing: "Bu adımda henüz bulgu yok",

      lifecycleRemediationRate: "Giderilme Oranı",
      lifecycleStatusUpdated: "Bulgu durumu güncellendi",
      lifecycleStatus_open: "Açık",
      lifecycleStatus_retesting: "Yeniden Test Ediliyor",
      lifecycleStatus_fixed: "Düzeltildi",
      lifecycleStatus_resolved: "Kapatıldı",
      lifecycleStatus_wont_fix: "Düzeltilmeyecek",
      lifecycleStatus_accepted_risk: "Kabul Edilen Risk",

      customTestsCategoryName: "Özel Testler",
      customTestsCategoryDesc: "Bu projeye özel, kuruluşunuza ait ek test maddeleri (resmi WSTG veri setinden gelmez).",
      customTestsLabel: "Özel Testler",
      customTestsDesc: "WSTG 5.0 henüz yayınlanmadığı için resmi içerik eklenemiyor — ama kuruluşunuza özel test maddeleri ekleyebilirsiniz. Bunlar checklist'te ayrı bir 'Özel Testler' kategorisi altında normal bir WSTG testi gibi görünür.",
      customTestTitlePlaceholder: "Test başlığı (ör. İç ağ admin paneli erişimi)",
      customTestDescPlaceholder: "Açıklama (opsiyonel)",
      customTestAddBtn: "Ekle",
      customTestTitleRequired: "Başlık zorunludur.",
      customTestsEmpty: "Henüz özel test eklenmedi.",

      pwTabEvidence: "Kanıtlar",
      pwEvidenceUploadLabel: "Ekran Görüntüsü Yükle",
      pwEvidenceUploadBtn: "Yükle",
      pwEvidenceUploading: "Yükleniyor...",
      pwEvidenceEmpty: "Henüz kanıt yüklenmedi.",
      pwEvidenceUploadError: "Yükleme başarısız",
      pwEvidenceAiOff: "AI analizi devre dışı — etkinleştirmek için backend/.env dosyasına ANTHROPIC_API_KEY ekleyin.",
      pwEvidenceAiError: "AI analizi başarısız",
      pwEvidenceAiConfidence: "Güven",
      pwEvidenceSuggested: "Önerilen WSTG testleri",
      pwEvidenceAccept: "Kabul Et",
      pwEvidenceReject: "Reddet",
      pwEvidenceLinkedTo: "Bağlı",
      pwEvidenceLinkFindingLabel: "Bir bulguya bağla:",
      pwEvidenceLinkFindingNone: "— Bağlı değil —",
      pwEvidenceLinkedToFinding: "Kanıt finding'e bağlandı",
      pwEvidenceDelete: "Sil",
      pwEvidenceAddHttpLabel: "HTTP İstek/Yanıt Ekle",
      pwEvidenceHttpLabelField: "Etiket (opsiyonel)",
      pwEvidenceHttpRequestLabel: "HTTP İsteği",
      pwEvidenceHttpResponseLabel: "HTTP Yanıtı",
      pwEvidenceRedactionNote: "Authorization/Cookie/JWT/API key/parola/e-posta/kredi kartı gibi hassas veriler kaydedilirken otomatik olarak maskelenir (redaction). Ham metin sadece 'Ham Metni Göster' ile açıkça görüntülenir.",
      pwEvidenceHttpRequired: "En az bir istek veya yanıt girilmelidir.",
      pwEvidenceShowRaw: "Ham Metni Göster/Gizle",
      pwEvidenceRawWarning: "Ham (redakte edilmemiş) metin — hassas veri içerebilir, dikkatli paylaşın.",
      pwEvidenceReviewPending: "İnceleme bekliyor",
      pwEvidenceReviewAccepted: "Kabul edildi",
      pwEvidenceReviewRejected: "Reddedildi",
      pwEvidenceDeleteConfirm: "Bu kanıtı silmek istediğinize emin misiniz?",

      pwTimelineEmpty: "Henüz bir aktivite kaydı yok.",

      pwReportsNoSession: "Bu projede henüz bir test oturumu yok.",
      pwReportsOpenBtn: "Raporu Aç ve İndir",
      pwProReportsLabel: "Profesyonel Raporlar",
      pwProReportsDesc: "Projedeki tüm oturumların bulgularını birleştiren, indirilebilir Word (.docx) raporları.",
      pwReportTypeTechnical: "Teknik Rapor",
      pwReportTypeTechnicalDesc: "Tüm test sonuçları ve bulguların tam detaylı dökümü — pentester/QA için.",
      pwReportTypeExecutive: "Yönetici Özeti",
      pwReportTypeExecutiveDesc: "Genel risk postürü, sayılar ve öne çıkan bulgular — yönetim için.",
      pwReportTypeDeveloper: "Geliştirici Çözüm Raporu",
      pwReportTypeDeveloperDesc: "Problem / Neden Önemli / Nasıl Düzeltilir formatında somut aksiyon rehberi.",
      pwReportsSessionExportLabel: "Basit JSON Dışa Aktarım (oturum bazlı)",

      reportBuilderTitle: "HTML Rapor Oluşturucu",
      reportBuilderDesc: "Özelleştirilebilir, tek dosyalık HTML rapor — tarayıcıdan doğrudan yazdır / PDF olarak kaydet.",
      reportTitleLabel: "Rapor Başlığı",
      reportClientLabel: "Müşteri Adı",
      reportPentesterLabel: "Test Uzmanı",
      reportDateRangeLabel: "Tarih Aralığı",
      reportIncludeLabel: "Dahil Edilecek Bulgular",
      reportIncludeAll: "Tümü",
      reportIncludeCriticalHigh: "Sadece Kritik + Yüksek",
      reportIncludeSelected: "Seçtiğim Bulgular",
      reportFindingPickerLabel: "Rapora Dahil Edilecek Bulgular",
      reportFindingPickerEmpty: "Bu projede henüz kayıtlı bulgu yok.",
      reportTemplateLabel: "Şablon",
      reportTemplateStandard: "Standart",
      reportTemplateExecutive: "Yönetici Özeti",
      reportTemplateDetailed: "Detaylı",
      reportConfidentialLabel: "Gizli (rapora 'GİZLİ' etiketi ekle)",
      reportExecSummaryLabel: "Yönetici Özeti (opsiyonel, AI ile oluşturulabilir)",
      reportExecSummaryPlaceholder: "Boş bırakılırsa rapor istatistik tabanlı sade bir özet kullanır.",
      reportGenSummaryBtn: "AI ile Özet Oluştur",
      reportOpenHtmlBtn: "HTML Raporu Aç",
      reportDownloadPdfBtn: "PDF İndir",
      reportPdfGenerating: "PDF oluşturuluyor…",

      pwTabKanbanDesc: "WSTG testlerini kanban panosunda sürükle-bırak ile takip edin.",
      kanbanFilterTestId: "WSTG ID filtrele...",
      kanbanFilterAllSeverity: "Tüm Önem Dereceleri",
      kanbanFilterAssignee: "Atanan kişi filtrele...",
      kanbanMyTasks: "Sadece Görevlerim",
      kanbanMyName: "Adım (filtre için)",
      kanbanAssignPlaceholder: "Ata...",
      kanbanMinutesShort: "dk",
      kanbanColumnEmpty: "Kart yok",
      kanbanCardUpdated: "Kart güncellendi",
      kanbanCol_todo: "Yapılacak",
      kanbanCol_testing: "Test Ediliyor",
      kanbanCol_review: "İncelemede",
      kanbanCol_confirmed: "Onaylandı",
      kanbanCol_done: "Tamamlandı",

      pwEventType_project_created: "Proje oluşturuldu",
      pwEventType_session_created: "Oturum oluşturuldu",
      pwEventType_session_completed: "Oturum tamamlandı",
      pwEventType_test_completed: "Test tamamlandı",
      pwEventType_finding_created: "Yeni bulgu",
      pwEventType_scope_updated: "Kapsam güncellendi",
      pwEventType_recon_run: "Recon çalıştırıldı",
      authSetupTitle: "Parolanızı belirleyin",
      authSetupDesc: "Bu çalışma alanı müşteri bulgularını ve kanıtları saklar. Devam etmeden önce bir parola belirleyin; parolanın kendisi değil, yalnızca tuzlanmış hash'i saklanır.",
      authLoginTitle: "Giriş yap",
      authLoginDesc: "Pentest Workspace'e devam etmek için parolanızı girin.",
      authSetupRemoteTitle: "Parola henüz belirlenmemiş",
      authSetupRemoteDesc: "İlk parola yalnızca API'nin çalıştığı bilgisayardan belirlenebilir. Arayüzü o bilgisayarda açın ya da orada terminalde şu komutu çalıştırın:",
      authPasswordLabel: "Parola",
      authNewPasswordLabel: "Yeni parola",
      authConfirmPasswordLabel: "Yeni parola (tekrar)",
      authCurrentPasswordLabel: "Mevcut parola",
      authPasswordHint: "En az 12 karakter. Bir parola yöneticisi ya da birkaç kelimelik bir cümle iyi bir seçimdir.",
      authSetupBtn: "Parolayı belirle ve devam et",
      authLoginBtn: "Giriş yap",
      authRetry: "Tekrar kontrol et",
      authContinueLocal: "Backend olmadan yerel checklist modunda devam et",
      authChangePassword: "Parolayı değiştir",
      authLogout: "Çıkış yap",
      authChangeTitle: "Parolayı değiştir",
      authChangeDesc: "Parola değişince diğer tarayıcılardaki açık oturumlar kapanır; bu oturum devam eder.",
      authChangeBtn: "Parolayı güncelle",
      authChangedToast: "Parola güncellendi. Diğer oturumlar kapatıldı.",
      authSessionExpiredNotice: "Oturumunuz sona erdi. Devam etmek için tekrar giriş yapın.",
      authReloggedToast: "Tekrar giriş yapıldı. Son işlemi yeniden deneyin.",
      authErrPasswordRequired: "Parola zorunludur.",
      authErrPasswordTooShort: "Parola en az 12 karakter olmalıdır.",
      authErrPasswordTooLong: "Parola en fazla 256 karakter olabilir.",
      authErrPasswordWhitespace: "Parola başında veya sonunda boşluk olamaz.",
      authErrPasswordUnchanged: "Yeni parola mevcut paroladan farklı olmalıdır.",
      authErrPasswordMismatch: "Parolalar eşleşmiyor.",
      authErrInvalidPassword: "Parola hatalı.",
      authErrInvalidCurrentPassword: "Mevcut parola hatalı.",
      authErrTooManyAttempts: "Çok fazla hatalı deneme. {s} saniye sonra tekrar deneyin.",
      authErrSetupLoopbackOnly: "İlk parola yalnızca API'nin çalıştığı bilgisayardan belirlenebilir.",
      authErrAlreadyConfigured: "Parola zaten belirlenmiş. Giriş yapın.",
      authErrSetupRequired: "Önce bir parola belirlenmeli.",
      authErrSessionExpired: "Oturumunuz sona erdi. Tekrar giriş yapın.",
      authErrNetwork: "API'ye ulaşılamadı. Backend çalışıyor mu?"
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
      sortByPriorityBtn: "Sort By Priority",
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
      exportProHint: "Tip: for an AI-assisted PDF/HTML professional report (finding selection, executive summary), open a Project and use its 'Reports' tab.",
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
      dbOnline: "Database connected",
      dbOffline: "No database — run backend/app.py (continuing in local mode)",
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

      navNotebook: "Notebook",
      navStudyMetrics: "Study Metrics",
      notebookTitle: "Notebook",
      notebookDesc: (name) => `Notes for the “${name}” session. Link them to a test item or keep them as general notes.`,
      notebookNeedSession: "Open a test session first to use the notebook.",
      notebookNeedBackend: "The notebook requires the backend.",
      notebookSearchPlaceholder: "Search notes…",
      notebookFilterAll: "All notes",
      notebookFilterGeneral: "General notes",
      newNote: "+ New Note",
      editNote: "Edit note",
      noteEditorDesc: "Write your observation clearly; attach screenshots if you like (pasting works too).",
      noteTitleLabel: "Title",
      noteTitlePlaceholder: "e.g. SQL injection in the login form",
      noteUntitled: "Untitled note",
      noteLinkedTestLabel: "Related test item (optional)",
      noteGeneralOption: "— General note (not linked to a test) —",
      noteGeneralBadge: "General",
      noteFpLabel: "Verification",
      noteFpUnknown: "Not assessed",
      noteFpValid: "Valid finding",
      noteFpFalse: "False positive",
      noteContentLabel: "Note / finding",
      noteAddImage: "Add image",
      noteImageHint: (n, max) => `${n}/${max} images · PNG, JPEG, GIF, WebP · up to 3 MB`,
      noteImageTypeError: "Only PNG, JPEG, GIF or WebP images can be added.",
      noteImageSizeError: "Images can't be larger than 3 MB.",
      noteImageCountError: (max) => `You can add at most ${max} images.`,
      noteImagePayloadError: "The images are too large in total; remove a few.",
      noteImageReadError: "Couldn't read the image.",
      noteImageRemove: "Remove image",
      noteUnsafeImagesDropped: (n) => `${n} old image(s) aren't in a safe format and are hidden; saving will remove them.`,
      noteCweNameLabel: "CWE name",
      noteCweSuggested: (id) => `Suggested CWEs for ${id}:`,
      noteCvssLabel: "CVSS 3.1 vector (optional)",
      noteCvssInvalid: "Invalid vector",
      noteAiAnalyze: "Analyze with AI",
      noteAiRationale: "Assessment",
      noteAiFp: "False-positive likelihood",
      noteAiSuggestCwe: "Suggested CWE",
      noteAiSuggestSeverity: "Suggested severity",
      noteAiSuggestCvss: "Suggested CVSS",
      noteAiApply: "Apply",
      noteAiApplied: "Suggestion applied to the form",
      noteAiNoSuggestion: "The AI returned no suggestions.",
      fpLikelihood_low: "Low",
      fpLikelihood_medium: "Medium",
      fpLikelihood_high: "High",
      noteContentRequired: "A note needs text or at least one image.",
      saveNote: "Save",
      deleteNote: "Delete",
      noteSaved: "Note saved",
      noteDeleted: "Note deleted",
      noteDeleteConfirm: "Delete this note?",
      noteEmptyList: "No notes yet. Add one with “+ New Note”.",
      noteEmptyFiltered: "No notes match this filter.",
      noteAddForTest: "Add note",
      noteCountForTest: (n) => `${n} note${n === 1 ? '' : 's'}`,
      controlGroupBanner: "This session is in the control group: AI features are off.",
      studyGroupLabel: "Study group (optional)",
      studyGroupNone: "— Not set —",
      studyGroupAi: "AI-assisted",
      studyGroupControl: "Control (checklist only)",
      studyGroupHintAi: "AI features stay on; AI calls in this session are recorded in the metrics.",
      studyGroupHintControl: "While this session is open, AI buttons are hidden (checklist only).",
      studyGroupBadge_ai_assisted: "AI-assisted",
      studyGroupBadge_control: "Control",
      sessionCompleteBtn: "Complete",
      sessionReopenBtn: "Reopen",
      sessionCompletedToast: "Session marked as completed",
      sessionReopenedToast: "Session reopened",
      studyMetricsTitle: "Study Metrics",
      studyMetricsDesc: "Averages of sessions assigned to the “AI-assisted” and “control” groups. These are descriptive; interpret carefully when the number of sessions per group (n) is small.",
      studyMetricsColAi: "AI-assisted",
      studyMetricsColControl: "Control",
      studyMetricsColDiff: "Difference",
      studyMetricMinutes: "Completion time (min)",
      studyMetricCompletedTests: "Completed tests",
      studyMetricCompletionPct: "Completion (%)",
      studyMetricFindings: "Findings",
      studyMetricFpRate: "False-positive rate (%)",
      studyMetricAiCalls: "AI calls",
      studyMetricAiLatency: "Avg. AI latency (ms)",
      studyMetricReportGenerated: "Sessions with an AI report draft (%)",
      studyMetricsEmpty: "No sessions are assigned to a study group yet. Pick a “Study group” when creating a session.",
      studyMetricsUnassigned: (n) => `${n} session(s) weren't counted because they have no group.`,
      studyMetricsDiffNote: "Difference = (AI − Control) / Control. Green means the AI group did better on that metric. Duration is only computed for sessions closed with “Complete”.",
      studyMetricsSessions: "Sessions",
      studyMetricsColSession: "Session",
      studyMetricsColGroup: "Group",
      studyMetricsCopyCsv: "Copy as CSV",
      loadingGeneric: "Loading…",
      studyMetricsLoadError: "Couldn't load the metrics.",
      studyMetricsNeedBackend: "Study metrics require the backend.",
      importModalTitle: "Import Findings",
      importModalDesc: "Upload Nmap, Nikto, WPScan, Burp Suite or OWASP ZAP output; matching findings are attached as notes to the relevant WSTG items. Burp/ZAP issues can also be created as professional findings in the project.",
      importOptNotes: "Add as notes to the matching checklist items and mark them done",
      importOptPro: (name) => `Create professional findings in “${name}” (with endpoint, CWE and remediation)`,
      importOptHttp: "Attach the HTTP request/response to the finding as evidence (cookies, Authorization and tokens are masked automatically)",
      importProNeedProject: "Select a project in the top bar first to create professional findings.",
      importProDedupeHint: "Findings whose title and endpoint already exist in the project are not created again.",
      importNothingSelected: "Nothing to apply is selected.",
      importCreatingFindings: (i, n) => `Creating findings… ${i}/${n}`,
      importProResult: (created, skipped, failed) => `${created} finding(s) created` + (skipped ? `, ${skipped} already existed` : '') + (failed ? `, ${failed} failed` : ''),
      importHttpBadge: "HTTP",
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
      reconResetBtn: "Reset / Re-scan",
      reconResetConfirm: "Delete the saved scan results and priority data for this project/session? This cannot be undone.",
      reconResetToast: "Scan data reset",
      reconCachedNotice: (target, when) => `Last scan: <b>${target}</b>${when ? ' · ' + when : ''} — showing without re-scanning.`,
      reconPriorityBadge_high: "High Priority",
      reconPriorityBadge_medium: "Medium Priority",
      reconPriorityBadge_low: "Low Priority",
      reconPriorityBadge_info: "Suggested",

      navPlanner: "Test Plan",
      plannerModalTitle: "Test Plan",
      plannerModalDesc: "Prioritized items from Attack Surface Discovery, ranked by a transparent score based on evidence count and WSTG methodology order. The reason is shown next to each suggestion.",
      plannerEmpty: "No test plan yet. Run Attack Surface Discovery against a target first and prioritize the findings.",
      plannerReasonLabel: "Reason",
      plannerGotoBtn: "Go to this item",
      plannerScoreNote: "Score is computed from evidence count + priority level + WSTG methodology order (fixed rules, no model call involved).",

      navAiNextTest: "AI: What's Next?",
      aiNextTestTitle: "AI: What's Next?",
      aiNextTestDesc: "Looking at the tests you've completed so far and the findings you've recorded, the AI suggests the next logical step along with its reasoning. Unlike the Test Plan: no recon evidence is required, and it uses AI reasoning instead of fixed rules — so it's always a draft suggestion, not a guaranteed-correct answer.",
      aiNextTestAskBtn: "Suggest",
      aiNextTestAllDone: "All tests appear to be completed — nothing left to suggest!",
      aiNextTestNoSuggestion: "The AI couldn't produce a suggestion. Please try again.",
      aiNextTestUngrounded: "The test ID suggested by the AI was unexpected — please review it carefully.",
      aiNextTestAltsLabel: "Alternative candidates",

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
      pwTabRetest: "Retest",
      rtDesc: "Retest findings the client reports as fixed: mark each as \"Fixed\" or \"Still open\" and add a note and evidence. Fixed → status Resolved; Still open → the finding is reopened. To put a finding in scope, set its status to Fixed / Retest Pending or add it from the \"Other open\" list.",
      rtState_pending: "Awaiting retest",
      rtState_still_open: "Still open",
      rtState_verified: "Fixed (verified)",
      rtFilter_pending: "Pending",
      rtFilter_still_open: "Still open",
      rtFilter_verified: "Verified",
      rtFilter_other: "Other open",
      rtFilter_all: "All",
      rtEmpty_pending: "No findings are awaiting retest.",
      rtEmpty_still_open: "No findings remained open after retest.",
      rtEmpty_verified: "No verified fixes yet.",
      rtEmpty_other: "No open findings outside the retest scope.",
      rtEmpty_all: "This project has no findings.",
      rtLastRetest: "Last retest",
      rtResult_fixed: "fixed",
      rtResult_not_fixed: "still open",
      rtNotePlaceholder: "Retest note (e.g. the payload now returns 400)",
      rtMarkFixed: "✓ Fixed",
      rtMarkOpen: "✗ Still open",
      rtAddEvidence: "Add evidence",
      rtRequest: "Add to retest",
      rtReportPdf: "Retest report (PDF)",
      rtReportHtml: "Open report (HTML)",
      rtIncludePending: "Include pending findings in the report",
      rtFileSuffix: "retest",
      rtToastFixed: "Marked as fixed; finding resolved",
      rtToastOpen: "Marked as still open; finding reopened",
      rtToastRequested: "Finding added to retest",
      rtToastEvidence: "Evidence attached to the finding",
      pwTabAuthz: "Authorization Matrix",
      azDesc: "Mark whether each role should be able to access each endpoint (expected) and what your own test showed (observed). Cells that are expected \"Denied\" but were \"Accessible\" are authorization flaws (WSTG-ATHZ-02/03/04). The app never sends requests to the target.",
      azEmptyTitle: "No roles defined yet",
      azEmptyDesc: "Add roles (e.g. Anonymous, User, Admin) as columns and endpoints as rows.",
      azDefaultRolesBtn: "Start with Anonymous / User / Admin",
      azEndpointCol: "Endpoint",
      azNoEndpoints: "No endpoints yet. Add one above or take them from the Attack Surface.",
      azNewRolePlaceholder: "New role name",
      azAddRole: "+ Role",
      azAddEndpoint: "+ Endpoint",
      azFromSurface: "Take endpoints from Attack Surface",
      azCopyCsv: "Copy as CSV",
      azCreateFindingsBtn: (n) => n ? `Create findings from mismatches (${n})` : "No mismatches to report",
      azCreateOneFinding: "Create a finding for this mismatch",
      azFindingsResult: (c, l, f) => `${c} finding(s) created` + (l ? `, ${l} linked to existing` : '') + (f ? `, ${f} failed` : ''),
      azSumCells: (n) => `${n} cells`,
      azSumTested: (n) => `${n} tested`,
      azSumViolations: (n) => `${n} unauthorized`,
      azSumOver: (n) => `${n} over-restricted`,
      azSumUntested: (n) => `${n} untested`,
      azExpected: "Expected",
      azObserved: "Observed",
      azExpAllow: "Allowed",
      azExpDeny: "Denied",
      azObsAllowed: "Accessible",
      azObsDenied: "Blocked",
      azObsNone: "Not tested",
      azObsNoneShort: "?",
      azStViolation: "Unauthorized access: this role reached a resource it should not.",
      azStOver: "Over-restricted: this role should have access but was blocked.",
      azStOk: "Behaves as expected.",
      azStObserved: "Result entered; also mark the expected access.",
      azStUntested: "Not tested yet.",
      azNote: "Note",
      azNotePlaceholder: "e.g. 200 OK, another user's order was returned",
      azNextCell: "Next cell →",
      azEditorHint: "Click a cell to mark expected and observed access. Click a role or endpoint name to edit it.",
      azRoleTitle: "Role",
      azRoleNameLabel: "Role name",
      azEndpointTitle: "Endpoint",
      azMethod: "Method",
      azPath: "Path",
      azDelete: "Delete",
      azDeleteRoleConfirm: (n) => `Delete the "${n}" role and all results in its column?`,
      azDeleteEndpointConfirm: (n) => `Delete ${n} and all results in its row?`,
      azTooManyRoles: (n) => `You can add at most ${n} roles.`,
      azRoleExists: "A role with this name already exists.",
      azEndpointExists: "This method and path already exist (or the path is empty).",
      azNoSurfaceEndpoints: "No endpoints recorded in the Attack Surface. Run Attack Surface Discovery first.",
      azSurfaceAdded: (a, s) => `${a} endpoint(s) added` + (s ? `, ${s} already present` : ''),
      azSaving: "Saving…",
      azSaved: "Saved",
      azLastSaved: (d) => `Last saved: ${d}`,
      azLoadError: "Couldn't load the authorization matrix.",
      pwTabTimeline: "Timeline", pwTabKanban: "Kanban", pwTabReports: "Reports",

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
      pwAssetsViewList: "List",
      pwAssetsViewMap: "Map",
      pwAssetsMapFindingsLabel: "Associated Findings",
      pwAssetsMapNoFindings: "No findings linked to this endpoint.",

      pwReconDesc: "Run Attack Surface Discovery for this project; results are automatically fed into Assets and the Timeline.",
      pwReconOpenBtn: "Open Attack Surface Discovery",

      pwTabTools: "Tools",
      pwToolsDesc: "Run real discovery tools (nmap, httpx, whatweb, subfinder, dnsx) on your own machine. You see and approve the exact command before it runs.",
      pwToolsExcludedNote: "Note: nuclei and ffuf are deliberately not included — nuclei's templates include active exploit-verification checks, and ffuf performs aggressive directory fuzzing. Both would need a separate, more tightly-scoped iteration.",
      toolSelectLabel: "Tool",
      toolTargetLabel: "Target",
      toolNotInstalled: "Not installed on your system",
      toolPreviewLabel: "Command that will run:",
      toolAuthLabel: "I confirm that I am authorized to test this target.",
      toolPreviewBtn: "Preview Command",
      toolRunBtn: "Approve & Run",
      toolRunning: "Running... (this can take a few minutes)",
      toolRunError: "Tool execution failed",
      toolTargetRequired: "Please enter a target.",
      toolAuthRequired: "You must check the authorization box to continue.",
      toolStatus_completed: "Completed",
      toolStatus_failed: "Failed",
      toolStatus_timeout: "Timed Out",
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

      aiAssistantTitle: "AI Assistant",
      aiGenDescBtn: "Generate Description",
      aiGenRemediationBtn: "Generate Remediation",
      aiRewriteBtn: "Make More Professional",
      aiFindSimilarBtn: "Find Similar Findings",
      aiSuggestCweBtn: "Suggest CWE/Severity",
      aiWorking: "AI is working…",
      aiRequestTimeout: "The AI response timed out (45s). Check your internet connection, the API key you're using, and the provider's status, then try again.",
      aiDone: "Done",
      aiSaveFirst: "Save the finding once before using the AI assistant.",
      aiNotConfigured: "No AI provider configured (check your .env file).",
      aiNoTextToRewrite: "Enter a description first.",

      navAiSettings: "AI Settings",
      aiSettingsTitle: "AI Settings",
      aiSettingsDesc: "Add, edit, and test your API keys here, and choose which provider is active. Keys are stored encrypted and never shown in full.",
      aiApiKeyLabel: "API Key",
      aiModelLabel: "Model",
      aiBaseUrlLabel: "Base URL",
      aiKeySavedPlaceholder: "Saved: {key} — enter a new key to change it",
      aiKeyEmptyPlaceholder: "Enter API key...",
      aiToggleVisibility: "Show/Hide",
      aiActiveLabel: "Active",
      aiTestBtn: "Test",
      aiActivateBtn: "Activate",
      aiDeleteBtn: "Delete",
      aiSettingsSaved: "AI setting saved",
      aiSettingsDeleted: "AI setting deleted",
      aiProviderActivated: "Provider activated",
      aiDeleteConfirm: "Are you sure you want to delete this provider's saved key?",
      aiTestSuccess: "Connection successful",
      aiTestFailed: "Connection failed",
      aiStatusWorkingWith: "is active",
      aiStatusNotConfigured: "AI not configured",

      byokTopbarLabel: "My Own Key",
      byokTitle: "Use Your Own API Key",
      byokDesc: "The key you enter here is kept only in this browser tab; it is never saved to the server and is automatically discarded when you close the tab. Once activated, all your AI requests use this key and model — the shared/default AI Settings are not affected.",
      byokStatusOff: "Currently using the shared/default AI provider.",
      byokStatusOn: "Active for this session: {provider} {model}",
      byokProviderLabel: "Provider",
      byokKeyLabel: "API Key",
      byokModelLabel: "Model (optional — default is used if left blank)",
      byokBaseUrlLabel: "Ollama Base URL",
      byokHint: "Tip: your key is stored in the browser's session storage; it survives a page refresh but disappears when you close the tab.",
      byokActivateBtn: "Activate For This Session",
      byokClearBtn: "Deactivate",
      byokActivatedToast: "Your own API key is now active for this session",
      byokClearedToast: "Your own API key was deactivated, back to the shared setting",
      byokMissingKey: "Please enter an API key",
      byokMissingProvider: "Please choose a provider",

      dupAlertTitle: "Potential Duplicate Finding Detected",
      dupAlertDesc: "Findings similar to this one already exist in the project.",
      dupMergeBtn: "Merge Selected",
      dupCreateAnywayBtn: "Create Anyway",
      dupSelectAtLeastTwo: "Select at least 2 findings to merge.",
      dupMergeSuccess: "Findings merged",
      dupNoneFound: "No similar findings found.",
      dupReasonSimilarTitle: "similar title",
      dupReasonSimilarDescription: "similar description",
      dupReasonSameEndpoint: "same endpoint",
      dupReasonSameCwe: "same CWE",
      dupReasonSameTestId: "same test ID",
      dupReasonSameRootCause: "likely same root cause",
      viewDetailsBtn: "View Details",
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
      lifecycleStatus_open: "Open",
      lifecycleStatus_retesting: "Retesting",
      lifecycleStatus_fixed: "Fixed",
      lifecycleStatus_resolved: "Resolved",
      lifecycleStatus_wont_fix: "Won't Fix",
      lifecycleStatus_accepted_risk: "Accepted Risk",

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
      pwEvidenceAiOff: "AI analysis disabled — add ANTHROPIC_API_KEY to backend/.env to enable it.",
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
      pwEvidenceShowRaw: "Show/Hide Raw Text",
      pwEvidenceRawWarning: "Raw (unredacted) text — may contain sensitive data, share carefully.",
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

      reportBuilderTitle: "HTML Report Builder",
      reportBuilderDesc: "Customizable, single-file HTML report — print / save as PDF directly from the browser.",
      reportTitleLabel: "Report Title",
      reportClientLabel: "Client Name",
      reportPentesterLabel: "Pentester",
      reportDateRangeLabel: "Date Range",
      reportIncludeLabel: "Findings to Include",
      reportIncludeAll: "All",
      reportIncludeCriticalHigh: "Critical + High Only",
      reportIncludeSelected: "Selected Findings",
      reportFindingPickerLabel: "Findings to Include in the Report",
      reportFindingPickerEmpty: "This project has no findings yet.",
      reportTemplateLabel: "Template",
      reportTemplateStandard: "Standard",
      reportTemplateExecutive: "Executive",
      reportTemplateDetailed: "Detailed",
      reportConfidentialLabel: "Confidential (adds a 'CONFIDENTIAL' label to the report)",
      reportExecSummaryLabel: "Executive Summary (optional, can be AI-generated)",
      reportExecSummaryPlaceholder: "If left empty, the report uses a plain statistics-based summary.",
      reportGenSummaryBtn: "Generate Summary with AI",
      reportOpenHtmlBtn: "Open HTML Report",
      reportDownloadPdfBtn: "Download PDF",
      reportPdfGenerating: "Generating PDF…",

      pwTabKanbanDesc: "Track WSTG tests on a drag-and-drop kanban board.",
      kanbanFilterTestId: "Filter WSTG ID...",
      kanbanFilterAllSeverity: "All Severities",
      kanbanFilterAssignee: "Filter assignee...",
      kanbanMyTasks: "My Tasks Only",
      kanbanMyName: "My name (for filter)",
      kanbanAssignPlaceholder: "Assign...",
      kanbanMinutesShort: "min",
      kanbanColumnEmpty: "No cards",
      kanbanCardUpdated: "Card updated",
      kanbanCol_todo: "To Do",
      kanbanCol_testing: "Testing",
      kanbanCol_review: "Review",
      kanbanCol_confirmed: "Confirmed",
      kanbanCol_done: "Done",

      pwEventType_project_created: "Project created",
      pwEventType_session_created: "Session created",
      pwEventType_session_completed: "Session completed",
      pwEventType_test_completed: "Test completed",
      pwEventType_finding_created: "New finding",
      pwEventType_scope_updated: "Scope updated",
      pwEventType_recon_run: "Recon run",
      authSetupTitle: "Set your password",
      authSetupDesc: "This workspace stores client findings and evidence. Set a password before you continue. Only a salted hash is stored, never the password itself.",
      authLoginTitle: "Sign in",
      authLoginDesc: "Enter your password to continue to Pentest Workspace.",
      authSetupRemoteTitle: "No password set yet",
      authSetupRemoteDesc: "The first password can only be set from the computer running the API. Open the interface on that computer, or run this command in a terminal there:",
      authPasswordLabel: "Password",
      authNewPasswordLabel: "New password",
      authConfirmPasswordLabel: "New password (again)",
      authCurrentPasswordLabel: "Current password",
      authPasswordHint: "At least 12 characters. A password manager or a short sentence of a few words works well.",
      authSetupBtn: "Set password and continue",
      authLoginBtn: "Sign in",
      authRetry: "Check again",
      authContinueLocal: "Continue in local checklist mode without the backend",
      authChangePassword: "Change password",
      authLogout: "Sign out",
      authChangeTitle: "Change password",
      authChangeDesc: "Changing the password signs out sessions in other browsers. This session stays signed in.",
      authChangeBtn: "Update password",
      authChangedToast: "Password updated. Other sessions were signed out.",
      authSessionExpiredNotice: "Your session has ended. Sign in again to continue.",
      authReloggedToast: "Signed in again. Retry your last action.",
      authErrPasswordRequired: "Password is required.",
      authErrPasswordTooShort: "Password must be at least 12 characters.",
      authErrPasswordTooLong: "Password can be at most 256 characters.",
      authErrPasswordWhitespace: "Password cannot start or end with a space.",
      authErrPasswordUnchanged: "The new password must differ from the current one.",
      authErrPasswordMismatch: "Passwords do not match.",
      authErrInvalidPassword: "Incorrect password.",
      authErrInvalidCurrentPassword: "Current password is incorrect.",
      authErrTooManyAttempts: "Too many failed attempts. Try again in {s} seconds.",
      authErrSetupLoopbackOnly: "The first password can only be set from the computer running the API.",
      authErrAlreadyConfigured: "A password is already set. Sign in instead.",
      authErrSetupRequired: "A password must be set first.",
      authErrSessionExpired: "Your session has ended. Sign in again.",
      authErrNetwork: "Could not reach the API. Is the backend running?"
    }
  };

  // Yeni arayüz (açık/koyu tema, üst çubuk) için ek metinler
  Object.assign(I18N.tr, {
    navAttackSurface: "Saldırı Yüzeyi",
    pwTabAssets: "Saldırı Yüzeyi",
    asNeedProject: "Saldırı yüzeyini görmek için önce bir proje açın.",
    asTitle: "Saldırı Yüzeyi",
    asDesc: "Bu projede kayıtlı keşif sonuçlarından derlenir. Bu sayfa tarama başlatmaz; yeni keşif için Saldırı Yüzeyi Keşfi'ni kullanın.",
    asTargetLabel: "Hedef:",
    asTargetScope_in: "Hedef kapsamda", asTargetScope_out: "Hedef kapsam dışı",
    asTargetScope_unknown: "Hedef kapsam listesinde yok", asTargetScope_undefined: "Kapsam tanımlanmamış",
    asLoading: "Kayıtlı keşif verisi yükleniyor…",
    asLoadError: "Saldırı yüzeyi verisi yüklenemedi.",
    asRetry: "Tekrar dene",
    asEmptyTitle: "Henüz kayıtlı keşif yok",
    asEmptyDesc: "Bu proje için Saldırı Yüzeyi Keşfi çalıştırıldığında bulunan alt alan adları, endpoint'ler ve teknolojiler burada listelenir.",
    asSummaryTitle: "Keşif özeti",
    asLastScan: "Son kayıtlı keşif",
    asRunCount: n => `${n} tarama kaydı`,
    asStatSubResolved: "DNS'te çözümlenen",
    asStatApi: n => `${n} tanesi API yolu`,
    asStatTechSub: "Ana sayfa yanıtından",
    asFilterHint: "Envanteri bu türe göre filtrelemek için tıklayın",
    asSearchPlaceholder: "Varlık veya WSTG ID ara…",
    asFilterTypeAll: "Tür: Tümü", asFilterScopeAll: "Kapsam: Tümü",
    asClearFilters: "Filtreleri temizle",
    asMapTitle: "Varlık ilişki haritası",
    asViewToggle: "Görünüm", asViewMap: "Harita", asViewList: "Liste",
    asRelationNote: "Bağlantılar, varlığın hangi hedefin tarama kaydında bulunduğunu gösterir. Teknolojiler hedefin ana sayfa yanıtından tespit edildiği için hedefe bağlıdır; hangi alt alan adında çalıştıkları kayıtlı değildir.",
    asRootNode: "Kök hedef",
    asGroup_subdomain: "Alt alan adları", asGroup_endpoint: "Endpoint'ler", asGroup_technology: "Teknolojiler",
    asMoreNodes: n => `+${n} varlık daha (listede göster)`,
    asNoMatch: "Filtrelerle eşleşen varlık yok.",
    asType_domain: "Kök alan adı", asType_subdomain: "Alt alan adı", asType_endpoint: "Endpoint", asType_technology: "Teknoloji",
    asTypeApiEndpoint: "API endpoint",
    asRecord_target: "Tarama hedefi", asRecord_resolved: "DNS çözümlendi", asRecord_link: "Sayfa bağlantısı",
    asRecord_detected: "Yanıttan tespit edildi",
    asRecordHttp: code => `Bilinen yol · HTTP ${code}`,
    asScope_in: "Kapsamda", asScope_out: "Kapsam dışı", asScope_unknown: "Listede yok", asScope_undefined: "Tanımsız",
    asInventoryTitle: "Varlık envanteri",
    asInventoryCount: (n, total) => n === total ? `(${n} varlık)` : `(${n}/${total} varlık)`,
    asColAsset: "Varlık", asColType: "Tür", asColRecord: "Kayıt", asColScope: "Kapsam",
    asColTests: "İlişkili WSTG testi", asColLastSeen: "Son görülme",
    asTestsCount: n => `${n} test`,
    asTestsDerivedNote: "İlişkili WSTG testleri, keşif kaydındaki gerekçe metinlerinden (\"…: /yol\") türetilmiştir. ✓ işareti testin bu projede tamamlandığını gösterir.",
    asFirstSeen: "İlk görülme",
    asTechNoHost: "Teknolojiler için endpoint veya bulgu ilişkisi kayıtlı değildir.",
    asSuggestionsTitle: "Test önerileri",
    asSuggestionsNote: "Her hedefin en son keşif kaydındaki öneriler; seviye ve gerekçeler kayıttan olduğu gibi gösterilir.",
    asLevel_high: "Yüksek öncelik", asLevel_medium: "Orta öncelik", asLevel_low: "Düşük öncelik", asLevel_info: "Bilgi",
    asShowAll: n => `Tümünü göster (${n})`, asShowLess: "Daha az göster",
    asOpenInNewTab: "Yeni sekmede aç", asCopy: "Kopyala", asDetails: "Detay", asColActions: "İşlemler",
    asLinkDisabledOut: "Hedef kapsam dışı olduğu için link kapatıldı; adresi kopyalayabilirsiniz.",
    asLinkWarn_unknown: "hedef kapsam listesinde yok", asLinkWarn_undefined: "proje kapsamı tanımlanmamış",
    asLinkNotice_unknown: target => `${target} kapsam listesinde yok. Linkleri açmadan önce bu hedefi test etme yetkiniz olduğunu doğrulayın.`,
    asLinkNotice_undefined: target => `Bu proje için kapsam tanımlanmamış. ${target} linklerini açmadan önce yetkinizi doğrulayın.`,
    asLinkNoticeOut: target => `${target} kapsam dışı olarak işaretli; bu hedefin linkleri kapatıldı. Adresleri yine de kopyalayabilirsiniz.`,
    asHideStatic: "Görsel, font ve stil dosyalarını gizle",
    copyFailedToast: "Kopyalanamadı; metni seçip elle kopyalayın.",
    navDashboard: "Genel Bakış",
    navCategories: "OWASP WSTG",
    themeLabel: "Tema",
    theme_light: "Açık", theme_dark: "Koyu", theme_system: "Sistem",
    ctxProject: "Proje", ctxSession: "Oturum",
    ctxNoProject: "Proje seçilmedi", ctxNoSession: "Oturum seçilmedi",
    dbBadgeOnline: "Backend bağlı", dbBadgeOffline: "Yerel mod",
    progressLabel: "Genel ilerleme",
    openGuideBtn: "WSTG Rehberini Aç",
    sortByPriorityBtn: "Önceliğe göre",
    sortByPriorityTitle: "Saldırı Yüzeyi Keşfi'nin önerdiği önceliğe göre sırala",
    testsCountLabel: (n, total) => n === total ? `Testler (${n})` : `Testler (${n}/${total})`,
    statusDoneLabel: "Tamamlandı", statusPendingLabel: "Bekliyor",
    statusLabel: "Durum", lastUpdatedLabel: "Son güncelleme",
    completeTestBtn: "Testi tamamla", completedUndoBtn: "Tamamlandı · geri al",
    prevTest: "Önceki test (↑)", nextTest: "Sonraki test (↓)",
    backToTests: "Testler",
    notesAutosaveHint: "Notlar yazarken otomatik kaydedilir.",
    selectTestTitle: "Bir test seçin",
    selectTestHint: "Soldaki listeden bir test seçtiğinizde adımları, örnekleri ve notlarınız burada görünür."
  });
  Object.assign(I18N.en, {
    navAttackSurface: "Attack Surface",
    pwTabAssets: "Attack Surface",
    asNeedProject: "Open a project first to see its attack surface.",
    asTitle: "Attack Surface",
    asDesc: "Compiled from discovery results already recorded for this project. This page never starts a scan; use Attack Surface Discovery for a new one.",
    asTargetLabel: "Target:",
    asTargetScope_in: "Target in scope", asTargetScope_out: "Target out of scope",
    asTargetScope_unknown: "Target not in scope list", asTargetScope_undefined: "No scope defined",
    asLoading: "Loading recorded discovery data…",
    asLoadError: "Could not load attack surface data.",
    asRetry: "Try again",
    asEmptyTitle: "No recorded discovery yet",
    asEmptyDesc: "Once Attack Surface Discovery is run for this project, the subdomains, endpoints and technologies it finds are listed here.",
    asSummaryTitle: "Discovery summary",
    asLastScan: "Last recorded discovery",
    asRunCount: n => `${n} scan record${n === 1 ? '' : 's'}`,
    asStatSubResolved: "Resolved in DNS",
    asStatApi: n => `${n} of them API paths`,
    asStatTechSub: "From the home page response",
    asFilterHint: "Click to filter the inventory by this type",
    asSearchPlaceholder: "Search asset or WSTG ID…",
    asFilterTypeAll: "Type: All", asFilterScopeAll: "Scope: All",
    asClearFilters: "Clear filters",
    asMapTitle: "Asset relationship map",
    asViewToggle: "View", asViewMap: "Map", asViewList: "List",
    asRelationNote: "Links show which target's scan record an asset was found in. Technologies are linked to the target because they were detected from its home page response; which subdomain runs them is not recorded.",
    asRootNode: "Root target",
    asGroup_subdomain: "Subdomains", asGroup_endpoint: "Endpoints", asGroup_technology: "Technologies",
    asMoreNodes: n => `+${n} more (show in list)`,
    asNoMatch: "No assets match the filters.",
    asType_domain: "Root domain", asType_subdomain: "Subdomain", asType_endpoint: "Endpoint", asType_technology: "Technology",
    asTypeApiEndpoint: "API endpoint",
    asRecord_target: "Scan target", asRecord_resolved: "DNS resolved", asRecord_link: "Page link",
    asRecord_detected: "Detected in response",
    asRecordHttp: code => `Known path · HTTP ${code}`,
    asScope_in: "In scope", asScope_out: "Out of scope", asScope_unknown: "Not listed", asScope_undefined: "Undefined",
    asInventoryTitle: "Asset inventory",
    asInventoryCount: (n, total) => n === total ? `(${n} assets)` : `(${n}/${total} assets)`,
    asColAsset: "Asset", asColType: "Type", asColRecord: "Record", asColScope: "Scope",
    asColTests: "Related WSTG test", asColLastSeen: "Last seen",
    asTestsCount: n => `${n} test${n === 1 ? '' : 's'}`,
    asTestsDerivedNote: "Related WSTG tests are derived from the reason texts in the discovery record (\"…: /path\"). ✓ means the test is completed in this project.",
    asFirstSeen: "First seen",
    asTechNoHost: "No endpoint or finding relation is recorded for technologies.",
    asSuggestionsTitle: "Test suggestions",
    asSuggestionsNote: "Suggestions from each target's latest discovery record; level and reasons are shown exactly as recorded.",
    asLevel_high: "High priority", asLevel_medium: "Medium priority", asLevel_low: "Low priority", asLevel_info: "Info",
    asShowAll: n => `Show all (${n})`, asShowLess: "Show less",
    asOpenInNewTab: "Open in new tab", asCopy: "Copy", asDetails: "Details", asColActions: "Actions",
    asLinkDisabledOut: "Link disabled because the target is out of scope; you can still copy the address.",
    asLinkWarn_unknown: "target is not in the scope list", asLinkWarn_undefined: "no project scope defined",
    asLinkNotice_unknown: target => `${target} is not in the scope list. Confirm you are authorized to test it before opening links.`,
    asLinkNotice_undefined: target => `No scope is defined for this project. Confirm your authorization before opening ${target} links.`,
    asLinkNoticeOut: target => `${target} is marked out of scope, so its links are disabled. You can still copy the addresses.`,
    asHideStatic: "Hide image, font and style files",
    copyFailedToast: "Could not copy; select the text and copy it manually.",
    navDashboard: "Overview",
    navCategories: "OWASP WSTG",
    themeLabel: "Theme",
    theme_light: "Light", theme_dark: "Dark", theme_system: "System",
    ctxProject: "Project", ctxSession: "Session",
    ctxNoProject: "No project", ctxNoSession: "No session",
    dbBadgeOnline: "Backend connected", dbBadgeOffline: "Local mode",
    progressLabel: "Overall progress",
    openGuideBtn: "Open WSTG Guide",
    sortByPriorityBtn: "By priority",
    sortByPriorityTitle: "Sort by the priority suggested by Attack Surface Discovery",
    testsCountLabel: (n, total) => n === total ? `Tests (${n})` : `Tests (${n}/${total})`,
    statusDoneLabel: "Completed", statusPendingLabel: "Pending",
    statusLabel: "Status", lastUpdatedLabel: "Last updated",
    completeTestBtn: "Complete test", completedUndoBtn: "Completed · undo",
    prevTest: "Previous test (↑)", nextTest: "Next test (↓)",
    backToTests: "Tests",
    notesAutosaveHint: "Notes are saved automatically as you type.",
    selectTestTitle: "Select a test",
    selectTestHint: "Pick a test from the list to see its steps, examples and your notes here."
  });

  let DATA = null;
  let TOP10 = null;
  let top10Index = 0;
  let progress = loadProgress();
  let findings = loadFindings();
  let reconPriority = loadReconPriority(); // test_id -> { level, reasons: [...] }
  let saveTimers = {};
  let currentCategoryId = null;
  let currentFilter = "all"; // all | done | pending
  let sortByReconPriority = false; // false = resmi WSTG sırası (varsayılan), true = recon önceliğine göre sırala
  let currentLang = loadLang();
  let currentFramework = loadFramework(); // 'wstg' | 'llm-security'
  let currentTheme = loadTheme();
  let dbOnline = false;
  let authBooted = false;      // giriş yapılıp backend'li mod başlatıldı mı
  let authMode = null;         // giriş/kurulum ekranı açıksa modu
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
    // Eski sürümlerden kalan renk teması adları (midnight, cyberpunk...) sisteme göre moda çevrilir.
    try{ const v = localStorage.getItem(THEME_KEY); return THEME_MODES.includes(v) ? v : "system"; }catch(e){ return "system"; }
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

  // Attack Surface Discovery verisi (öncelik rozetleri + son tarama önbelleği)
  // artik ProJE (varsa) ya da OTURUM (varsa) bazinda ayri anahtarlarda
  // tutulur -- eskiden tek, global bir anahtardaydi ve bu yuzden bir
  // oturumu/projeyi silip yenisini actiginizda eski taramanin sonuclari
  // (Test Plani, checklist rozetleri) sizmaya devam ediyordu. Baglam yoksa
  // ('nosession') eski davranisla ayni sekilde calisir.
  function reconContextKey(){
    if(currentProjectId) return `project:${currentProjectId}`;
    if(currentSession && currentSession.id) return `session:${currentSession.id}`;
    return 'nosession';
  }

  function loadReconPriority(){
    try{ return JSON.parse(localStorage.getItem(`${RECON_PRIORITY_KEY}:${reconContextKey()}`)) || {}; }
    catch(e){ return {}; }
  }
  function saveReconPriority(){
    try{ localStorage.setItem(`${RECON_PRIORITY_KEY}:${reconContextKey()}`, JSON.stringify(reconPriority)); }catch(e){}
  }
  // Bağlam (proje/oturum) değiştiğinde çağrılır: eski bağlamın önceliklerini
  // görüntülemeyi bırakıp yeni bağlamınkini (varsa) yükler.
  function reloadReconContext(){
    reconPriority = loadReconPriority();
    renderSidebar();
    renderDashboard();
    if(currentCategoryId) renderTestList();
  }

  // Ham tarama sonucunu (subdomain/tech/endpoint/öneri listesi), Attack
  // Surface Discovery penceresi kapatılıp yeniden açıldığında yeniden
  // taramaya gerek kalmadan geri getirebilmek için bağlam bazlı önbelleğe
  // yazar. Proje modunda ayrıca backend'e de kalıcı olarak yazılır
  // (bkz. runRecon → POST /recon); bu önbellek oturum modunda ve
  // backend'e erişilemediğinde de aynı deneyimi sağlamak içindir.
  function loadReconCache(){
    try{ return JSON.parse(localStorage.getItem(`${RECON_CACHE_KEY}:${reconContextKey()}`)) || null; }
    catch(e){ return null; }
  }
  function saveReconCache(result){
    try{ localStorage.setItem(`${RECON_CACHE_KEY}:${reconContextKey()}`, JSON.stringify({ result, cachedAt: new Date().toISOString() })); }catch(e){}
  }
  function clearReconCache(){
    try{ localStorage.removeItem(`${RECON_CACHE_KEY}:${reconContextKey()}`); }catch(e){}
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
    saveTimers[testId] = setTimeout(()=>{ delete saveTimers[testId]; saveFinding(testId); }, 700);
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
    const row = document.querySelector(`#testList .test-row-item[data-id="${safeId}"]`);
    const test = findTestInCurrentCategory(testId);
    if(row && test){
      const holder = document.createElement('div');
      holder.innerHTML = renderTestRow(test);
      row.replaceWith(holder.firstElementChild);
    }
    if(testId === selectedTestId) updateDetailStatus();
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
    inflightFindingSaves[testId] = (inflightFindingSaves[testId] || 0) + 1;
    const req = existing
      ? apiRequest(`/sessions/${currentSession.id}/results/${testId}`, { method: 'PUT', body: JSON.stringify(payload) })
      : apiRequest(`/sessions/${currentSession.id}/results`, { method: 'POST', body: JSON.stringify(Object.assign({ test_id: testId, status: 'pending' }, payload)) });
    const done = () => { inflightFindingSaves[testId] = Math.max(0, (inflightFindingSaves[testId] || 1) - 1); };
    return req.then(result => {
      done();
      sessionResults[testId] = result;
      refreshFindingBadge(testId);
      setFindingStatus(testId, t('findingSavedToast'), false);
    }).catch(err => {
      done();
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
    document.querySelectorAll('[data-i18n-title]').forEach(el=>{
      el.setAttribute('title', t(el.getAttribute('data-i18n-title')));
    });
    updateThemeTrigger();
    updateProjectChip();
    const langSelect = document.getElementById('langSelect');
    if(langSelect) langSelect.value = currentLang;
    const authLangSelect = document.getElementById('authLangSelect');
    if(authLangSelect) authLangSelect.value = currentLang;
    const frameworkSelect = document.getElementById('frameworkSelect');
    if(frameworkSelect) frameworkSelect.value = currentFramework;
  }

  const darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function resolvedTheme(){
    if(currentTheme === 'system') return darkQuery && darkQuery.matches ? 'dark' : 'light';
    return currentTheme;
  }

  function applyTheme(){
    document.documentElement.setAttribute('data-theme', resolvedTheme());
    updateThemeTrigger();
  }

  function updateThemeTrigger(){
    const btn = document.getElementById('themeTrigger');
    const use = document.querySelector('#themeTriggerIcon use');
    const iconId = { light: 'ic-sun', dark: 'ic-moon', system: 'ic-monitor' }[currentTheme] || 'ic-sun';
    if(use) use.setAttribute('href', '#' + iconId);
    if(btn) btn.title = `${t('themeLabel')}: ${t('theme_' + currentTheme)}`;
  }

  // Açık → Koyu → Sistem döngüsü
  function cycleTheme(){
    const idx = THEME_MODES.indexOf(currentTheme);
    currentTheme = THEME_MODES[(idx + 1) % THEME_MODES.length];
    saveTheme(currentTheme);
    applyTheme();
    showToast(`${t('themeLabel')}: ${t('theme_' + currentTheme)}`);
  }

  if(darkQuery && darkQuery.addEventListener){
    darkQuery.addEventListener('change', ()=>{ if(currentTheme === 'system') applyTheme(); });
  }

  function renderSidebar(){
    const nav = document.getElementById('categoryNav');
    nav.innerHTML = getEffectiveCategories().map(c => {
      const done = c.tests.filter(t => progress[t.id]).length;
      const all = c.tests.length && done === c.tests.length;
      const active = currentCategoryId === c.id && document.getElementById('categoryOverlay').classList.contains('open');
      return `<button class="nav-sub ${all?'done':''} ${active?'active':''}" data-cat="${c.id}" title="${escapeHtml(c.code)}">
        <span class="nav-sub-name">${escapeHtml(c.name)}</span>
        <span class="count">${done}/${c.tests.length}</span>
      </button>`;
    }).join('');
    nav.querySelectorAll('.nav-sub').forEach(el=>{
      el.addEventListener('click', ()=>{ closeSidebar(); openCategory(el.dataset.cat); });
    });
    const label = document.getElementById('categoryToggleLabel');
    if(label) label.textContent = currentFramework === 'llm-security' ? 'OWASP LLM Top 10' : 'OWASP WSTG';
  }

  function renderDashboard(){
    const s = stats();
    document.getElementById('ringFill').style.background =
      `conic-gradient(var(--accent) 0 ${s.pct}%, var(--track) ${s.pct}% 100%)`;
    document.getElementById('ringPct').textContent = s.pct + '%';
    const progressSub = document.getElementById('progressSub');
    if(progressSub){
      progressSub.textContent = currentSession
        ? `${currentSession.name} · ${s.done}/${s.total}`
        : `${t('sessionLocalMode')} · ${s.done}/${s.total}`;
    }
    document.getElementById('statDone').textContent = s.done;
    document.getElementById('statPending').textContent = s.pending;
    document.getElementById('statCategories').textContent = s.categories;
    document.getElementById('statTotal').textContent = s.total;

    const grid = document.getElementById('categoriesGrid');
    grid.innerHTML = getEffectiveCategories().map(c => {
      const done = c.tests.filter(t => progress[t.id]).length;
      const pct = c.tests.length ? Math.round((done/c.tests.length)*100) : 0;
      return `<div class="category-card ${pct===100?'done-all':''}" data-cat="${c.id}" tabindex="0" role="button">
        <div class="cc-top">
          <span class="cc-ico">${icon(c.icon)}</span>
          <span class="badge">${escapeHtml(c.code)}</span>
        </div>
        <h4>${escapeHtml(c.name)}</h4>
        <p>${escapeHtml(c.description || '')}</p>
        <div class="cat-progress-row">
          <div class="cat-progress-bar"><div class="cat-progress-fill" style="width:${pct}%"></div></div>
          <div class="cat-progress-text">${done}/${c.tests.length}</div>
        </div>
      </div>`;
    }).join('');
    grid.querySelectorAll('.category-card').forEach(el=>{
      el.addEventListener('click', ()=> openCategory(el.dataset.cat));
      el.addEventListener('keydown', e=>{ if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); openCategory(el.dataset.cat); } });
    });
  }

  function escapeHtml(s){
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }

  // ---------------------------------------------------------------------
  // Checklist: solda test listesi, sağda seçili testin detayı.
  // Not alanı yazarken otomatik kaydedilir (scheduleFindingSave); bu yüzden
  // kullanıcı not yazarken detay paneli yeniden çizilmez, sadece durum
  // rozetleri güncellenir (bkz. renderTestList -> updateDetailStatus).
  // ---------------------------------------------------------------------
  let selectedTestId = null;
  const inflightFindingSaves = {}; // test_id -> devam eden kayıt isteği sayısı
  let visibleTestIds = [];

  const detailIcons = {
    desc: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
    steps: '<path d="M10 6h10M10 12h10M10 18h10"/><path d="M4 6h1M4 12h1M4 18h1"/>',
    example: '<path d="m4 17 6-5-6-5"/><path d="M12 19h8"/>',
    tools: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/>',
    notes: '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1M9 10h6M9 14h6M9 18h3"/>',
    chev: '<path d="m9 6 6 6-6 6"/>',
    back: '<path d="m15 6-6 6 6 6"/>',
    check: '<path d="m5 12 4.5 4.5L19 7"/>'
  };
  function dIcon(name, cls){
    return `<svg class="i ${cls||''}" viewBox="0 0 24 24">${detailIcons[name]}</svg>`;
  }

  function findTestInCurrentCategory(id){
    const cat = getEffectiveCategories().find(c=>c.id===currentCategoryId);
    return cat ? cat.tests.find(x => x.id === id) : null;
  }

  // Liste satırındaki durum etiketi: not varsa önem derecesi, yoksa tamamlandı/bekliyor.
  function testStatusBadge(test){
    const fd = getFindingData(test.id);
    if(fd.text && fd.text.trim()){
      return `<span class="severity-badge sev-${fd.severity || 'info'}">${t('severity_' + (fd.severity || 'info'))}</span>`;
    }
    return progress[test.id]
      ? `<span class="badge green">${t('statusDoneLabel')}</span>`
      : `<span class="badge">${t('statusPendingLabel')}</span>`;
  }

  function renderTestRow(test){
    const done = !!progress[test.id];
    const rp = reconPriority[test.id];
    const selected = test.id === selectedTestId;
    return `<div class="test-row-item ${done?'done':''} ${selected?'selected':''}" data-id="${escapeHtml(test.id)}" role="option" aria-selected="${selected}" tabindex="-1">
      <button type="button" class="test-check ${done?'checked':''}" data-id="${escapeHtml(test.id)}" title="${t('testEditedTitle')}" aria-label="${t('testEditedTitle')}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M4 12l5 5L20 6"/></svg>
      </button>
      <div class="tri-body">
        <div class="tri-top">
          <span class="test-item-code">${escapeHtml(test.id)}</span>
          <span class="tri-badges">
            ${rp ? `<span class="recon-priority-badge prio-${rp.level}" title="${escapeHtml((rp.reasons||[]).join(' · '))}">${t('reconPriorityBadge_'+rp.level)}</span>` : ''}
            ${testStatusBadge(test)}
          </span>
        </div>
        <div class="tri-title">${escapeHtml(test.title)}</div>
      </div>
      ${dIcon('chev', 'tri-chev')}
    </div>`;
  }

  // Backend zaman damgaları UTC'dir ama saat dilimi eki taşımaz; ek yoksa 'Z' eklenir.
  function parseApiDate(value){
    if(!value) return null;
    const str = String(value);
    const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(str) ? str : str + 'Z');
    return isNaN(d) ? null : d;
  }

  function lastUpdatedFor(testId){
    if(currentSession){
      const r = sessionResults[testId];
      return r && (r.updated_at || r.completed_at);
    }
    const f = findings[testId];
    return f && f.updatedAt;
  }

  function renderTestDetail(){
    const box = document.getElementById('testDetail');
    const test = selectedTestId ? findTestInCurrentCategory(selectedTestId) : null;
    if(!test){
      box.innerHTML = `<div class="empty-state"><h3>${t('selectTestTitle')}</h3><p>${t('selectTestHint')}</p></div>`;
      box.dataset.id = '';
      renderDetailFoot(null);
      return;
    }
    const fd = getFindingData(test.id);
    const steps = test.steps || [];
    const tools = test.tools || [];
    box.dataset.id = test.id;
    box.innerHTML = `
      <button type="button" class="btn btn-ghost btn-sm detail-back" data-action="back">${dIcon('back')}<span>${t('backToTests')}</span></button>
      <div class="detail-head">
        <div class="detail-head-text">
          <div class="detail-code">${escapeHtml(test.id)}</div>
          <h2 class="detail-title">${escapeHtml(test.title)}</h2>
        </div>
        <div class="detail-badges" id="detailBadges"></div>
      </div>
      ${test.description ? `
      <div class="detail-section">
        ${dIcon('desc', 'ds-ico')}
        <div class="ds-body"><h5>${t('descriptionLabel')}</h5><p>${escapeHtml(test.description)}</p></div>
      </div>` : ''}
      ${steps.length ? `
      <div class="detail-section">
        ${dIcon('steps', 'ds-ico')}
        <div class="ds-body"><h5>${t('howToLabel')}</h5>
          <ol class="step-list">${steps.map(s=>`<li>${escapeHtml(s)}</li>`).join('')}</ol>
        </div>
      </div>` : ''}
      ${test.example ? `
      <div class="detail-section">
        ${dIcon('example', 'ds-ico')}
        <div class="ds-body">
          <div class="ds-head-row"><h5>${t('exampleLabel')}</h5>
            <button type="button" class="btn btn-secondary btn-xs copy-btn" data-copy="${encodeURIComponent(test.example)}">${t('copyBtn')}</button>
          </div>
          <div class="example-box">${escapeHtml(test.example)}</div>
        </div>
      </div>` : ''}
      ${tools.length ? `
      <div class="detail-section">
        ${dIcon('tools', 'ds-ico')}
        <div class="ds-body"><h5>${t('toolsLabel')}</h5>
          <div class="tools-row">${tools.map(tool=>`<span class="tool-chip">${escapeHtml(tool)}</span>`).join('')}</div>
        </div>
      </div>` : ''}
      <div class="detail-section finding-block">
        ${dIcon('notes', 'ds-ico')}
        <div class="ds-body">
          <div class="ds-head-row">
            <h5>${t('findingsLabel')}</h5>
            ${dbOnline && currentSession ? `<button type="button" class="btn btn-secondary btn-xs" data-action="add-note" data-id="${escapeHtml(test.id)}"><svg class="i"><use href="#ic-note"/></svg><span>${escapeHtml(t('noteAddForTest'))}</span></button>` : ''}
            <label class="severity-field">
              <span>${t('severityLabel')}</span>
              <select class="severity-select" data-id="${escapeHtml(test.id)}">
                ${SEVERITIES.map(s=>`<option value="${s}" ${fd.severity===s?'selected':''}>${t('severity_'+s)}</option>`).join('')}
              </select>
            </label>
          </div>
          <textarea class="finding-textarea" data-id="${escapeHtml(test.id)}" rows="4" placeholder="${t('findingsPlaceholder')}">${escapeHtml(fd.text)}</textarea>
          <div class="hint">${t('notesAutosaveHint')}</div>
        </div>
      </div>`;
    box.scrollTop = 0;
    updateDetailStatus();
    refreshNoteButtons();
  }

  function renderDetailFoot(test){
    const foot = document.getElementById('testDetailFoot');
    if(!test){ foot.innerHTML = ''; foot.style.display = 'none'; return; }
    foot.style.display = '';
    const done = !!progress[test.id];
    const updated = parseApiDate(lastUpdatedFor(test.id));
    const idx = visibleTestIds.indexOf(test.id);
    foot.innerHTML = `
      <div class="foot-meta">
        ${updated ? `<span>${t('lastUpdatedLabel')}: ${escapeHtml(updated.toLocaleString(t('dateLocale'), {dateStyle:'medium', timeStyle:'short'}))}</span><span class="foot-sep"></span>` : ''}
        <span>${t('statusLabel')}: ${done ? t('statusDoneLabel') : t('statusPendingLabel')}</span>
        <span class="finding-status" data-id="${escapeHtml(test.id)}"></span>
      </div>
      <div class="foot-actions">
        <span class="foot-nav">
          <button type="button" class="icon-btn sm bordered" data-action="prev" ${idx <= 0 ? 'disabled' : ''} title="${t('prevTest')}">${dIcon('back')}</button>
          <button type="button" class="icon-btn sm bordered" data-action="next" ${idx < 0 || idx >= visibleTestIds.length - 1 ? 'disabled' : ''} title="${t('nextTest')}">${dIcon('chev')}</button>
        </span>
        <button type="button" class="btn ${done ? 'btn-secondary is-done' : 'btn-primary'}" data-action="toggle-done" data-id="${escapeHtml(test.id)}">
          ${dIcon('check')}<span>${done ? t('completedUndoBtn') : t('completeTestBtn')}</span>
        </button>
      </div>`;
  }

  // Not/önem/tamamlanma değiştiğinde detay panelini baştan çizmeden günceller.
  function updateDetailStatus(){
    const test = selectedTestId ? findTestInCurrentCategory(selectedTestId) : null;
    if(!test) return;
    const badges = document.getElementById('detailBadges');
    if(badges){
      const fd = getFindingData(test.id);
      const rp = reconPriority[test.id];
      badges.innerHTML =
        (rp ? `<span class="recon-priority-badge prio-${rp.level}">${t('reconPriorityBadge_'+rp.level)}</span>` : '') +
        (fd.text && fd.text.trim() ? `<span class="severity-badge sev-${fd.severity || 'info'}">${t('severity_' + (fd.severity || 'info'))}</span>` : '');
    }
    renderDetailFoot(test);
  }

  function selectTest(id, opts){
    opts = opts || {};
    if(selectedTestId && saveTimers[selectedTestId]){
      clearTimeout(saveTimers[selectedTestId]); delete saveTimers[selectedTestId];
      saveFinding(selectedTestId);
    }
    selectedTestId = id;
    document.querySelectorAll('#testList .test-row-item').forEach(row=>{
      const on = row.dataset.id === id;
      row.classList.toggle('selected', on);
      row.setAttribute('aria-selected', on);
      if(on && opts.scroll) row.scrollIntoView({block:'nearest'});
    });
    renderTestDetail();
    if(opts.showDetail) document.getElementById('checklistBody').classList.add('show-detail');
  }

  function stepSelection(delta){
    const idx = visibleTestIds.indexOf(selectedTestId);
    const next = visibleTestIds[idx + delta];
    if(next) selectTest(next, { scroll: true });
  }

  function openCategory(catId, focusTestId){
    const cat = getEffectiveCategories().find(c=>c.id===catId);
    if(!cat) return;
    currentCategoryId = catId;
    currentFilter = "all";
    sortByReconPriority = false;
    const sortBtn = document.getElementById('sortPriorityToggle');
    if(sortBtn) sortBtn.classList.remove('active');
    document.querySelectorAll('.filter-toggle button').forEach(b=>b.classList.toggle('active', b.dataset.filter === 'all'));
    document.getElementById('panelTitle').textContent = `${cat.code} · ${cat.name}`;
    document.getElementById('panelDesc').textContent = cat.description;
    document.getElementById('itemSearch').value = "";
    const guide = document.getElementById('openGuideBtn');
    if(guide) guide.style.display = currentFramework === 'wstg' ? '' : 'none';
    const focusExists = focusTestId && cat.tests.some(x => x.id === focusTestId);
    selectedTestId = focusExists ? focusTestId : (cat.tests[0] && cat.tests[0].id) || null;
    document.getElementById('checklistBody').classList.toggle('show-detail', !!focusExists);
    renderTestList({ forceDetail: true });
    document.getElementById('categoryOverlay').classList.add('open');
    document.body.style.overflow = 'hidden';
    renderSidebar();
    setTimeout(()=>{
      const row = document.querySelector(`#testList .test-row-item.selected`);
      if(row) row.scrollIntoView({block:'nearest'});
    }, 30);
  }

  function closeCategory(){
    const overlay = document.getElementById('categoryOverlay');
    const wasOpen = overlay.classList.contains('open');
    if(wasOpen && selectedTestId && saveTimers[selectedTestId]){
      clearTimeout(saveTimers[selectedTestId]); delete saveTimers[selectedTestId];
      saveFinding(selectedTestId);
    }
    overlay.classList.remove('open');
    document.body.style.overflow = '';
    if(wasOpen && DATA) renderSidebar();
  }

  function renderTestList(opts){
    opts = opts || {};
    const cat = getEffectiveCategories().find(c=>c.id===currentCategoryId);
    if(!cat) return;
    const q = document.getElementById('itemSearch').value.trim().toLowerCase();
    let items = cat.tests;
    if(currentFilter === 'done') items = items.filter(t=>progress[t.id]);
    if(currentFilter === 'pending') items = items.filter(t=>!progress[t.id]);
    if(q) items = items.filter(x => x.title.toLowerCase().includes(q) || x.id.toLowerCase().includes(q) || (x.description||'').toLowerCase().includes(q));
    // Varsayılan: resmi WSTG numaralandırma sırası korunur (JSON'daki sıra).
    // Recon önceliğine göre sıralama yalnızca "Önceliğe göre" seçildiğinde.
    if(sortByReconPriority){
      const prioOrder = { high: 3, medium: 2, low: 1, info: 0 };
      items = items.slice().sort((a, b) => {
        const pa = reconPriority[a.id] ? (prioOrder[reconPriority[a.id].level] ?? 0) + 1 : 0;
        const pb = reconPriority[b.id] ? (prioOrder[reconPriority[b.id].level] ?? 0) + 1 : 0;
        return pb - pa;
      });
    }
    visibleTestIds = items.map(x => x.id);
    document.getElementById('testListHead').textContent = t('testsCountLabel')(items.length, cat.tests.length);

    const prevSelected = selectedTestId;
    if(!visibleTestIds.includes(selectedTestId)) selectedTestId = visibleTestIds[0] || null;

    const list = document.getElementById('testList');
    list.innerHTML = items.length ? items.map(renderTestRow).join('') : `<div class="search-empty">${t('noMatchInCategory')}</div>`;

    // Kullanıcı not yazıyorsa detay panelini yeniden çizme (imleç/yazı kaybolmasın).
    const box = document.getElementById('testDetail');
    const typing = box.contains(document.activeElement) && document.activeElement.matches('textarea, select, input');
    const saving = selectedTestId && (saveTimers[selectedTestId] || inflightFindingSaves[selectedTestId]);
    if(!opts.forceDetail && selectedTestId === prevSelected && box.dataset.id === selectedTestId && (typing || saving)){
      updateDetailStatus();
    } else {
      renderTestDetail();
    }
  }

  function toggleDone(id){
    if(saveTimers[id]){ clearTimeout(saveTimers[id]); delete saveTimers[id]; saveFinding(id); }
    progress[id] = !progress[id];
    const done = progress[id];
    if(currentSession){
      persistResult(id, done).then(()=>{
        if(currentCategoryId && id === selectedTestId) updateDetailStatus();
      }).catch(err => {
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

  function closeSidebar(){
    const sb = document.getElementById('sidebar');
    if(sb) sb.classList.remove('open');
    const scrim = document.getElementById('sidebarScrim');
    if(scrim) scrim.classList.remove('open');
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
    const fallback = ()=>{
      try{
        const ta = document.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        showToast(ok ? t('copiedToast') : t('copyFailedToast'));
      }catch(e){ showToast(t('copyFailedToast')); }
    };
    if(navigator.clipboard && window.isSecureContext){
      navigator.clipboard.writeText(text).then(()=> showToast(t('copiedToast'))).catch(fallback);
    } else {
      fallback();
    }
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

  const BYOK_STORAGE_KEY = 'wstgAiByok';

  function loadByok(){
    try{
      const raw = sessionStorage.getItem(BYOK_STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    }catch(e){ return null; }
  }
  function saveByok(cfg){
    try{ sessionStorage.setItem(BYOK_STORAGE_KEY, JSON.stringify(cfg)); }catch(e){}
  }
  function clearByok(){
    try{ sessionStorage.removeItem(BYOK_STORAGE_KEY); }catch(e){}
  }
  // BYOK header'ları -- sadece o anki isteğe eklenir, hiçbir yere kaydedilmez.
  // Backend (ai/factory.get_ai_provider) bunları DB/​.env ayarlarının önüne
  // alır; header yoksa davranış tamamen eskisi gibi paylaşılan ayarla devam eder.
  function byokHeaders(){
    const cfg = loadByok();
    if(!cfg || !cfg.provider) return {};
    if(cfg.provider !== 'ollama' && !cfg.api_key) return {};
    const headers = { 'X-AI-Provider': cfg.provider };
    if(cfg.api_key) headers['X-AI-Api-Key'] = cfg.api_key;
    if(cfg.model) headers['X-AI-Model'] = cfg.model;
    if(cfg.base_url) headers['X-AI-Base-Url'] = cfg.base_url;
    return headers;
  }

  // AI çağrıları (Gemini/OpenAI/Anthropic/Ollama'ya giden istekler) bazen
  // ağ/sağlayıcı tarafında yavaşlayabilir ya da tamamen takılabilir. fetch()
  // tek başına bunun için bir zaman aşımı uygulamaz -- bu yüzden AI
  // endpoint'lerine giden istekleri burada AbortController ile sınırlıyoruz;
  // böylece arayüz "AI çalışıyor…" ekranında sonsuza kadar takılı kalmak
  // yerine, makul bir sürede net bir hata gösterir.
  const AI_REQUEST_UI_TIMEOUT_MS = 45000;

  function apiRequest(path, options){
    options = options || {};
    const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
    const isAiPath = path.indexOf('/ai/') !== -1 || path.indexOf('/ai-') !== -1;
    if(isAiPath){
      Object.assign(headers, byokHeaders());
    }

    let signal = options.signal;
    let timeoutId = null;
    if(isAiPath && typeof AbortController !== 'undefined' && !signal){
      const ctrl = new AbortController();
      signal = ctrl.signal;
      timeoutId = setTimeout(()=> ctrl.abort(), AI_REQUEST_UI_TIMEOUT_MS);
    }

    return fetch(API_BASE + path, Object.assign({}, options, { headers, signal, credentials: 'include' })).then(async res => {
      if(timeoutId) clearTimeout(timeoutId);
      if(!res.ok){
        let msg = res.statusText;
        let body = null;
        try{ body = await res.json(); msg = body.error || msg; }catch(e){}
        if(window.WSTGAuth.isSessionLost(res.status, body)) handleSessionLost();
        const err = new Error(msg);
        err.status = res.status;
        err.body = body;
        throw err;
      }
      if(res.status === 204) return null;
      return res.json();
    }).catch(err => {
      if(timeoutId) clearTimeout(timeoutId);
      if(err && err.name === 'AbortError'){
        throw new Error(t('aiRequestTimeout'));
      }
      throw err;
    });
  }

  // apiRequest JSON beklemeyen çağrılar (blob/text/FormData) için: çerezi
  // gönderir, oturum düştüyse giriş ekranını açar, yanıtı olduğu gibi döndürür.
  function apiFetch(path, options){
    return fetch(API_BASE + path, Object.assign({}, options, { credentials: 'include' })).then(res => {
      if(res.status === 401){
        res.clone().json().then(body => {
          if(window.WSTGAuth.isSessionLost(res.status, body)) handleSessionLost();
        }).catch(()=>{});
      }
      return res;
    });
  }

  // Backend var mı ve oturum durumu ne? Backend yoksa null döner (yerel mod).
  // /auth/status giriş istemeyen tek okuma ucudur; /sessions artık 401 döner.
  function checkDb(){
    const ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = ctrl ? setTimeout(()=>ctrl.abort(), 2500) : null;
    return fetch(API_BASE + '/auth/status', { signal: ctrl ? ctrl.signal : undefined, credentials: 'include' })
      .then(res => { clearTimeout(timer); return res.ok ? res.json() : null; })
      .catch(() => { clearTimeout(timer); return null; });
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
    if(!currentSession || sessionNotesFor !== currentSession.id){ sessionNotes = []; sessionNotesFor = null; }
    updateStudyGroupBodyClass();
    const chip = document.getElementById('sessionChip');
    const topName = document.getElementById('topbarSessionName');
    const topBtn = document.getElementById('topbarSessionBtn');
    if(currentSession){
      const done = Object.values(sessionResults).filter(r => r.status && r.status !== 'pending').length;
      const total = allTests().length;
      if(chip){
        chip.style.display = 'flex';
        document.getElementById('sessionChipName').textContent = currentSession.name;
        const group = currentSession.study_group;
        document.getElementById('sessionChipSub').textContent = `${done}/${total}` +
          (group === 'ai_assisted' || group === 'control' ? ' · ' + t('studyGroupBadge_' + group) : '');
      }
      if(topName) topName.textContent = currentSession.name;
      if(topBtn) topBtn.classList.remove('placeholder');
    } else {
      if(chip) chip.style.display = 'none';
      if(topName) topName.textContent = dbOnline ? t('ctxNoSession') : t('sessionLocalMode');
      if(topBtn) topBtn.classList.add('placeholder');
    }
    const badge = document.getElementById('dbBadge');
    if(badge){
      badge.className = 'scope-badge ' + (dbOnline ? 'verified' : 'unverified');
      badge.textContent = dbOnline ? t('dbBadgeOnline') : t('dbBadgeOffline');
      badge.title = dbOnline ? t('dbOnline') : t('dbOffline');
    }
    renderProgressSub();
    const avatar = document.getElementById('avatar');
    if(avatar){
      const name = (currentSession && currentSession.tester_name) || '';
      const initials = name.trim().split(/\s+/).filter(Boolean).slice(0,2).map(w => w[0].toLocaleUpperCase(t('dateLocale'))).join('');
      avatar.textContent = initials || 'PW';
      avatar.title = name || 'Pentest Workspace';
    }
  }

  function renderProgressSub(){
    const el = document.getElementById('progressSub');
    if(!el || !DATA) return;
    const s = stats();
    el.textContent = `${currentSession ? currentSession.name : t('sessionLocalMode')} · ${s.done}/${s.total}`;
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
        syncProjectFromSession(session);
        reloadReconContext();
        renderSidebar(); renderDashboard();
        if(currentCategoryId) renderTestList();
        updateSessionUI();
        closeSessionGate();
        loadSessionNotes().catch(()=>{});
      });
  }

  // Bir projeye bağlı oturum açıldığında üst çubuktaki proje bağlamını da
  // o projeye getirir (oturum projesiz ise mevcut proje bağlamına dokunmaz).
  function syncProjectFromSession(session){
    if(!session || !session.project_id || session.project_id === currentProjectId) return;
    apiRequest(`/projects/${session.project_id}`).then(project => {
      if(!currentSession || currentSession.id !== session.id) return;
      currentProjectId = project.id;
      currentProjectObj = project;
      updateProjectChip();
      reloadReconContext();
      return apiRequest(`/projects/${project.id}/custom-tests`).then(items => {
        customTests = items || [];
        renderSidebar(); renderDashboard();
      });
    }).catch(()=>{});
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
              <div class="session-card-name">${escapeHtml(s.name)} ${studyGroupBadge(s.study_group)}</div>
              <div class="session-card-meta">
                <span>${escapeHtml(s.tester_name || '—')}</span>
                <span>${escapeHtml(s.target_url || '—')}</span>
                <span>${new Date(s.created_at).toLocaleString(t('dateLocale'))}</span>
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
            ${s.status === 'completed'
              ? `<button data-action="reopen" data-id="${s.id}">${t('sessionReopenBtn')}</button>`
              : `<button data-action="complete" data-id="${s.id}">${t('sessionCompleteBtn')}</button>`}
            <button data-action="delete" data-id="${s.id}" class="danger">${t('pwEvidenceDelete')}</button>
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
    document.getElementById('studyGroupSelect').value = '';
    document.getElementById('studyGroupHint').textContent = '';
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
      target_url: document.getElementById('targetUrlInput').value.trim(),
      study_group: document.getElementById('studyGroupSelect').value || null
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
        reloadReconContext();
        renderSidebar(); renderDashboard();
        updateSessionUI();
      }
      renderSessionList();
      showToast(t('sessionDeleted'));
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  function setSessionStatusUI(id, status){
    apiRequest(`/sessions/${id}`, { method: 'PUT', body: JSON.stringify({ status }) }).then(session => {
      if(currentSession && currentSession.id === id){ currentSession = session; updateSessionUI(); }
      renderSessionList();
      showToast(t(status === 'completed' ? 'sessionCompletedToast' : 'sessionReopenedToast'));
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  // ========================
  // ÇALIŞMA GRUBU (A/B) + NOT DEFTERİ
  // ========================
  const NB = window.WSTGNotebook;
  let sessionNotes = [];
  let sessionNotesFor = null;      // sessionNotes hangi oturuma ait
  let noteEditorImages = [];
  let noteAiResult = null;
  let noteCvssTimer = null;
  let noteCweToken = 0;

  function isControlSession(){
    return !!(currentSession && currentSession.study_group === 'control');
  }
  // Kontrol grubundaki oturum açıkken .ai-feature işaretli öğeler gizlenir (CSS).
  function updateStudyGroupBodyClass(){
    document.body.classList.toggle('study-control-mode', isControlSession());
  }
  function studyGroupBadge(group){
    if(group !== 'ai_assisted' && group !== 'control') return '';
    return `<span class="badge ${group === 'control' ? '' : 'blue'}">${escapeHtml(t('studyGroupBadge_' + group))}</span>`;
  }
  function safeSeverity(s){ return SEVERITIES.indexOf(s) !== -1 ? s : 'info'; }

  function testOptionsHtml(selectedId, firstOption){
    let html = firstOption || '';
    getEffectiveCategories().forEach(c => {
      html += `<optgroup label="${escapeHtml(c.code + ' · ' + c.name)}">` +
        c.tests.map(tt => `<option value="${escapeHtml(tt.id)}" ${tt.id === selectedId ? 'selected' : ''}>${escapeHtml(tt.id)} — ${escapeHtml(tt.title)}</option>`).join('') +
        `</optgroup>`;
    });
    return html;
  }

  function loadSessionNotes(){
    if(!currentSession || !dbOnline){ sessionNotes = []; sessionNotesFor = null; return Promise.resolve([]); }
    const sid = currentSession.id;
    return apiRequest(`/sessions/${sid}/notes`).then(notes => {
      if(!currentSession || currentSession.id !== sid) return sessionNotes;
      sessionNotes = Array.isArray(notes) ? notes : [];
      sessionNotesFor = sid;
      refreshNoteButtons();
      return sessionNotes;
    });
  }

  function notesForTest(testId){
    return currentSession && sessionNotesFor === currentSession.id ? sessionNotes.filter(n => n.test_id === testId) : [];
  }

  // Checklist detayındaki "Not ekle" düğmesinin sayacını günceller.
  function refreshNoteButtons(){
    document.querySelectorAll('#testDetail [data-action="add-note"]').forEach(btn => {
      const n = notesForTest(btn.dataset.id).length;
      btn.querySelector('span').textContent = n ? `${t('noteAddForTest')} · ${t('noteCountForTest')(n)}` : t('noteAddForTest');
    });
  }

  function noteCardHtml(n){
    const sev = safeSeverity(n.severity);
    const info = n.test_id ? testInfoById(n.test_id) : null;
    const images = NB.safeImages(n.images);
    const fp = n.is_false_positive === true ? `<span class="badge red">${escapeHtml(t('noteFpFalse'))}</span>`
      : n.is_false_positive === false ? `<span class="badge green">${escapeHtml(t('noteFpValid'))}</span>` : '';
    const when = parseApiDate(n.updated_at || n.created_at);
    return `<div class="finding-card note-card" data-id="${Number(n.id)}">
      <div class="finding-card-top">
        <span class="severity-badge sev-${sev}">${escapeHtml(t('severity_' + sev))}</span>
        ${typeof n.cvss_score === 'number' ? `<span class="cvss-mini-badge">CVSS ${n.cvss_score.toFixed(1)}</span>` : ''}
        ${n.cwe_id ? `<span class="badge mono">${escapeHtml(n.cwe_id)}</span>` : ''}
        ${fp}
        <span class="note-card-test">${n.test_id
          ? `<span class="badge mono" title="${escapeHtml(info ? info.title : '')}">${escapeHtml(n.test_id)}</span>`
          : `<span class="badge">${escapeHtml(t('noteGeneralBadge'))}</span>`}</span>
      </div>
      <div class="finding-card-title">${escapeHtml(n.title && n.title.trim() ? n.title : t('noteUntitled'))}</div>
      ${n.content ? `<div class="note-card-content">${escapeHtml(n.content)}</div>` : ''}
      ${images.length ? `<div class="note-thumbs">${images.map((img, i) => `
        <button type="button" class="note-thumb" data-action="zoom" data-id="${Number(n.id)}" data-idx="${i}" title="${escapeHtml(img.name || '')}">
          <img src="${escapeHtml(img.data)}" alt="${escapeHtml(img.name || '')}" loading="lazy">
        </button>`).join('')}</div>` : ''}
      <div class="finding-card-meta">
        ${when ? `<span>${escapeHtml(when.toLocaleString(t('dateLocale'), { dateStyle: 'medium', timeStyle: 'short' }))}</span>` : ''}
        ${n.cwe_name ? `<span>${escapeHtml(n.cwe_name)}</span>` : ''}
      </div>
      <div class="project-card-actions">
        <button data-action="edit" data-id="${Number(n.id)}">${escapeHtml(t('editBtn'))}</button>
      </div>
    </div>`;
  }

  function renderNotebookList(){
    const list = document.getElementById('notebookList');
    const filter = document.getElementById('notebookTestFilter').value;
    const q = document.getElementById('notebookSearch').value;
    const notes = NB.filterNotes(sessionNotes, filter, q);
    if(!notes.length){
      list.innerHTML = `<div class="search-empty">${escapeHtml(t(sessionNotes.length ? 'noteEmptyFiltered' : 'noteEmptyList'))}</div>`;
      return;
    }
    list.innerHTML = notes.map(noteCardHtml).join('');
  }

  function openNotebook(){
    if(!dbOnline){ showToast(t('notebookNeedBackend')); return; }
    if(!currentSession){ showToast(t('notebookNeedSession')); openSessionGate(true); return; }
    document.getElementById('notebookDesc').textContent = t('notebookDesc')(currentSession.name);
    document.getElementById('notebookSearch').value = '';
    document.getElementById('notebookTestFilter').innerHTML =
      `<option value="">${escapeHtml(t('notebookFilterAll'))}</option><option value="__general__">${escapeHtml(t('notebookFilterGeneral'))}</option>` +
      testOptionsHtml(null);
    document.getElementById('notebookList').innerHTML = `<div class="search-empty">${escapeHtml(t('loadingGeneric'))}</div>`;
    document.getElementById('notebookOverlay').classList.add('open');
    loadSessionNotes().then(renderNotebookList).catch(err => {
      document.getElementById('notebookList').innerHTML = `<div class="search-empty">${escapeHtml(err.message || t('resultSaveError'))}</div>`;
    });
  }
  function closeNotebook(){ document.getElementById('notebookOverlay').classList.remove('open'); }

  function setNoteStatus(msg, isError){
    const el = document.getElementById('noteEditorStatus');
    el.textContent = msg || '';
    el.classList.toggle('is-info', !!msg && !isError);
  }

  function renderNoteThumbs(){
    document.getElementById('noteImageThumbs').innerHTML = noteEditorImages.map((img, i) => `
      <div class="note-thumb">
        <img src="${escapeHtml(img.data)}" alt="${escapeHtml(img.name || '')}">
        <button type="button" class="note-thumb-remove" data-idx="${i}" aria-label="${escapeHtml(t('noteImageRemove'))}" title="${escapeHtml(t('noteImageRemove'))}">&times;</button>
      </div>`).join('');
    document.getElementById('noteImageHint').textContent = t('noteImageHint')(noteEditorImages.length, NB.MAX_IMAGES);
  }

  function readImageFile(file){
    return new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve({ name: file.name || 'kanit', data: String(reader.result || '') });
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(file);
    });
  }

  function addNoteImages(files){
    const arr = Array.from(files || []).filter(Boolean);
    if(!arr.length) return;
    let errKey = null;
    const accepted = [];
    arr.forEach(f => {
      const e = NB.imageFileError(f);
      if(e) errKey = e === 'size' ? 'noteImageSizeError' : 'noteImageTypeError';
      else accepted.push(f);
    });
    const room = NB.MAX_IMAGES - noteEditorImages.length;
    if(accepted.length > room){ accepted.length = Math.max(room, 0); errKey = 'count'; }
    Promise.all(accepted.map(readImageFile)).then(results => {
      results.forEach(r => {
        if(!r || !NB.isSafeImageDataUrl(r.data)){ errKey = errKey || 'noteImageReadError'; return; }
        if(NB.payloadChars(noteEditorImages) + r.data.length > NB.MAX_PAYLOAD_CHARS){ errKey = 'noteImagePayloadError'; return; }
        noteEditorImages.push(r);
      });
      renderNoteThumbs();
      if(errKey === 'count') setNoteStatus(t('noteImageCountError')(NB.MAX_IMAGES), true);
      else setNoteStatus(errKey ? t(errKey) : '', !!errKey);
    });
  }

  function renderNoteCweSuggestions(testId){
    const wrap = document.getElementById('noteCweSuggestions');
    const token = ++noteCweToken;
    wrap.innerHTML = '';
    if(!testId || !dbOnline) return;
    apiRequest(`/mapping/wstg/${encodeURIComponent(testId)}?lang=${currentLang}`).then(res => {
      if(token !== noteCweToken) return;
      const cwes = (res && Array.isArray(res.suggested_cwes) ? res.suggested_cwes : []).filter(c => c && c.id).slice(0, 8);
      if(!cwes.length) return;
      wrap.innerHTML = `<span class="hint">${escapeHtml(t('noteCweSuggested')(testId))}</span>` + cwes.map(c =>
        `<button type="button" class="badge mono note-chip" data-cwe-id="${escapeHtml(c.id)}" data-cwe-name="${escapeHtml(c.name || '')}">${escapeHtml(c.id)}${c.name ? ' · ' + escapeHtml(c.name) : ''}</button>`).join('');
    }).catch(()=>{});
  }

  function updateNoteCvssPreview(){
    const el = document.getElementById('noteCvssPreview');
    const vector = document.getElementById('noteCvssInput').value.trim();
    clearTimeout(noteCvssTimer);
    el.classList.remove('invalid');
    if(!vector){ el.textContent = '–'; return; }
    const metrics = NB.parseCvssVector(vector);
    if(!metrics){ el.textContent = t('noteCvssInvalid'); el.classList.add('invalid'); return; }
    noteCvssTimer = setTimeout(() => {
      apiRequest('/cvss/calculate', { method: 'POST', body: JSON.stringify(metrics) }).then(r => {
        if(document.getElementById('noteCvssInput').value.trim() !== vector) return;
        el.textContent = `${Number(r.base_score).toFixed(1)} · ${t('severity_' + safeSeverity(r.severity))}`;
      }).catch(() => {
        if(document.getElementById('noteCvssInput').value.trim() !== vector) return;
        el.textContent = t('noteCvssInvalid'); el.classList.add('invalid');
      });
    }, 250);
  }

  function openNoteEditor(note, prefillTestId){
    if(!dbOnline){ showToast(t('notebookNeedBackend')); return; }
    if(!currentSession){ showToast(t('notebookNeedSession')); openSessionGate(true); return; }
    document.getElementById('noteEditorForm').reset();
    setNoteStatus('');
    const linked = note ? (note.test_id || '') : (prefillTestId || '');
    document.getElementById('noteEditId').value = note ? note.id : '';
    document.getElementById('noteEditorTitle').textContent = t(note ? 'editNote' : 'newNote');
    document.getElementById('noteTitleInput').value = note ? (note.title || '') : '';
    document.getElementById('noteContentInput').value = note ? (note.content || '') : '';
    document.getElementById('noteSeveritySelect').innerHTML = SEVERITIES.map(s =>
      `<option value="${s}">${escapeHtml(t('severity_' + s))}</option>`).join('');
    document.getElementById('noteSeveritySelect').value = safeSeverity(note ? note.severity : 'info');
    document.getElementById('noteFpSelect').value = NB.fpToSelect(note ? note.is_false_positive : null);
    document.getElementById('noteTestSelect').innerHTML = testOptionsHtml(linked, `<option value="">${escapeHtml(t('noteGeneralOption'))}</option>`);
    document.getElementById('noteTestSelect').value = linked;
    const original = note && Array.isArray(note.images) ? note.images : [];
    noteEditorImages = NB.safeImages(original).map(img => ({ name: img.name || 'kanit', data: img.data }));
    renderNoteThumbs();
    if(original.length > noteEditorImages.length) setNoteStatus(t('noteUnsafeImagesDropped')(original.length - noteEditorImages.length));
    document.getElementById('noteCweIdInput').value = note ? (note.cwe_id || '') : '';
    document.getElementById('noteCweNameInput').value = note ? (note.cwe_name || '') : '';
    renderNoteCweSuggestions(linked);
    document.getElementById('noteCvssInput').value = note ? (note.cvss_vector || '') : '';
    updateNoteCvssPreview();
    noteAiResult = null;
    document.getElementById('noteAiResult').hidden = true;
    document.getElementById('noteAiStatus').textContent = '';
    document.getElementById('deleteNoteBtn').style.display = note ? '' : 'none';
    document.getElementById('noteEditorOverlay').classList.add('open');
    setTimeout(() => document.getElementById(note ? 'noteContentInput' : 'noteTitleInput').focus(), 50);
  }
  function closeNoteEditor(){ document.getElementById('noteEditorOverlay').classList.remove('open'); }

  function afterNotesChanged(toastKey){
    return loadSessionNotes().then(() => {
      if(document.getElementById('notebookOverlay').classList.contains('open')) renderNotebookList();
      closeNoteEditor();
      showToast(t(toastKey));
    });
  }

  function saveNoteFromEditor(e){
    if(e) e.preventDefault();
    if(!currentSession) return;
    const id = document.getElementById('noteEditId').value;
    const testId = document.getElementById('noteTestSelect').value || null;
    const info = testId ? testInfoById(testId) : null;
    const payload = {
      title: document.getElementById('noteTitleInput').value.trim(),
      content: document.getElementById('noteContentInput').value.trim(),
      severity: document.getElementById('noteSeveritySelect').value,
      test_id: testId,
      category_id: info ? info.catId : null,
      images: noteEditorImages,
      cwe_id: document.getElementById('noteCweIdInput').value.trim() || null,
      cwe_name: document.getElementById('noteCweNameInput').value.trim() || null,
      cvss_vector: document.getElementById('noteCvssInput').value.trim() || null,
      is_false_positive: NB.selectToFp(document.getElementById('noteFpSelect').value),
    };
    if(!payload.content && !payload.images.length){ setNoteStatus(t('noteContentRequired'), true); return; }
    const btn = document.getElementById('saveNoteBtn');
    btn.disabled = true;
    const base = `/sessions/${currentSession.id}/notes`;
    apiRequest(id ? `${base}/${encodeURIComponent(id)}` : base, { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) })
      .then(() => afterNotesChanged('noteSaved'))
      .catch(err => setNoteStatus(err.message || t('resultSaveError'), true))
      .finally(() => { btn.disabled = false; });
  }

  function deleteNoteFromEditor(){
    const id = document.getElementById('noteEditId').value;
    if(!id || !currentSession || !confirm(t('noteDeleteConfirm'))) return;
    apiRequest(`/sessions/${currentSession.id}/notes/${encodeURIComponent(id)}`, { method: 'DELETE' })
      .then(() => afterNotesChanged('noteDeleted'))
      .catch(err => setNoteStatus(err.message || t('resultSaveError'), true));
  }

  function renderNoteAiResult(r){
    const box = document.getElementById('noteAiResult');
    noteAiResult = r;
    const rows = [];
    if(r.rationale) rows.push(`<p><b>${escapeHtml(t('noteAiRationale'))}:</b> ${escapeHtml(r.rationale)}</p>`);
    if(['low', 'medium', 'high'].indexOf(r.false_positive_likelihood) !== -1){
      rows.push(`<p><b>${escapeHtml(t('noteAiFp'))}:</b> ${escapeHtml(t('fpLikelihood_' + r.false_positive_likelihood))}` +
        `${r.false_positive_reasoning ? ' — ' + escapeHtml(r.false_positive_reasoning) : ''}</p>`);
    }
    const suggestion = (label, value, kind) => `<div class="note-ai-row"><span><b>${escapeHtml(label)}:</b> ${value}</span>` +
      `<button type="button" class="btn btn-secondary btn-xs" data-apply="${kind}">${escapeHtml(t('noteAiApply'))}</button></div>`;
    if(r.suggested_cwe_id) rows.push(suggestion(t('noteAiSuggestCwe'), escapeHtml(r.suggested_cwe_id + (r.suggested_cwe_name ? ' · ' + r.suggested_cwe_name : '')), 'cwe'));
    if(SEVERITIES.indexOf(r.suggested_severity) !== -1) rows.push(suggestion(t('noteAiSuggestSeverity'), escapeHtml(t('severity_' + r.suggested_severity)), 'severity'));
    if(r.suggested_cvss_vector) rows.push(suggestion(t('noteAiSuggestCvss'),
      `<code>${escapeHtml(r.suggested_cvss_vector)}</code>${typeof r.suggested_cvss_score === 'number' ? ' · ' + r.suggested_cvss_score.toFixed(1) : ''}`, 'cvss'));
    box.innerHTML = rows.length ? rows.join('') : `<p>${escapeHtml(t('noteAiNoSuggestion'))}</p>`;
    box.hidden = false;
  }

  function applyNoteAiSuggestion(kind){
    const r = noteAiResult;
    if(!r) return;
    if(kind === 'cwe'){
      document.getElementById('noteCweIdInput').value = r.suggested_cwe_id || '';
      document.getElementById('noteCweNameInput').value = r.suggested_cwe_name || '';
    } else if(kind === 'severity'){
      document.getElementById('noteSeveritySelect').value = safeSeverity(r.suggested_severity);
    } else if(kind === 'cvss'){
      document.getElementById('noteCvssInput').value = r.suggested_cvss_vector || '';
      updateNoteCvssPreview();
    }
    showToast(t('noteAiApplied'));
  }

  function analyzeNoteWithAI(){
    if(isControlSession() || !currentSession) return;
    const content = document.getElementById('noteContentInput').value.trim();
    if(!content){ setNoteStatus(t('noteContentRequired'), true); return; }
    const btn = document.getElementById('noteAiAnalyzeBtn');
    const status = document.getElementById('noteAiStatus');
    btn.disabled = true;
    status.textContent = t('aiWorking');
    apiRequest('/ai/analyze-finding', { method: 'POST', body: JSON.stringify({
      title: document.getElementById('noteTitleInput').value.trim(), content,
      test_id: document.getElementById('noteTestSelect').value || null,
      lang: currentLang, session_id: currentSession.id,
    }) }).then(r => {
      if(r && r.error){ status.textContent = r.error; return; }
      status.textContent = '';
      renderNoteAiResult(r || {});
    }).catch(err => { status.textContent = err.message || t('aiRequestTimeout'); })
      .finally(() => { btn.disabled = false; });
  }

  function openNoteLightbox(src, name){
    if(!NB.isSafeImageDataUrl(src)) return;
    const img = document.getElementById('noteLightboxImg');
    img.src = src;
    img.alt = name || '';
    document.getElementById('noteLightbox').classList.add('open');
  }
  function closeNoteLightbox(){
    document.getElementById('noteLightbox').classList.remove('open');
    document.getElementById('noteLightboxImg').removeAttribute('src');
  }

  // --- Çalışma Metrikleri ---
  function csvCell(v){
    let s = v === null || v === undefined ? '' : String(v);
    if(/^[=+\-@\t\r]/.test(s)) s = "'" + s;   // Excel formül enjeksiyonuna karşı
    return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }
  let lastStudyData = null;

  function studySessionsCsv(sessions){
    const cols = ['session_name', 'study_group', 'completion_minutes', 'total_tests', 'completed_tests', 'completion_pct',
      'total_findings', 'confirmed_false_positives', 'confirmed_valid_findings', 'undetermined_findings',
      'false_positive_rate_pct', 'ai_calls_total', 'ai_success_rate_pct', 'avg_ai_latency_ms', 'report_generated'];
    return [cols.join(',')].concat((sessions || []).map(s => cols.map(c => csvCell(s[c])).join(','))).join('\n');
  }

  function renderStudyMetrics(data){
    lastStudyData = data;
    const box = document.getElementById('studyMetricsContent');
    const cmp = (data && data.comparison) || {};
    const ai = cmp.ai_assisted || { n: 0 };
    const ctrl = cmp.control || { n: 0 };
    const unassigned = data && data.unassigned_sessions_count
      ? `<p class="hint">${escapeHtml(t('studyMetricsUnassigned')(data.unassigned_sessions_count))}</p>` : '';
    if(!ai.n && !ctrl.n){
      box.innerHTML = `<div class="search-empty">${escapeHtml(t('studyMetricsEmpty'))}</div>${unassigned}`;
      return;
    }
    const rows = NB.studyRows(cmp).map(r => `<tr>
        <th scope="row">${escapeHtml(t(r.labelKey))}</th><td>${r.ai}</td><td>${r.control}</td>
        <td>${r.diff ? `<span class="study-diff ${r.tone || ''}">${escapeHtml(r.diff)}</span>` : '–'}</td></tr>`).join('');
    const sessions = (data.sessions || []).map(s => `<tr>
        <th scope="row">${escapeHtml(s.session_name || '—')}</th><td>${studyGroupBadge(s.study_group)}</td>
        <td>${NB.formatStudyValue(s.completion_minutes)}</td><td>${NB.formatStudyValue(s.completion_pct)}</td>
        <td>${NB.formatStudyValue(s.total_findings)}</td><td>${NB.formatStudyValue(s.false_positive_rate_pct)}</td>
        <td>${NB.formatStudyValue(s.ai_calls_total)}</td></tr>`).join('');
    box.innerHTML = `
      <div class="table-wrap"><table class="table study-table">
        <thead><tr><th></th><th>${escapeHtml(t('studyMetricsColAi'))} <span class="hint">n=${Number(ai.n) || 0}</span></th>
          <th>${escapeHtml(t('studyMetricsColControl'))} <span class="hint">n=${Number(ctrl.n) || 0}</span></th><th>${escapeHtml(t('studyMetricsColDiff'))}</th></tr></thead>
        <tbody>${rows}
          <tr><th scope="row">${escapeHtml(t('studyMetricReportGenerated'))}</th><td>${NB.formatStudyValue(ai.pct_report_generated)}</td>
            <td>${NB.formatStudyValue(ctrl.pct_report_generated)}</td><td>–</td></tr>
        </tbody></table></div>
      <p class="hint">${escapeHtml(t('studyMetricsDiffNote'))}</p>
      ${unassigned}
      <div class="filter-bar" style="margin:22px 0 8px">
        <h5 style="margin:0;flex:1">${escapeHtml(t('studyMetricsSessions'))}</h5>
        <button type="button" class="btn btn-secondary btn-sm" id="studyCopyCsvBtn">${escapeHtml(t('studyMetricsCopyCsv'))}</button>
      </div>
      <div class="table-wrap"><table class="table study-table">
        <thead><tr><th>${escapeHtml(t('studyMetricsColSession'))}</th><th>${escapeHtml(t('studyMetricsColGroup'))}</th>
          <th>${escapeHtml(t('studyMetricMinutes'))}</th><th>${escapeHtml(t('studyMetricCompletionPct'))}</th>
          <th>${escapeHtml(t('studyMetricFindings'))}</th><th>${escapeHtml(t('studyMetricFpRate'))}</th><th>${escapeHtml(t('studyMetricAiCalls'))}</th></tr></thead>
        <tbody>${sessions}</tbody></table></div>`;
  }

  function openStudyMetrics(){
    if(!dbOnline){ showToast(t('studyMetricsNeedBackend')); return; }
    const box = document.getElementById('studyMetricsContent');
    box.innerHTML = `<div class="search-empty">${escapeHtml(t('loadingGeneric'))}</div>`;
    document.getElementById('studyMetricsOverlay').classList.add('open');
    apiRequest('/study/metrics').then(renderStudyMetrics).catch(err => {
      box.innerHTML = `<div class="search-empty">${escapeHtml(t('studyMetricsLoadError'))}<br><small>${escapeHtml(err.message || '')}</small></div>`;
    });
  }
  function closeStudyMetrics(){ document.getElementById('studyMetricsOverlay').classList.remove('open'); }

  function bindNotebookAndStudyEvents(){
    document.getElementById('notebookNavBtn').addEventListener('click', openNotebook);
    document.getElementById('closeNotebookOverlay').addEventListener('click', closeNotebook);
    document.getElementById('notebookOverlay').addEventListener('click', e => {
      if(e.target.id === 'notebookOverlay'){ closeNotebook(); return; }
      const btn = e.target.closest('[data-action]');
      if(!btn) return;
      const note = sessionNotes.find(n => String(n.id) === btn.dataset.id);
      if(btn.dataset.action === 'edit' && note) openNoteEditor(note);
      if(btn.dataset.action === 'zoom' && note){
        const img = NB.safeImages(note.images)[Number(btn.dataset.idx)];
        if(img) openNoteLightbox(img.data, img.name);
      }
    });
    document.getElementById('notebookTestFilter').addEventListener('change', renderNotebookList);
    document.getElementById('notebookSearch').addEventListener('input', renderNotebookList);
    document.getElementById('newNoteBtn').addEventListener('click', () => {
      const f = document.getElementById('notebookTestFilter').value;
      openNoteEditor(null, f && f !== '__general__' ? f : '');
    });

    document.getElementById('closeNoteEditorOverlay').addEventListener('click', closeNoteEditor);
    document.getElementById('noteEditorOverlay').addEventListener('click', e => { if(e.target.id === 'noteEditorOverlay') closeNoteEditor(); });
    document.getElementById('noteEditorForm').addEventListener('submit', saveNoteFromEditor);
    document.getElementById('deleteNoteBtn').addEventListener('click', deleteNoteFromEditor);
    document.getElementById('noteTestSelect').addEventListener('change', e => renderNoteCweSuggestions(e.target.value));
    document.getElementById('noteCvssInput').addEventListener('input', updateNoteCvssPreview);
    document.getElementById('noteImageInput').addEventListener('change', e => { addNoteImages(e.target.files); e.target.value = ''; });
    document.getElementById('noteContentInput').addEventListener('paste', e => {
      const files = Array.from((e.clipboardData && e.clipboardData.files) || []).filter(f => f.type && f.type.indexOf('image/') === 0);
      if(files.length){ e.preventDefault(); addNoteImages(files); }
    });
    document.getElementById('noteImageThumbs').addEventListener('click', e => {
      const rm = e.target.closest('.note-thumb-remove');
      if(rm){ noteEditorImages.splice(Number(rm.dataset.idx), 1); renderNoteThumbs(); return; }
      const img = e.target.closest('.note-thumb img');
      if(img) openNoteLightbox(img.getAttribute('src'), img.alt);
    });
    document.getElementById('noteCweSuggestions').addEventListener('click', e => {
      const chip = e.target.closest('[data-cwe-id]');
      if(!chip) return;
      document.getElementById('noteCweIdInput').value = chip.dataset.cweId;
      document.getElementById('noteCweNameInput').value = chip.dataset.cweName || '';
    });
    document.getElementById('noteAiAnalyzeBtn').addEventListener('click', analyzeNoteWithAI);
    document.getElementById('noteAiResult').addEventListener('click', e => {
      const b = e.target.closest('[data-apply]');
      if(b) applyNoteAiSuggestion(b.dataset.apply);
    });
    document.getElementById('noteLightbox').addEventListener('click', e => {
      if(e.target.id === 'noteLightbox' || e.target.closest('#closeNoteLightbox')) closeNoteLightbox();
    });

    document.getElementById('studyMetricsNavBtn').addEventListener('click', openStudyMetrics);
    document.getElementById('closeStudyMetricsOverlay').addEventListener('click', closeStudyMetrics);
    document.getElementById('studyMetricsOverlay').addEventListener('click', e => {
      if(e.target.id === 'studyMetricsOverlay'){ closeStudyMetrics(); return; }
      if(e.target.closest('#studyCopyCsvBtn') && lastStudyData){
        copyToClipboard(studySessionsCsv(lastStudyData.sessions));
      }
    });
    document.getElementById('studyGroupSelect').addEventListener('change', e => {
      const v = e.target.value;
      document.getElementById('studyGroupHint').textContent = v === 'ai_assisted' ? t('studyGroupHintAi') : v === 'control' ? t('studyGroupHintControl') : '';
    });
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
    document.getElementById('importAddNotes').checked = true;
    document.getElementById('importCreateFindings').checked = true;
    document.getElementById('importAttachHttp').checked = true;
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

  function renderImportOptions(){
    const hasPro = lastImportFindings.some(f => f.pro);
    const hasHttp = lastImportFindings.some(f => f.http);
    const canPro = hasPro && dbOnline && !!currentProjectId;
    const proRow = document.getElementById('importProRow');
    const proBox = document.getElementById('importCreateFindings');
    proRow.style.display = hasPro ? '' : 'none';
    proBox.disabled = !canPro;
    if(!canPro) proBox.checked = false;
    document.getElementById('importProLabel').textContent =
      t('importOptPro')(currentProjectObj && currentProjectObj.name ? currentProjectObj.name : '—');
    document.getElementById('importHttpRow').style.display = hasHttp ? '' : 'none';
    syncImportHttpOption();
    document.getElementById('importProHint').textContent =
      !hasPro ? '' : (canPro ? t('importProDedupeHint') : t('importProNeedProject'));
  }

  function syncImportHttpOption(){
    const proOn = document.getElementById('importCreateFindings').checked;
    const http = document.getElementById('importAttachHttp');
    http.disabled = !proOn;
  }

  function renderImportPreview(){
    const wrap = document.getElementById('importPreviewWrap');
    const list = document.getElementById('importPreviewList');
    const countEl = document.getElementById('importPreviewCount');
    if(!lastImportFindings.length){ wrap.style.display = 'none'; return; }
    wrap.style.display = '';
    countEl.textContent = t('importPreviewCount')(lastImportFindings.length);
    renderImportOptions();
    list.innerHTML = lastImportFindings.map(f => {
      const sev = SEVERITIES.indexOf(f.severity) !== -1 ? f.severity : 'info';
      const idsHtml = (f.testIds || []).map(id => {
        const meta = testInfoById(id);
        return `<span class="import-preview-ids">${escapeHtml(id)}${meta ? ' · ' + escapeHtml(meta.title) : ''}</span>`;
      }).join(' ');
      const pro = f.pro || {};
      const meta = [
        pro.endpoint ? `<span class="badge mono import-endpoint" title="${escapeHtml(pro.endpoint)}">${escapeHtml(pro.endpoint)}</span>` : '',
        pro.cwe ? `<span class="badge mono">${escapeHtml(pro.cwe)}</span>` : '',
        f.http ? `<span class="badge blue">${escapeHtml(t('importHttpBadge'))}</span>` : '',
      ].filter(Boolean).join('');
      return `<div class="import-preview-item ${f.unmatched ? 'unmatched' : ''}">
        <input type="checkbox" class="import-check" data-row="${escapeHtml(f._rowId)}" ${f._checked ? 'checked' : ''}>
        <div class="import-preview-body">
          <div class="import-preview-top">
            <span class="import-preview-title">${escapeHtml(f.title || '')}</span>
            <span class="severity-badge sev-${sev}">${escapeHtml(t('severity_' + sev))}</span>
            ${f.unmatched ? `<span class="severity-badge sev-info">${escapeHtml(t('importUnmatchedTag'))}</span>` : ''}
          </div>
          ${meta ? `<div class="import-preview-meta">${meta}</div>` : ''}
          <div>${idsHtml}</div>
          ${f.detail ? `<div class="import-preview-detail">${escapeHtml(f.detail)}</div>` : ''}
          <div class="import-preview-source">${escapeHtml(f.source || '')}</div>
        </div>
      </div>`;
    }).join('');
  }

  function applyImportNotes(items){
    items.forEach(f => {
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
  }

  // Burp/ZAP bulgularını projede Finding (+ isteğe bağlı HTTP kanıtı) olarak
  // oluşturur. Aynı başlık+endpoint projede zaten varsa atlanır, böylece aynı
  // rapor ikinci kez içe aktarıldığında kopya oluşmaz.
  async function createImportedFindings(items, attachHttp, onProgress){
    const pid = currentProjectId;
    const key = (title, endpoint) => `${String(title || '').trim().toLowerCase()}|${String(endpoint || '').trim().toLowerCase()}`;
    const existing = await apiRequest(`/projects/${pid}/findings`);
    const seen = new Set((existing || []).map(f => key(f.title, f.endpoint)));
    const sessionId = currentSession && currentSession.project_id === pid ? currentSession.id : null;
    const res = { created: 0, skipped: 0, failed: 0 };
    for(let i = 0; i < items.length; i++){
      const f = items[i];
      onProgress(i + 1, items.length);
      const k = key(f.pro.title, f.pro.endpoint);
      if(seen.has(k)){ res.skipped++; continue; }
      seen.add(k);
      const testId = !f.unmatched && f.testIds && f.testIds[0] && testInfoById(f.testIds[0]) ? f.testIds[0] : null;
      try{
        const created = await apiRequest(`/projects/${pid}/findings`, { method: 'POST', body: JSON.stringify(
          Object.assign({}, f.pro, { status: 'open', test_id: testId, session_id: sessionId })) });
        res.created++;
        if(attachHttp && f.http && (f.http.request || f.http.response)){
          await apiRequest(`/projects/${pid}/evidence/http`, { method: 'POST', body: JSON.stringify({
            http_request: f.http.request || '', http_response: f.http.response || '', label: f.http.label,
            linked_finding_id: created.id, linked_test_id: testId, linked_session_id: sessionId,
          }) }).catch(() => {});
        }
      }catch(e){ res.failed++; }
    }
    return res;
  }

  function applyImportSelected(){
    const checked = lastImportFindings.filter(f => f._checked);
    if(!checked.length) return;
    const addNotes = document.getElementById('importAddNotes').checked;
    const proBox = document.getElementById('importCreateFindings');
    const proItems = checked.filter(f => f.pro);
    const createPro = !proBox.disabled && proBox.checked && proItems.length > 0;
    const statusEl = document.getElementById('importStatus');
    statusEl.classList.remove('error');
    if(!addNotes && !createPro){ statusEl.textContent = t('importNothingSelected'); statusEl.classList.add('error'); return; }

    if(addNotes) applyImportNotes(checked);
    if(!createPro){
      showToast(t('importAppliedToast')(checked.length));
      closeImportModal();
      return;
    }
    const btn = document.getElementById('importApplyBtn');
    btn.disabled = true;
    createImportedFindings(proItems, document.getElementById('importAttachHttp').checked,
      (i, n) => { statusEl.textContent = t('importCreatingFindings')(i, n); })
      .then(r => {
        statusEl.textContent = '';
        showToast(t('importProResult')(r.created, r.skipped, r.failed));
        const ws = document.getElementById('projectWorkspaceOverlay');
        if(ws && ws.classList.contains('open') && (activePwTab === 'findings' || activePwTab === 'evidence')) renderPwTab();
        if(r.failed){ statusEl.textContent = t('importProResult')(r.created, r.skipped, r.failed); statusEl.classList.add('error'); }
        else closeImportModal();
      })
      .catch(err => { statusEl.textContent = err.message || t('resultSaveError'); statusEl.classList.add('error'); })
      .finally(() => { btn.disabled = false; });
  }

  // ========================
  // Attack Surface Discovery (Recon)
  // ========================

  let lastReconResult = null;

  function openReconModal(){
    document.getElementById('reconResultsWrap').style.display = 'none';
    document.getElementById('reconTargetInput').value = '';
    document.getElementById('reconAuthCheck').checked = false;
    document.getElementById('reconCachedNotice').style.display = 'none';
    const status = document.getElementById('reconStatus');
    status.textContent = '';
    status.classList.remove('error');
    lastReconResult = null;
    document.getElementById('reconOverlay').classList.add('open');

    // Daha önce bu proje/oturum için bir tarama yapıldıysa, yeniden
    // taramaya gerek kalmadan sonuçları geri getir.
    if(currentProjectId){
      apiRequest(`/projects/${currentProjectId}/recon/latest`).then(res => {
        if(res && res.run) restoreReconResult(res.run, res.run.created_at);
      }).catch(()=>{ restoreFromLocalReconCache(); });
    } else {
      restoreFromLocalReconCache();
    }
  }

  function restoreFromLocalReconCache(){
    const cached = loadReconCache();
    if(cached && cached.result) restoreReconResult(cached.result, cached.cachedAt);
  }

  function restoreReconResult(result, cachedAtIso){
    lastReconResult = result;
    document.getElementById('reconTargetInput').value = result.target || result.baseUrl || '';
    renderReconResults(result);
    const notice = document.getElementById('reconCachedNotice');
    const text = document.getElementById('reconCachedText');
    const when = cachedAtIso ? new Date(cachedAtIso).toLocaleString(t('dateLocale')) : '';
    text.innerHTML = t('reconCachedNotice')(escapeHtml(result.target || result.baseUrl || ''), escapeHtml(when));
    notice.style.display = '';
  }

  function resetReconState(){
    if(!confirm(t('reconResetConfirm'))) return;
    clearReconCache();
    const doClear = currentProjectId
      ? apiRequest(`/projects/${currentProjectId}/recon`, { method: 'DELETE' }).catch(()=>{})
      : Promise.resolve();
    doClear.then(()=>{
      lastReconResult = null;
      document.getElementById('reconResultsWrap').style.display = 'none';
      document.getElementById('reconCachedNotice').style.display = 'none';
      document.getElementById('reconTargetInput').value = '';
      showToast(t('reconResetToast'));
    });
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
    document.getElementById('reconCachedNotice').style.display = 'none';

    apiRequest('/recon', {
      method: 'POST',
      body: JSON.stringify({ target, confirm_authorized: true, project_id: currentProjectId || undefined })
    }).then(result => {
      lastReconResult = result;
      statusEl.textContent = '';
      renderReconResults(result);
      saveReconCache(result); // sonraki açılışta yeniden taramadan göster
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
  // AI: Sırada Ne Var? — Test Planı'nın (kural tabanlı) AI destekli
  // alternatifi. Recon kanıtı gerekmez; tamamlanan testlere + kayıtlı
  // bulgulara bakıp bir sonraki adımı gerekçesiyle önerir. Session
  // açıksa backend, tamamlanan test listesini ve bulguları oturumdan
  // kendisi türetir; session yoksa (yerel/oturumsuz mod) burada
  // `progress` ve local `findings` deposundan elle topluyoruz.
  // ========================

  function openAiNextTestModal(){
    document.getElementById('aiNextTestResult').style.display = 'none';
    document.getElementById('aiNextTestResult').innerHTML = '';
    document.getElementById('aiNextTestStatus').textContent = '';
    document.getElementById('aiNextTestStatus').className = 'ai-provider-status';
    document.getElementById('aiNextTestOverlay').classList.add('open');
  }
  function closeAiNextTestModal(){
    document.getElementById('aiNextTestOverlay').classList.remove('open');
  }

  function localCompletedTestIds(){
    return Object.keys(progress).filter(id => progress[id]);
  }
  function localFindingsForAi(){
    return Object.entries(findings).map(([testId, f]) => {
      const meta = testInfoById(testId);
      return { title: (meta && meta.title) || testId, severity: f.severity || 'info', test_id: testId };
    }).filter(f => f.severity && f.severity !== 'info');
  }

  function askAiNextTest(){
    const statusEl = document.getElementById('aiNextTestStatus');
    const resultEl = document.getElementById('aiNextTestResult');
    resultEl.style.display = 'none';
    statusEl.className = 'ai-provider-status';
    statusEl.textContent = t('aiWorking');

    const body = currentSession
      ? { session_id: currentSession.id, lang: currentLang }
      : { completed_test_ids: localCompletedTestIds(), findings: localFindingsForAi(), lang: currentLang };

    apiRequest('/ai/suggest-next-test', { method: 'POST', body: JSON.stringify(body) })
      .then(suggestion => {
        statusEl.textContent = '';
        renderAiNextTestResult(suggestion);
      })
      .catch(err => {
        statusEl.className = 'ai-provider-status failure';
        statusEl.textContent = `✗ ${err && err.message ? err.message : String(err)}`;
      });
  }

  function renderAiNextTestResult(s){
    const resultEl = document.getElementById('aiNextTestResult');
    resultEl.style.display = '';

    if(s.all_done){
      resultEl.innerHTML = `<div class="ant-all-done">${escapeHtml(t('aiNextTestAllDone'))}</div>`;
      return;
    }
    if(!s.suggested_test_id){
      resultEl.innerHTML = `<div class="ant-all-done">${escapeHtml(t('aiNextTestNoSuggestion'))}</div>`;
      return;
    }

    const meta = testInfoById(s.suggested_test_id);
    const priority = (s.priority || 'medium').toLowerCase();
    const groundedWarning = s.suggestion_grounded === false
      ? `<div class="ant-grounded-warning">${escapeHtml(t('aiNextTestUngrounded'))}</div>` : '';
    const altsHtml = (s.alternative_test_ids && s.alternative_test_ids.length)
      ? `<div class="ant-alts">${escapeHtml(t('aiNextTestAltsLabel'))}: ${s.alternative_test_ids.map(escapeHtml).join(', ')}</div>` : '';

    resultEl.innerHTML = `
      <div class="ant-top">
        <span class="ant-id">${escapeHtml(s.suggested_test_id)}</span>
        <span class="ant-title">${escapeHtml(s.suggested_test_title || (meta && meta.title) || '')}</span>
        <span class="ant-priority ${priority}">${escapeHtml(t('reconPriorityBadge_'+priority) || priority)}</span>
      </div>
      ${groundedWarning}
      <div class="ant-reasoning">${escapeHtml(s.reasoning || '')}</div>
      ${altsHtml}
      <div class="ant-actions">
        ${meta ? `<button type="button" class="btn btn-primary btn-sm" id="aiNextTestGotoBtn" data-cat="${meta.catId}" data-test="${escapeHtml(s.suggested_test_id)}">${t('plannerGotoBtn')}</button>` : ''}
        <button type="button" class="btn btn-secondary btn-sm" id="aiNextTestAgainBtn">${t('aiNextTestAskBtn')}</button>
      </div>`;

    const gotoBtn = document.getElementById('aiNextTestGotoBtn');
    if(gotoBtn) gotoBtn.addEventListener('click', ()=>{
      closeAiNextTestModal();
      openCategory(gotoBtn.dataset.cat, gotoBtn.dataset.test);
    });
    document.getElementById('aiNextTestAgainBtn').addEventListener('click', askAiNextTest);
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
    const name = document.getElementById('projectChipName');
    if(currentProjectObj){
      chip.classList.remove('placeholder');
      name.textContent = currentProjectObj.name;
      chip.title = currentProjectObj.client || t('navProjects');
      document.getElementById('projectChipSub').textContent = currentProjectObj.client || '';
    } else {
      chip.classList.add('placeholder');
      name.textContent = t('ctxNoProject');
      chip.title = t('navProjects');
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
                ${p.client ? `<span>${escapeHtml(p.client)}</span>` : ''}
                <span>${t('projectSessionsLabel')(p.session_count || 0)}</span>
                ${p.start_date ? `<span>${escapeHtml(p.start_date)}${p.end_date ? ' → ' + escapeHtml(p.end_date) : ''}</span>` : ''}
              </div>
            </div>
            <span class="project-status-pill ${p.status}">${t('projectStatus_'+p.status)}</span>
          </div>
          ${p.description ? `<div class="import-preview-source">${escapeHtml(p.description)}</div>` : ''}
          <div class="project-card-actions">
            <button data-action="open" data-id="${p.id}">${t('openProjectBtn')}</button>
            <button data-action="edit" data-id="${p.id}">${t('editBtn')}</button>
            <button data-action="delete" data-id="${p.id}" class="danger">${t('pwEvidenceDelete')}</button>
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
        reloadReconContext();
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

  function openProjectWorkspace(projectId, initialTab){
    apiRequest(`/projects/${projectId}`).then(project => {
      currentProjectId = project.id;
      currentProjectObj = project;
      updateProjectChip();
      closeProjectsModal();
      reloadReconContext();
      renderProjectWorkspaceHeader();
      switchPwTab(initialTab || 'overview');
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
      timeline: renderPwTimeline, kanban: renderPwKanban, reports: renderPwReports, authz: renderPwAuthz, retest: renderPwRetest
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

  let lastFindingsForMap = [];

  // ========================
  // Saldırı Yüzeyi (proje çalışma alanı > Assets sekmesi)
  //
  // Salt-okunur: yalnızca GET /assets, GET /scope, GET /findings ve oturum
  // sonuçlarını okur. /api/recon'u ÇAĞIRMAZ; yeni tarama kullanıcı isterse
  // mevcut Attack Surface Discovery penceresinden (yetki onayıyla) başlatılır.
  // Hesaplamalar js/attack-surface.js içinde ve birim testlidir.
  // ========================
  let asState = null;          // { surface, findings }
  const AS_HIDE_STATIC_KEY = 'wstg_as_hide_static_v1';
  function loadHideStatic(){ try{ return localStorage.getItem(AS_HIDE_STATIC_KEY) === '1'; }catch(e){ return false; } }
  function saveHideStatic(v){ try{ v ? localStorage.setItem(AS_HIDE_STATIC_KEY, '1') : localStorage.removeItem(AS_HIDE_STATIC_KEY); }catch(e){} }
  let asFilters = { q: '', type: 'all', scope: 'all', hideStatic: loadHideStatic() };
  let asView = null;           // 'map' | 'list' (null -> ekran genişliğine göre)
  let asSelectedKey = null;
  let asShowAllSuggestions = false;
  let asRequestSeq = 0;
  const AS_MAP_LIMIT = 6;

  const asIcons = {
    domain: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    endpoint: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    technology: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    bulb: '<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.6.5 1 1.2 1 2V16h5v-.1c0-.8.4-1.5 1-2A6 6 0 0 0 12 3z"/>',
    chev: '<path d="m9 6 6 6-6 6"/>',
    map: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2h12v2"/>',
    list: '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    warn: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>'
  };
  function asIcon(name, cls){
    const key = name === 'subdomain' ? 'domain' : name;
    return `<svg class="i ${cls||''}" viewBox="0 0 24 24" aria-hidden="true">${asIcons[key] || asIcons.endpoint}</svg>`;
  }
  function asKey(row){ return `${row.type}|${row.target}|${row.value}`; }

  // Varlık değeri: kayıtlı baseUrl'den güvenle üretilmiş bir adres varsa yeni
  // sekmede açılan normal bir link (metin seçilip kopyalanabilir); hedef kapsam
  // dışıysa link verilmez, sadece metin + kopyalama. Adres js/attack-surface.js
  // safeUrl() ile yalnızca http(s) ve aynı origin için üretilir.
  function asValueHtml(row){
    if(row.url && row.linkScope !== 'out'){
      const unverified = row.linkScope === 'unknown' || row.linkScope === 'undefined';
      const title = `${t('asOpenInNewTab')}: ${row.url}` + (unverified ? ` — ${t('asLinkWarn_' + row.linkScope)}` : '');
      return `<a class="asset-link ${unverified ? 'unverified' : ''}" href="${escapeHtml(row.url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(title)}">${escapeHtml(row.value)}${asIcon('external', 'i-xs')}</a>`;
    }
    const off = row.url && row.linkScope === 'out';
    return `<span class="asset-text" ${off ? `title="${escapeHtml(t('asLinkDisabledOut'))}"` : ''}>${escapeHtml(row.value)}</span>`;
  }

  function asActionsHtml(row){
    const copyVal = row.url || row.value;
    return `<span class="as-actions">
      <button type="button" class="icon-btn sm" data-as-copy="${escapeHtml(copyVal)}" title="${escapeHtml(t('asCopy'))}" aria-label="${escapeHtml(t('asCopy') + ': ' + copyVal)}">${asIcon('copy')}</button>
      <button type="button" class="icon-btn sm" data-as-key="${escapeHtml(asKey(row))}" title="${escapeHtml(t('asDetails'))}" aria-label="${escapeHtml(t('asDetails') + ': ' + row.value)}">${asIcon('info')}</button>
    </span>`;
  }

  // Hedef bazında link uyarısı (satır satır tekrar etmemek için tek satır).
  function asLinkNoticeHtml(){
    const seen = new Set();
    return asState.surface.inventory.filter(r => r.url && r.linkScope && r.linkScope !== 'in' && !seen.has(r.target) && seen.add(r.target))
      .map(r => {
        const out = r.linkScope === 'out';
        return `<div class="as-link-notice ${out ? 'out' : ''}" role="note">${asIcon(out ? 'shield' : 'warn')}<span>${escapeHtml(t(out ? 'asLinkNoticeOut' : 'asLinkNotice_' + r.linkScope)(r.target))}</span></div>`;
      }).join('');
  }

  function asShortDate(iso){
    const d = iso ? new Date(iso) : null;
    return d && !isNaN(d) ? d.toLocaleString(t('dateLocale'), { dateStyle: 'short', timeStyle: 'short' }) : '—';
  }
  function asDate(iso){
    const d = iso ? new Date(iso) : null;
    return d && !isNaN(d) ? d.toLocaleString(t('dateLocale'), { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  }
  function asTypeLabel(row){
    if(row.type === 'endpoint' && row.isApi) return t('asTypeApiEndpoint');
    return t('asType_' + row.type);
  }
  function asRecordLabel(row){
    if(row.record === 'http') return t('asRecordHttp')(row.httpStatus);
    return t('asRecord_' + row.record);
  }
  function asScopeBadge(scope){
    if(!scope) return '<span class="cell-muted">—</span>';
    const cls = { in: 'green', out: 'red', unknown: 'amber', undefined: '' }[scope] || '';
    return `<span class="badge ${cls}">${t('asScope_' + scope)}</span>`;
  }
  function asLevelBadge(level){
    const lv = LEVEL_LABEL_KEYS[level] ? level : 'info';
    return `<span class="test-tag lv-${lv} lv-badge">${escapeHtml(t(LEVEL_LABEL_KEYS[lv]))}</span>`;
  }
  const LEVEL_LABEL_KEYS = { high: 'asLevel_high', medium: 'asLevel_medium', low: 'asLevel_low', info: 'asLevel_info' };

  // Projede tamamlanmış testler: açık oturum bu projeye aitse onun ilerlemesi,
  // değilse projenin ilk oturumunun sonuçları (Findings sekmesiyle aynı akış).
  function projectDoneTestIds(){
    if(currentSession && currentSession.project_id === currentProjectId){
      return Promise.resolve(new Set(Object.keys(progress).filter(id => progress[id])));
    }
    return apiRequest(`/sessions?project_id=${currentProjectId}`).then(sessions => {
      if(!sessions || !sessions.length) return new Set();
      return apiRequest(`/sessions/${sessions[0].id}/results`).then(results =>
        new Set((results || []).filter(r => r.status && r.status !== 'pending').map(r => r.test_id)));
    }).catch(()=> new Set());
  }

  function renderPwAssets(){
    const content = document.getElementById('pwContent');
    const seq = ++asRequestSeq;
    if(!window.WSTGAttackSurface){
      content.innerHTML = `<div class="search-empty">${t('asLoadError')}</div>`;
      return;
    }
    content.innerHTML = `<div class="as-loading" role="status"><span class="as-spinner" aria-hidden="true"></span>${t('asLoading')}</div>`;
    Promise.all([
      apiRequest(`/projects/${currentProjectId}/assets`),
      apiRequest(`/projects/${currentProjectId}/scope`).catch(()=> []),
      apiRequest(`/projects/${currentProjectId}/findings`).catch(()=> []),
      projectDoneTestIds(),
    ]).then(([assets, scope, findings, doneIds]) => {
      if(seq !== asRequestSeq || activePwTab !== 'assets') return; // kullanıcı başka sekmeye geçti
      asState = { surface: window.WSTGAttackSurface.buildSurface(assets, scope, doneIds), findings: findings || [] };
      lastFindingsForMap = asState.findings;
      if(asView === null) asView = window.matchMedia && window.matchMedia('(max-width: 700px)').matches ? 'list' : 'map';
      renderAttackSurface();
    }).catch(err => {
      if(seq !== asRequestSeq) return;
      content.innerHTML = `
        <div class="empty-state" role="alert">
          <h3>${t('asLoadError')}</h3>
          <p>${escapeHtml(String((err && err.message) || err))}</p>
          <div class="hero-actions"><button type="button" class="btn btn-secondary" id="asRetryBtn">${t('asRetry')}</button></div>
        </div>`;
      document.getElementById('asRetryBtn').addEventListener('click', renderPwAssets);
    });
  }

  function renderAttackSurface(){
    const content = document.getElementById('pwContent');
    const s = asState.surface;
    if(!s.runCount){
      content.innerHTML = `
        <div class="empty-state">
          <div class="empty-ico">${asIcon('map')}</div>
          <h3>${t('asEmptyTitle')}</h3>
          <p>${t('asEmptyDesc')}</p>
          <div class="hero-actions"><button type="button" class="btn btn-primary" data-as-action="open-recon">${t('pwReconOpenBtn')}</button></div>
        </div>`;
      wireAttackSurface(content);
      return;
    }
    const scopeText = s.targetScope ? `<span class="badge ${({in:'green',out:'red',unknown:'amber'})[s.targetScope]||''}">${asIcon('shield','i-xs')}${t('asTargetScope_' + s.targetScope)}</span>` : '';
    content.innerHTML = `
      <div class="as-head">
        <div>
          <h3 class="as-title">${t('asTitle')}</h3>
          <p class="as-desc">${t('asDesc')}</p>
        </div>
        <div class="as-head-side">
          <div class="as-target"><span>${t('asTargetLabel')}</span> <b>${escapeHtml(s.latestTarget || '—')}</b></div>
          ${scopeText}
        </div>
      </div>
      ${renderAsSummary(s)}
      <div class="as-filters" role="search">
        <div class="search-input"><svg class="i"><use href="#ic-search"/></svg>
          <input type="text" id="asSearch" placeholder="${t('asSearchPlaceholder')}" value="${escapeHtml(asFilters.q)}" aria-label="${t('asSearchPlaceholder')}">
        </div>
        <select id="asTypeFilter" aria-label="${t('asColType')}">
          ${['all','domain','subdomain','endpoint','technology'].map(v => `<option value="${v}" ${asFilters.type===v?'selected':''}>${v==='all' ? t('asFilterTypeAll') : t('asType_'+v)}</option>`).join('')}
        </select>
        <select id="asScopeFilter" aria-label="${t('asColScope')}">
          ${['all','in','out','unknown','undefined'].map(v => `<option value="${v}" ${asFilters.scope===v?'selected':''}>${v==='all' ? t('asFilterScopeAll') : t('asScope_'+v)}</option>`).join('')}
        </select>
        <button type="button" class="btn btn-secondary" data-as-action="clear-filters">${t('asClearFilters')}</button>
        ${s.staticCount ? `<label class="as-check"><input type="checkbox" id="asHideStatic" ${asFilters.hideStatic ? 'checked' : ''}>
          <span>${t('asHideStatic')} <span class="muted-count">(${s.staticCount})</span></span></label>` : ''}
      </div>
      <section class="card as-card" aria-labelledby="asMapTitle">
        <div class="card-head">
          <h4 class="card-title" id="asMapTitle">${t('asMapTitle')}</h4>
          <div class="seg" role="group" aria-label="${t('asViewToggle')}">
            <button type="button" class="${asView==='map'?'active':''}" data-as-view="map" aria-pressed="${asView==='map'}">${asIcon('map')}${t('asViewMap')}</button>
            <button type="button" class="${asView==='list'?'active':''}" data-as-view="list" aria-pressed="${asView==='list'}">${asIcon('list')}${t('asViewList')}</button>
          </div>
        </div>
        <p class="as-note">${t('asRelationNote')}</p>
        <div id="asMapBody"></div>
      </section>
      <section class="card as-card" aria-labelledby="asInvTitle">
        <div class="card-head">
          <h4 class="card-title" id="asInvTitle">${t('asInventoryTitle')} <span class="muted-count" id="asInvCount"></span></h4>
        </div>
        <div id="asInventory"></div>
        <div id="asmEndpointDetail" class="asm-endpoint-detail" style="display:none" tabindex="-1"></div>
      </section>
      <section class="card as-card" aria-labelledby="asSuggTitle">
        <div class="card-head">
          <h4 class="card-title" id="asSuggTitle">${asIcon('bulb')}${t('asSuggestionsTitle')}</h4>
        </div>
        <p class="as-note">${t('asSuggestionsNote')}</p>
        <div id="asSuggestions"></div>
      </section>`;
    renderAsMap();
    renderAsInventory();
    renderAsSuggestions();
    wireAttackSurface(content);
  }

  function renderAsSummary(s){
    const tile = (icon, label, value, sub, type) => `
      <button type="button" class="as-stat" ${type ? `data-as-type="${type}" aria-pressed="${asFilters.type===type}"` : 'disabled'} ${type ? `aria-label="${escapeHtml(label)}: ${value}. ${t('asFilterHint')}"` : ''}>
        <span class="as-stat-ico">${asIcon(icon)}</span>
        <span class="as-stat-text"><span class="as-stat-label">${escapeHtml(label)}</span>${sub ? `<span class="as-stat-sub">${escapeHtml(sub)}</span>` : ''}</span>
        <span class="as-stat-value">${value}</span>
      </button>`;
    return `
      <section class="as-summary" aria-label="${t('asSummaryTitle')}">
        <div class="as-scan">
          <span class="as-stat-ico">${asIcon('clock')}</span>
          <div>
            <div class="as-stat-label">${t('asLastScan')}</div>
            <div class="as-scan-date">${escapeHtml(asDate(s.lastScanAt))}</div>
            <div class="as-stat-sub">${t('asRunCount')(s.runCount)}</div>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" data-as-action="open-recon">${t('pwReconOpenBtn')}</button>
        </div>
        ${tile('subdomain', t('asType_subdomain'), s.counts.subdomain, t('asStatSubResolved'), 'subdomain')}
        ${tile('endpoint', t('asType_endpoint'), s.counts.endpoint, s.counts.api ? t('asStatApi')(s.counts.api) : '', 'endpoint')}
        ${tile('technology', t('asType_technology'), s.counts.technology, t('asStatTechSub'), 'technology')}
      </section>`;
  }

  function asFiltered(){
    return window.WSTGAttackSurface.filterInventory(asState.surface.inventory, asFilters);
  }

  function asNodeHtml(row, extraCls){
    const key = asKey(row);
    const sub = row.type === 'domain' ? t('asRootNode') : asTypeLabel(row);
    const flag = row.scope === 'out' ? `<span class="mn-out">${t('asScope_out')}</span>` : '';
    return `<button type="button" class="as-node t-${row.type} ${extraCls||''} ${asSelectedKey===key?'selected':''}" data-as-key="${escapeHtml(key)}"
        aria-label="${escapeHtml(row.value)} — ${escapeHtml(sub)}${row.scope==='out' ? ' — ' + escapeHtml(t('asScope_out')) : ''}">
      ${asIcon(row.type)}
      <span class="mn-text"><span class="mn-title">${escapeHtml(row.value)}</span><span class="mn-sub">${escapeHtml(sub)}</span></span>
      ${flag}
    </button>`;
  }

  function renderAsMap(){
    const body = document.getElementById('asMapBody');
    const s = asState.surface;
    const visible = new Set(asFiltered().map(asKey));
    const byTarget = s.targets.map(tg => {
      const rows = s.inventory.filter(r => r.target === tg.target);
      return { tg, root: rows.find(r => r.type === 'domain'), rows };
    });

    if(asView === 'list'){
      body.innerHTML = byTarget.map(({ tg, root, rows }) => {
        const groups = ['subdomain','endpoint','technology'].map(type => {
          const items = rows.filter(r => r.type === type && visible.has(asKey(r)));
          if(!items.length) return '';
          return `<li><span class="as-tree-group">${asIcon(type)}${t('asGroup_' + type)} <span class="muted-count">(${items.length})</span></span>
            <ul>${items.map(r => `<li class="as-tree-row ${asSelectedKey===asKey(r)?'selected':''}">
              <span class="as-tree-value">${asValueHtml(r)}</span>
              <span class="as-tree-meta">${escapeHtml(asRecordLabel(r))}${r.tests.length ? ' · ' + t('asTestsCount')(r.tests.length) : ''}${r.scope === 'out' ? ' · ' + escapeHtml(t('asScope_out')) : ''}</span>
              ${asActionsHtml(r)}
            </li>`).join('')}</ul></li>`;
        }).join('');
        return `<ul class="as-tree" aria-label="${escapeHtml(tg.target)}">
          <li><div class="as-tree-row as-tree-root ${root && asSelectedKey===asKey(root)?'selected':''}">${asIcon('domain')}
              <span class="as-tree-value">${root ? asValueHtml(root) : escapeHtml(tg.target)}</span>
              <span class="as-tree-meta">${t('asRootNode')}</span>${root ? asActionsHtml(root) : ''}</div>
            ${groups ? `<ul>${groups}</ul>` : `<p class="as-note">${t('asNoMatch')}</p>`}
          </li></ul>`;
      }).join('');
      return;
    }

    body.innerHTML = byTarget.map(({ tg, root, rows }) => {
      const cols = ['subdomain','endpoint','technology'].map(type => {
        const all = rows.filter(r => r.type === type && visible.has(asKey(r)));
        if(!all.length) return '';
        const shown = all.slice(0, AS_MAP_LIMIT);
        const more = all.length - shown.length;
        return `<div class="as-col">
          <div class="as-col-head">${t('asGroup_' + type)} <span class="muted-count">(${all.length})</span></div>
          <div class="as-col-items">
            ${shown.map(r => asNodeHtml(r)).join('')}
            ${more > 0 ? `<button type="button" class="as-node t-more" data-as-more="${type}">${t('asMoreNodes')(more)}</button>` : ''}
          </div>
        </div>`;
      }).join('');
      return `<div class="as-map" role="group" aria-label="${escapeHtml(tg.target)}">
        <div class="as-root-row">${root ? asNodeHtml(root, 'as-root') : ''}</div>
        ${cols ? `<div class="as-cols">${cols}</div>` : `<p class="as-note as-center">${t('asNoMatch')}</p>`}
      </div>`;
    }).join('');
  }

  function renderAsInventory(){
    const box = document.getElementById('asInventory');
    const rows = asFiltered();
    document.getElementById('asInvCount').textContent = t('asInventoryCount')(rows.length, asState.surface.inventory.length);
    if(!rows.length){
      box.innerHTML = `<div class="search-empty">${t('asNoMatch')}</div>`;
      return;
    }
    box.innerHTML = asLinkNoticeHtml() + `
      <div class="table-wrap">
        <table class="table as-table">
          <colgroup><col class="c-asset"><col class="c-type"><col class="c-record"><col class="c-scope"><col class="c-tests"><col class="c-seen"><col class="c-actions"></colgroup>
          <thead><tr>
            <th scope="col">${t('asColAsset')}</th>
            <th scope="col">${t('asColType')}</th>
            <th scope="col">${t('asColRecord')}</th>
            <th scope="col">${t('asColScope')}</th>
            <th scope="col">${t('asColTests')}</th>
            <th scope="col">${t('asColLastSeen')}</th>
            <th scope="col"><span class="sr-only">${t('asColActions')}</span></th>
          </tr></thead>
          <tbody>
            ${rows.map(r => {
              const key = asKey(r);
              const tests = r.tests.length
                ? r.tests.map(x => `<button type="button" class="test-tag lv-${x.level} as-test-link" data-as-test="${escapeHtml(x.test_id)}" title="${escapeHtml(x.reason)}">${escapeHtml(x.test_id)}${x.done ? ' ✓' : ''}</button>`).join(' ')
                : '<span class="cell-muted">—</span>';
              return `<tr class="${asSelectedKey===key?'selected':''}" data-as-row="${escapeHtml(key)}">
                <td data-label="${t('asColAsset')}"><div class="cell-asset">
                  <span class="type-ico type-${r.type}">${asIcon(r.type)}</span>
                  <span class="cell-asset-text"><span class="asset-val">${asValueHtml(r)}</span>
                  ${r.type !== 'domain' ? `<span class="asset-parent" title="${escapeHtml(r.target)}">${escapeHtml(r.target)}</span>` : ''}</span>
                </div></td>
                <td data-label="${t('asColType')}" class="cell-muted">${escapeHtml(asTypeLabel(r))}</td>
                <td data-label="${t('asColRecord')}" class="cell-muted">${escapeHtml(asRecordLabel(r))}</td>
                <td data-label="${t('asColScope')}">${asScopeBadge(r.scope)}</td>
                <td data-label="${t('asColTests')}"><span class="as-tests">${tests}</span></td>
                <td data-label="${t('asColLastSeen')}" class="cell-muted" title="${escapeHtml(asDate(r.lastSeen))}">${escapeHtml(asShortDate(r.lastSeen))}</td>
                <td class="cell-actions">${asActionsHtml(r)}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
      <p class="as-note">${t('asTestsDerivedNote')}</p>`;
  }

  function renderAsSuggestions(){
    const box = document.getElementById('asSuggestions');
    const list = asState.surface.suggestions;
    if(!list.length){
      box.innerHTML = `<div class="search-empty">${t('reconNoSuggestions')}</div>`;
      return;
    }
    const shown = asShowAllSuggestions ? list : list.slice(0, 5);
    box.innerHTML = `<ul class="as-sugg-list">
      ${shown.map(sg => {
        const meta = testInfoById(sg.test_id);
        return `<li class="suggestion ${sg.done ? 'is-done' : ''}">
          <div class="sg-body">
            <div class="sg-top">
              <span class="badge mono">${escapeHtml(sg.test_id)}</span>
              ${asLevelBadge(sg.level)}
              ${sg.done ? `<span class="badge green">${t('statusDoneLabel')}</span>` : ''}
            </div>
            <div class="sg-title">${escapeHtml(meta ? meta.title : sg.test_id)}</div>
            <ul class="sg-reasons">${sg.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
          </div>
          ${meta ? `<button type="button" class="btn btn-secondary btn-sm" data-as-test="${escapeHtml(sg.test_id)}">${t('plannerGotoBtn')}</button>` : ''}
        </li>`;
      }).join('')}
    </ul>
    ${list.length > 5 ? `<div class="as-more-row"><button type="button" class="link-btn" data-as-action="toggle-suggestions" aria-expanded="${asShowAllSuggestions}">${asShowAllSuggestions ? t('asShowLess') : t('asShowAll')(list.length)}</button></div>` : ''}`;
  }

  function renderAsDetail(key){
    const row = asState.surface.inventory.find(r => asKey(r) === key);
    const box = document.getElementById('asmEndpointDetail');
    if(!row || !box){ if(box) box.style.display = 'none'; return; }
    const needle = String(row.value).toLowerCase();
    const matched = (row.type === 'technology') ? [] :
      asState.findings.filter(f => f.endpoint && String(f.endpoint).toLowerCase().includes(needle));
    box.style.display = '';
    box.innerHTML = `
      <div class="asm-endpoint-detail-top">
        <div>
          <div class="asm-endpoint-path">${asValueHtml(row)}
            <button type="button" class="btn btn-secondary btn-xs" data-as-copy="${escapeHtml(row.url || row.value)}">${asIcon('copy')}${t('asCopy')}</button>
          </div>
          ${row.url ? `<div class="as-note as-detail-url">${escapeHtml(row.url)}</div>` : ''}
          <div class="as-note">${escapeHtml(asTypeLabel(row))} · ${escapeHtml(asRecordLabel(row))} · ${t('asFirstSeen')}: ${escapeHtml(asDate(row.firstSeen))}</div>
        </div>
        ${row.type !== 'technology' ? `<button type="button" class="btn btn-primary btn-sm" id="asmCreateFindingBtn">${t('newFindingBtn')}</button>` : ''}
      </div>
      ${row.tests.length ? `<div class="asm-endpoint-findings-label">${t('asColTests')}</div>
        <div class="as-detail-tests">${row.tests.map(x => `<button type="button" class="test-row" data-as-test="${escapeHtml(x.test_id)}">
          ${asLevelBadge(x.level)}<span class="tr-title"><b>${escapeHtml(x.test_id)}</b> ${escapeHtml((testInfoById(x.test_id)||{}).title || '')}<small>${escapeHtml(x.reason)}</small></span>${x.done ? `<span class="badge green">${t('statusDoneLabel')}</span>` : ''}
        </button>`).join('')}</div>` : ''}
      ${row.type !== 'technology' ? `<div class="asm-endpoint-findings-label" style="margin-top:14px">${t('pwAssetsMapFindingsLabel')}</div>
      ${matched.length ? matched.map(f => `
        <div class="asm-endpoint-finding-row">
          <span class="finding-code">${escapeHtml(f.finding_code)}</span>
          <span class="severity-badge sev-${escapeHtml(f.severity || 'info')}">${t('severity_'+(f.severity || 'info'))}</span>
          <span>${escapeHtml(f.title)}</span>
        </div>`).join('') : `<div class="import-preview-source">${t('pwAssetsMapNoFindings')}</div>`}` : `<p class="as-note">${t('asTechNoHost')}</p>`}`;
    const btn = document.getElementById('asmCreateFindingBtn');
    if(btn) btn.addEventListener('click', ()=>{
      openFindingModal(null, { title: row.value, endpoint: row.value });
    });
  }

  function asRefreshLists(){
    renderAsMap();
    renderAsInventory();
  }

  function selectAsAsset(key){
    asSelectedKey = key;
    asRefreshLists();
    renderAsDetail(key);
    const box = document.getElementById('asmEndpointDetail');
    if(box && box.style.display !== 'none'){
      box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      box.focus({ preventScroll: true });
    }
  }

  function wireAttackSurface(content){
    // pwContent her sekmede yeniden kullanıldığından dinleyiciyi bir kez bağlarız.
    if(content._asWired) return;
    content._asWired = true;
    content.addEventListener('click', e=>{
      if(activePwTab !== 'assets' || !asState) return;
      const action = e.target.closest('[data-as-action]');
      if(action){
        const a = action.dataset.asAction;
        if(a === 'open-recon'){ closeProjectWorkspace(); openReconModal(); }
        if(a === 'clear-filters'){ asFilters = { q: '', type: 'all', scope: 'all', hideStatic: false }; saveHideStatic(false); renderAttackSurface(); }
        if(a === 'toggle-suggestions'){ asShowAllSuggestions = !asShowAllSuggestions; renderAsSuggestions(); }
        return;
      }
      const view = e.target.closest('[data-as-view]');
      if(view){ asView = view.dataset.asView; renderAttackSurface(); return; }
      const typeTile = e.target.closest('[data-as-type]');
      if(typeTile){ asFilters.type = asFilters.type === typeTile.dataset.asType ? 'all' : typeTile.dataset.asType; renderAttackSurface(); return; }
      const more = e.target.closest('[data-as-more]');
      if(more){ asFilters.type = more.dataset.asMore; asView = 'list'; renderAttackSurface(); return; }
      const test = e.target.closest('[data-as-test]');
      if(test){
        const meta = testInfoById(test.dataset.asTest);
        if(meta){ closeProjectWorkspace(); openCategory(meta.catId, test.dataset.asTest); }
        return;
      }
      const copy = e.target.closest('[data-as-copy]');
      if(copy){ copyToClipboard(copy.dataset.asCopy); return; }
      if(e.target.closest('a[href]')) return; // link: tarayıcı yeni sekmede açar
      const node = e.target.closest('[data-as-key]');
      if(node){ selectAsAsset(node.dataset.asKey); return; }
      // Satırın boş bir yerine tıklama da detayı açar; metin seçiliyorsa açmaz.
      const tr = e.target.closest('tr[data-as-row]');
      if(tr && !(window.getSelection && String(window.getSelection()).trim())) selectAsAsset(tr.dataset.asRow);
    });
    content.addEventListener('input', e=>{
      if(activePwTab !== 'assets' || !asState || e.target.id !== 'asSearch') return;
      asFilters.q = e.target.value;
      asRefreshLists();
    });
    content.addEventListener('change', e=>{
      if(activePwTab !== 'assets' || !asState) return;
      if(e.target.id === 'asTypeFilter'){ asFilters.type = e.target.value; asRefreshLists(); }
      if(e.target.id === 'asScopeFilter'){ asFilters.scope = e.target.value; asRefreshLists(); }
      if(e.target.id === 'asHideStatic'){ asFilters.hideStatic = e.target.checked; saveHideStatic(e.target.checked); asRefreshLists(); }
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

  function buildFindingPayload(){
    const title = document.getElementById('findingTitleInput').value.trim();
    if(!title){ showToast(t('findingTitleRequired')); return null; }
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
    return payload;
  }

  let pendingFindingPayload = null;
  let dupCandidates = [];

  function submitFindingForm(){
    const payload = buildFindingPayload();
    if(!payload) return;

    apiRequest(`/projects/${currentProjectId}/findings/check-duplicates`, {
      method: 'POST',
      body: JSON.stringify({
        title: payload.title, description: payload.description,
        endpoint: payload.endpoint, cwe: payload.cwe, test_id: payload.test_id,
        exclude_id: editingFindingId
      })
    }).then(res => {
      if(res.matches && res.matches.length){
        openDuplicateAlert(res.matches, payload);
      } else {
        actuallySaveFinding(payload);
      }
    }).catch(()=> actuallySaveFinding(payload)); // duplicate kontrolu basarisiz olursa kaydetmeyi ENGELLEMEZ
  }

  function actuallySaveFinding(payload){
    const req = editingFindingId
      ? apiRequest(`/projects/${currentProjectId}/findings/${editingFindingId}`, { method: 'PUT', body: JSON.stringify(payload) })
      : apiRequest(`/projects/${currentProjectId}/findings`, { method: 'POST', body: JSON.stringify(payload) });

    req.then(()=>{
      showToast(t('findingSaved'));
      closeDuplicateAlert();
      closeFindingModal();
      renderPwFindings();
    }).catch(err => showToast(err.message || t('resultSaveError')));
  }

  const DUP_REASON_KEYS = {
    similar_title: 'dupReasonSimilarTitle',
    similar_description: 'dupReasonSimilarDescription',
    same_endpoint: 'dupReasonSameEndpoint',
    same_cwe: 'dupReasonSameCwe',
    same_test_id: 'dupReasonSameTestId',
    likely_same_root_cause: 'dupReasonSameRootCause',
  };

  function openDuplicateAlert(matches, payload){
    pendingFindingPayload = payload;
    dupCandidates = matches;
    document.getElementById('dupAlertList').innerHTML = matches.map((m, i) => `
      <div class="import-preview-item">
        <label class="dup-candidate-row">
          <input type="checkbox" class="dup-candidate-check" data-idx="${i}">
          <div class="import-preview-body">
            <div class="import-preview-top">
              <span class="import-preview-title">${escapeHtml(m.finding.finding_code || '')} — ${escapeHtml(m.finding.title)}</span>
              <span class="severity-badge sev-${m.finding.severity}">${t('severity_'+m.finding.severity)}</span>
              <span class="dup-score-badge">${Math.round(m.score)}%</span>
            </div>
            <div class="import-preview-detail">${m.reasons.map(r => t(DUP_REASON_KEYS[r] || r)).join(' · ')}</div>
          </div>
        </label>
        <button type="button" class="planner-goto-btn dup-view-btn" data-idx="${i}" data-i18n="viewDetailsBtn">${t('viewDetailsBtn')}</button>
      </div>`).join('');
    document.getElementById('duplicateAlertOverlay').classList.add('open');
  }

  function closeDuplicateAlert(){
    document.getElementById('duplicateAlertOverlay').classList.remove('open');
    pendingFindingPayload = null;
    dupCandidates = [];
  }

  // --- AI Report Assistant (finding modal butonlari) ---
  // Ilke: AI hicbir alani DOGRUDAN kaydetmez -- sadece ilgili textarea'yi
  // doldurur, kullanici gozden gecirip "Kaydet"e basmadan hicbir sey
  // veritabanina yazilmaz.
  function setAiAssistantBusy(busy, message){
    const statusEl = document.getElementById('aiAssistantStatus');
    statusEl.textContent = message || (busy ? t('aiWorking') : '');
    document.querySelectorAll('.ai-assistant-actions button').forEach(b => b.disabled = busy);
  }

  function handleAiError(err){
    if(err && err.body && err.body.ai_configured === false){
      setAiAssistantBusy(false, t('aiNotConfigured'));
    } else {
      setAiAssistantBusy(false, '');
    }
    showToast((err && err.message) || t('resultSaveError'));
  }

  function runFindingAiAction(endpoint, onSuccess){
    if(!editingFindingId){
      showToast(t('aiSaveFirst'));
      return;
    }
    setAiAssistantBusy(true);
    apiRequest(`/projects/${currentProjectId}/findings/${editingFindingId}/ai/${endpoint}`, {
      method: 'POST', body: JSON.stringify({ lang: currentLang })
    }).then(res => {
      setAiAssistantBusy(false, t('aiDone'));
      onSuccess(res);
    }).catch(handleAiError);
  }

  function initAiAssistantButtons(){
    document.getElementById('aiGenDescBtn').addEventListener('click', ()=>{
      runFindingAiAction('description', res => {
        document.getElementById('findingDescInput').value = res.description;
      });
    });
    document.getElementById('aiGenRemediationBtn').addEventListener('click', ()=>{
      runFindingAiAction('remediation', res => {
        document.getElementById('findingRemediationInput').value = res.remediation;
      });
    });
    document.getElementById('aiSuggestCweBtn').addEventListener('click', ()=>{
      runFindingAiAction('analyze', res => {
        if(res.suggested_cwe_id) document.getElementById('findingCweInput').value = res.suggested_cwe_id;
        if(res.suggested_cvss_vector){
          const parsed = parseCvssVector(res.suggested_cvss_vector);
          if(parsed){ currentCvssMetrics = parsed; renderCvssCalculator(); }
        }
        showToast(res.rationale || t('aiDone'));
      });
    });
    document.getElementById('aiRewriteDescBtn').addEventListener('click', ()=>{
      const textEl = document.getElementById('findingDescInput');
      const text = textEl.value.trim();
      if(!text){ showToast(t('aiNoTextToRewrite')); return; }
      setAiAssistantBusy(true);
      apiRequest('/ai/rewrite', { method: 'POST', body: JSON.stringify({ text, lang: currentLang }) })
        .then(res => {
          setAiAssistantBusy(false, t('aiDone'));
          textEl.value = res.text;
        }).catch(handleAiError);
    });
    document.getElementById('aiFindSimilarBtn').addEventListener('click', ()=>{
      const payload = buildFindingPayload();
      if(!payload) return;
      setAiAssistantBusy(true);
      apiRequest(`/projects/${currentProjectId}/findings/check-duplicates`, {
        method: 'POST',
        body: JSON.stringify({
          title: payload.title, description: payload.description,
          endpoint: payload.endpoint, cwe: payload.cwe, test_id: payload.test_id,
          exclude_id: editingFindingId
        })
      }).then(res => {
        setAiAssistantBusy(false, '');
        if(res.matches && res.matches.length){
          openDuplicateAlert(res.matches, payload);
        } else {
          showToast(t('dupNoneFound'));
        }
      }).catch(handleAiError);
    });
  }

  // --- BYOK: Kendi API Key'inle Kullan (bu oturuma özel, sunucuya kaydedilmez) ---
  const BYOK_PROVIDERS_META = [
    { id: 'anthropic', icon: 'A', label: 'Anthropic', defaultModel: 'claude-sonnet-5', needsKey: true, needsBaseUrl: false, placeholder: 'sk-ant-...' },
    { id: 'openai', icon: 'O', label: 'OpenAI', defaultModel: 'gpt-5.6-terra', needsKey: true, needsBaseUrl: false, placeholder: 'sk-...' },
    { id: 'gemini', icon: 'G', label: 'Gemini', defaultModel: 'gemini-3.7-flash', needsKey: true, needsBaseUrl: false, placeholder: 'AIza...' },
    { id: 'ollama', icon: 'L', label: 'Ollama', defaultModel: 'llama3.1', needsKey: false, needsBaseUrl: true, placeholder: '(gerekmez)' },
  ];
  let byokSelectedProvider = 'anthropic';

  function updateByokDot(){
    const dot = document.getElementById('byokDot');
    if(!dot) return;
    dot.classList.toggle('active', !!loadByok());
  }

  function renderByokProviderGrid(){
    const grid = document.getElementById('byokProviderGrid');
    if(!grid) return;
    grid.innerHTML = BYOK_PROVIDERS_META.map(meta => `
      <button type="button" class="byok-provider-card ${meta.id === byokSelectedProvider ? 'selected' : ''}" data-provider="${meta.id}">
        <span class="byok-provider-icon">${meta.icon}</span>
        <span class="byok-provider-name">${meta.label}</span>
      </button>
    `).join('');
  }

  function applyByokProviderFields(){
    const meta = BYOK_PROVIDERS_META.find(m => m.id === byokSelectedProvider) || BYOK_PROVIDERS_META[0];
    const keyLabel = document.getElementById('byokKeyLabel');
    const keyWrap = document.getElementById('byokKeyInput').closest('.ai-key-input-wrap');
    const baseUrlLabel = document.getElementById('byokBaseUrlLabel');
    const baseUrlInput = document.getElementById('byokBaseUrlInput');
    const keyInput = document.getElementById('byokKeyInput');
    keyInput.placeholder = meta.placeholder;
    if(meta.needsKey){ keyLabel.style.display = ''; keyWrap.style.display = ''; }
    else { keyLabel.style.display = 'none'; keyWrap.style.display = 'none'; }
    if(meta.needsBaseUrl){ baseUrlLabel.style.display = ''; baseUrlInput.style.display = ''; }
    else { baseUrlLabel.style.display = 'none'; baseUrlInput.style.display = 'none'; }
    document.getElementById('byokModelInput').placeholder = meta.defaultModel;
  }

  function refreshByokStatusStrip(){
    const strip = document.getElementById('byokStatusStrip');
    const dot = document.getElementById('byokStatusDot');
    const text = document.getElementById('byokStatusText');
    const clearBtn = document.getElementById('byokClearBtn');
    const cfg = loadByok();
    if(cfg){
      strip.classList.add('active');
      dot.classList.add('active');
      const meta = BYOK_PROVIDERS_META.find(m => m.id === cfg.provider);
      text.textContent = t('byokStatusOn').replace('{provider}', (meta && meta.label) || cfg.provider).replace('{model}', cfg.model || '');
      clearBtn.style.display = '';
    } else {
      strip.classList.remove('active');
      dot.classList.remove('active');
      text.textContent = t('byokStatusOff');
      clearBtn.style.display = 'none';
    }
  }

  function openByokModal(){
    const cfg = loadByok();
    byokSelectedProvider = (cfg && cfg.provider) || 'anthropic';
    renderByokProviderGrid();
    applyByokProviderFields();
    document.getElementById('byokKeyInput').value = (cfg && cfg.api_key) || '';
    document.getElementById('byokModelInput').value = (cfg && cfg.model) || '';
    document.getElementById('byokBaseUrlInput').value = (cfg && cfg.base_url) || '';
    document.getElementById('byokTestStatus').textContent = '';
    document.getElementById('byokTestStatus').className = 'ai-provider-status';
    refreshByokStatusStrip();
    document.getElementById('byokOverlay').classList.add('open');
  }
  function closeByokModal(){
    document.getElementById('byokOverlay').classList.remove('open');
  }

  function readByokFormValues(){
    const meta = BYOK_PROVIDERS_META.find(m => m.id === byokSelectedProvider) || BYOK_PROVIDERS_META[0];
    return {
      provider: byokSelectedProvider,
      api_key: document.getElementById('byokKeyInput').value.trim(),
      model: document.getElementById('byokModelInput').value.trim() || meta.defaultModel,
      base_url: document.getElementById('byokBaseUrlInput').value.trim(),
    };
  }

  function wireByokModal(){
    const topbarBtn = document.getElementById('topbarByokBtn');
    if(topbarBtn) topbarBtn.addEventListener('click', openByokModal);
    document.getElementById('closeByokOverlay').addEventListener('click', closeByokModal);
    document.getElementById('byokOverlay').addEventListener('click', e=>{
      if(e.target.id === 'byokOverlay') closeByokModal();
    });

    document.getElementById('byokProviderGrid').addEventListener('click', e=>{
      const card = e.target.closest('.byok-provider-card');
      if(!card) return;
      byokSelectedProvider = card.dataset.provider;
      renderByokProviderGrid();
      applyByokProviderFields();
    });

    document.getElementById('byokKeyToggleBtn').addEventListener('click', ()=>{
      const input = document.getElementById('byokKeyInput');
      input.type = input.type === 'password' ? 'text' : 'password';
    });

    document.getElementById('byokActivateBtn').addEventListener('click', ()=>{
      const meta = BYOK_PROVIDERS_META.find(m => m.id === byokSelectedProvider);
      const values = readByokFormValues();
      if(!values.provider){ showToast(t('byokMissingProvider')); return; }
      if(meta.needsKey && !values.api_key){ showToast(t('byokMissingKey')); return; }
      saveByok(values);
      refreshByokStatusStrip();
      updateByokDot();
      showToast(t('byokActivatedToast'));
    });

    document.getElementById('byokClearBtn').addEventListener('click', ()=>{
      clearByok();
      document.getElementById('byokKeyInput').value = '';
      document.getElementById('byokModelInput').value = '';
      document.getElementById('byokBaseUrlInput').value = '';
      refreshByokStatusStrip();
      updateByokDot();
      showToast(t('byokClearedToast'));
    });

    document.getElementById('byokTestBtn').addEventListener('click', ()=>{
      const meta = BYOK_PROVIDERS_META.find(m => m.id === byokSelectedProvider);
      const values = readByokFormValues();
      if(meta.needsKey && !values.api_key){ showToast(t('byokMissingKey')); return; }
      const statusEl = document.getElementById('byokTestStatus');
      statusEl.className = 'ai-provider-status';
      statusEl.textContent = t('aiWorking');
      const headers = { 'Content-Type': 'application/json', 'X-AI-Provider': values.provider };
      if(values.api_key) headers['X-AI-Api-Key'] = values.api_key;
      if(values.model) headers['X-AI-Model'] = values.model;
      if(values.base_url) headers['X-AI-Base-Url'] = values.base_url;
      apiFetch('/ai/ping', { method: 'POST', headers })
        .then(async res => {
          const body = await res.json().catch(()=>({}));
          if(res.ok && body.ok !== false){
            statusEl.className = 'ai-provider-status success';
            statusEl.textContent = `✓ ${t('aiTestSuccess')} (${body.provider || values.provider}${body.latency_ms ? ' · ' + body.latency_ms + 'ms' : ''})`;
          } else {
            statusEl.className = 'ai-provider-status failure';
            statusEl.textContent = `✗ ${t('aiTestFailed')}: ${body.error || res.statusText}`;
          }
        })
        .catch(err => {
          statusEl.className = 'ai-provider-status failure';
          statusEl.textContent = `✗ ${t('aiTestFailed')}: ${err.message || err}`;
        });
    });
  }

  // --- AI Ayarları (API key yönetimi UI'dan) ---
  // Key'ler ASLA tam olarak burada tutulmaz/gösterilmez -- backend sadece
  // maskelenmiş hali (api_key_masked) döner, input placeholder'ı bunu
  // gösterir. Kaydetme sırasında input boş bırakılırsa mevcut key korunur.
  const AI_PROVIDERS_META = [
    { id: 'gemini', label: 'Gemini', defaultModel: 'gemini-3.7-flash', needsKey: true, needsBaseUrl: false },
    { id: 'openai', label: 'OpenAI', defaultModel: 'gpt-5.6-terra', needsKey: true, needsBaseUrl: false },
    { id: 'anthropic', label: 'Anthropic', defaultModel: 'claude-sonnet-5', needsKey: true, needsBaseUrl: false },
    { id: 'ollama', label: 'Ollama', defaultModel: 'llama3.1', needsKey: false, needsBaseUrl: true },
  ];

  function renderAiStatusBadge(){
    const badge = document.getElementById('aiStatusBadge');
    if(!badge) return;
    apiRequest('/ai/status').then(res => {
      if(res.configured){
        badge.textContent = `${res.provider} ${t('aiStatusWorkingWith')}`;
        badge.className = 'ai-status-badge configured';
      } else {
        badge.textContent = `${t('aiStatusNotConfigured')}`;
        badge.className = 'ai-status-badge not-configured';
      }
    }).catch(()=>{ badge.textContent = ''; });
  }

  function openAiSettingsModal(){
    document.getElementById('aiSettingsOverlay').classList.add('open');
    renderAiProviderList();
  }
  function closeAiSettingsModal(){
    document.getElementById('aiSettingsOverlay').classList.remove('open');
  }

  function renderAiProviderList(){
    const container = document.getElementById('aiProviderList');
    container.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest('/ai/settings').then(settings => {
      const byProvider = {};
      settings.forEach(s => { byProvider[s.provider] = s; });
      container.innerHTML = AI_PROVIDERS_META.map(meta => {
        const s = byProvider[meta.id] || null;
        const isActive = !!(s && s.is_active);
        const hasKey = !!(s && s.has_key);
        const maskedKey = (s && s.api_key_masked) || '';
        const model = (s && s.model) || meta.defaultModel;
        const baseUrl = (s && s.base_url) || 'http://localhost:11434';
        const keyPlaceholder = hasKey ? t('aiKeySavedPlaceholder').replace('{key}', maskedKey) : t('aiKeyEmptyPlaceholder');
        return `
        <div class="ai-provider-row" data-provider="${meta.id}">
          <div class="ai-provider-header">
            <span class="ai-provider-name">${meta.label}</span>
            ${isActive ? `<span class="ai-provider-active-badge">✓ ${t('aiActiveLabel')}</span>` : ''}
          </div>
          <div class="finding-form-row">
            ${meta.needsKey ? `
            <div>
              <label>${t('aiApiKeyLabel')}</label>
              <div class="ai-key-input-wrap">
                <input type="password" class="ai-key-input" placeholder="${escapeHtml(keyPlaceholder)}">
                <button type="button" class="ai-key-toggle-btn" title="${t('aiToggleVisibility')}"><svg class="i i-sm" viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button>
              </div>
            </div>` : ''}
            <div>
              <label>${t('aiModelLabel')}</label>
              <input type="text" class="ai-model-input" value="${escapeHtml(model)}">
            </div>
          </div>
          ${meta.needsBaseUrl ? `
          <label>${t('aiBaseUrlLabel')}</label>
          <input type="text" class="ai-baseurl-input" value="${escapeHtml(baseUrl)}">` : ''}
          <div class="ai-provider-actions">
            <button type="button" class="btn btn-sm ai-save-btn">${t('saveBtn')}</button>
            <button type="button" class="btn btn-sm ai-test-btn">${t('aiTestBtn')}</button>
            <button type="button" class="btn btn-sm ai-activate-btn" ${isActive ? 'disabled' : ''}>${t('aiActivateBtn')}</button>
            ${s ? `<button type="button" class="btn btn-sm danger ai-delete-btn">${t('aiDeleteBtn')}</button>` : ''}
          </div>
          <div class="ai-provider-status"></div>
        </div>`;
      }).join('');
    }).catch(err => {
      container.innerHTML = `<div class="search-empty">${escapeHtml(err.message || String(err))}</div>`;
    });
  }

  function wireAiSettingsModal(){
    document.getElementById('aiSettingsNavBtn').addEventListener('click', openAiSettingsModal);
    document.getElementById('closeAiSettingsOverlay').addEventListener('click', closeAiSettingsModal);
    document.getElementById('aiSettingsOverlay').addEventListener('click', e=>{
      if(e.target.id === 'aiSettingsOverlay') closeAiSettingsModal();
    });

    document.getElementById('aiProviderList').addEventListener('click', e=>{
      const row = e.target.closest('.ai-provider-row');
      if(!row) return;
      const provider = row.dataset.provider;
      const statusEl = row.querySelector('.ai-provider-status');
      const keyInput = row.querySelector('.ai-key-input');
      const modelInput = row.querySelector('.ai-model-input');
      const baseUrlInput = row.querySelector('.ai-baseurl-input');

      if(e.target.classList.contains('ai-key-toggle-btn')){
        if(keyInput) keyInput.type = keyInput.type === 'password' ? 'text' : 'password';
        return;
      }

      if(e.target.classList.contains('ai-save-btn')){
        const payload = { provider };
        if(modelInput) payload.model = modelInput.value.trim();
        if(baseUrlInput) payload.base_url = baseUrlInput.value.trim();
        if(keyInput && keyInput.value.trim()) payload.api_key = keyInput.value.trim();
        apiRequest('/ai/settings', { method: 'POST', body: JSON.stringify(payload) })
          .then(()=>{ showToast(t('aiSettingsSaved')); renderAiProviderList(); })
          .catch(err => showToast(err.message || t('resultSaveError')));
        return;
      }

      if(e.target.classList.contains('ai-activate-btn')){
        apiRequest('/ai/settings/activate', { method: 'POST', body: JSON.stringify({ provider }) })
          .then(()=>{ showToast(t('aiProviderActivated')); renderAiProviderList(); renderAiStatusBadge(); })
          .catch(err => showToast(err.message || t('resultSaveError')));
        return;
      }

      if(e.target.classList.contains('ai-delete-btn')){
        if(!confirm(t('aiDeleteConfirm'))) return;
        apiRequest(`/ai/settings/${provider}`, { method: 'DELETE' })
          .then(()=>{ showToast(t('aiSettingsDeleted')); renderAiProviderList(); renderAiStatusBadge(); })
          .catch(err => showToast(err.message || t('resultSaveError')));
        return;
      }

      if(e.target.classList.contains('ai-test-btn')){
        statusEl.textContent = t('aiWorking');
        statusEl.className = 'ai-provider-status';
        const payload = { provider };
        if(keyInput && keyInput.value.trim()) payload.api_key = keyInput.value.trim();
        if(baseUrlInput) payload.base_url = baseUrlInput.value.trim();
        apiRequest('/ai/settings/test', { method: 'POST', body: JSON.stringify(payload) })
          .then(res => {
            statusEl.textContent = `${t('aiTestSuccess')} (${res.latency_ms}ms)`;
            statusEl.className = 'ai-provider-status success';
          })
          .catch(err => {
            statusEl.textContent = `${err.message || t('aiTestFailed')}`;
            statusEl.className = 'ai-provider-status failure';
          });
      }
    });
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
            ${f.test_id ? `<span>${escapeHtml(f.test_id)}</span>` : ''}
            ${f.endpoint ? `<span>${escapeHtml(f.endpoint)}</span>` : ''}
            ${f.assigned_to ? `<span>${escapeHtml(f.assigned_to)}</span>` : ''}
          </div>
          <div class="project-card-actions">
            <button data-action="edit" data-id="${f.id}">${t('editBtn')}</button>
            <button data-action="delete" data-id="${f.id}" class="danger">${t('pwEvidenceDelete')}</button>
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

  // ========================
  // YETKİLENDİRME MATRİSİ (roller x endpoint'ler)
  // ========================
  // Saf mantık js/authz-matrix.js'te. Uygulama hedefe istek atmaz; gözlenen
  // sonuçları pentester kendi denemesine göre işaretler.
  const AZ = window.WSTGAuthz;
  let azDoc = null;
  let azProjectId = null;
  let azSelected = null;          // { kind: 'cell'|'role'|'endpoint', id }
  let azSaveTimer = null;
  let azSaveSeq = 0;

  function azLabel(v){
    return { allow: t('azExpAllow'), deny: t('azExpDeny'), allowed: t('azObsAllowed'), denied: t('azObsDenied') }[v] || '—';
  }

  function azSetStatus(text, isError){
    const el = document.getElementById('azSaveStatus');
    if(!el) return;
    el.textContent = text || '';
    el.classList.toggle('error', !!isError);
  }

  function azScheduleSave(){
    clearTimeout(azSaveTimer);
    azSetStatus(t('azSaving'));
    const pid = azProjectId;
    azSaveTimer = setTimeout(() => {
      const seq = ++azSaveSeq;
      const body = { roles: azDoc.roles, endpoints: azDoc.endpoints, cells: azDoc.cells };
      apiRequest(`/projects/${pid}/authz-matrix`, { method: 'PUT', body: JSON.stringify(body) })
        .then(() => { if(seq === azSaveSeq && pid === azProjectId) azSetStatus(t('azSaved')); })
        .catch(err => { if(seq === azSaveSeq) azSetStatus(err.message || t('resultSaveError'), true); });
    }, 500);
  }

  function azCellHtml(e, r){
    const key = AZ.cellKey(e.id, r.id);
    const cell = AZ.getCell(azDoc, e.id, r.id);
    const st = AZ.cellStatus(cell);
    const selected = azSelected && azSelected.kind === 'cell' && azSelected.id === key;
    const aria = `${r.name} · ${e.method} ${e.path}: ${t('azExpected')} ${azLabel(cell.expected)}, ${t('azObserved')} ${cell.observed ? azLabel(cell.observed) : t('azObsNone')}`;
    return `<button type="button" class="az-cell st-${st}${selected ? ' selected' : ''}" data-cell="${escapeHtml(key)}" aria-label="${escapeHtml(aria)}" title="${escapeHtml(aria)}">
      <span class="az-exp">${escapeHtml(cell.expected ? azLabel(cell.expected) : '—')}</span>
      <span class="az-obs">${escapeHtml(cell.observed ? azLabel(cell.observed) : t('azObsNoneShort'))}</span>
      ${cell.finding_id ? '<span class="az-flag" aria-hidden="true">●</span>' : ''}
    </button>`;
  }

  function azSummaryHtml(){
    const s = AZ.summarize(azDoc);
    return `<span class="badge">${escapeHtml(t('azSumCells')(s.cells))}</span>
      <span class="badge">${escapeHtml(t('azSumTested')(s.tested))}</span>
      <span class="badge ${s.violations ? 'red' : ''}">${escapeHtml(t('azSumViolations')(s.violations))}</span>
      <span class="badge ${s.over_restricted ? 'amber' : ''}">${escapeHtml(t('azSumOver')(s.over_restricted))}</span>
      <span class="badge">${escapeHtml(t('azSumUntested')(s.untested))}</span>`;
  }

  function azPendingViolations(){
    return AZ.violations(azDoc).filter(v => !v.cell.finding_id);
  }

  function azRefreshCounters(){
    const sum = document.getElementById('azSummary');
    if(sum) sum.innerHTML = azSummaryHtml();
    const btn = document.getElementById('azFindingsBtn');
    if(btn){
      const n = azPendingViolations().length;
      btn.disabled = !n;
      btn.textContent = t('azCreateFindingsBtn')(n);
    }
  }

  function azSegHtml(field, options, current){
    return `<div class="az-seg" role="group">${options.map(([val, label]) =>
      `<button type="button" class="${(current || null) === val ? 'active' : ''}" data-set="${field}" data-val="${val === null ? '' : val}">${escapeHtml(label)}</button>`).join('')}</div>`;
  }

  function azEditorHtml(){
    if(!azSelected) return `<p class="hint">${escapeHtml(t('azEditorHint'))}</p>`;
    if(azSelected.kind === 'role'){
      const r = azDoc.roles.find(x => x.id === azSelected.id);
      if(!r) return '';
      return `<h5>${escapeHtml(t('azRoleTitle'))}</h5>
        <form id="azRoleForm" class="session-form">
          <label for="azRoleRename">${escapeHtml(t('azRoleNameLabel'))}</label>
          <input type="text" id="azRoleRename" maxlength="60" value="${escapeHtml(r.name)}">
          <div class="hero-actions"><button type="submit" class="btn btn-primary btn-sm">${escapeHtml(t('saveBtn'))}</button>
          <button type="button" class="btn danger btn-sm" id="azDeleteRole">${escapeHtml(t('azDelete'))}</button></div>
        </form>`;
    }
    if(azSelected.kind === 'endpoint'){
      const e = azDoc.endpoints.find(x => x.id === azSelected.id);
      if(!e) return '';
      return `<h5>${escapeHtml(t('azEndpointTitle'))}</h5>
        <form id="azEndpointForm" class="session-form">
          <label for="azEpEditMethod">${escapeHtml(t('azMethod'))}</label>
          <select id="azEpEditMethod">${AZ.METHODS.map(m => `<option ${m === e.method ? 'selected' : ''}>${m}</option>`).join('')}</select>
          <label for="azEpEditPath">${escapeHtml(t('azPath'))}</label>
          <input type="text" id="azEpEditPath" class="mono" maxlength="500" value="${escapeHtml(e.path)}">
          <label for="azEpEditNote">${escapeHtml(t('azNote'))}</label>
          <input type="text" id="azEpEditNote" maxlength="500" value="${escapeHtml(e.note || '')}">
          <div class="hero-actions"><button type="submit" class="btn btn-primary btn-sm">${escapeHtml(t('saveBtn'))}</button>
          <button type="button" class="btn danger btn-sm" id="azDeleteEndpoint">${escapeHtml(t('azDelete'))}</button></div>
        </form>`;
    }
    const [eid, rid] = azSelected.id.split(':');
    const e = azDoc.endpoints.find(x => x.id === eid);
    const r = azDoc.roles.find(x => x.id === rid);
    if(!e || !r) return '';
    const cell = AZ.getCell(azDoc, eid, rid);
    const st = AZ.cellStatus(cell);
    const stText = { violation: t('azStViolation'), over: t('azStOver'), ok: t('azStOk'), observed: t('azStObserved'), untested: t('azStUntested'), unset: '' }[st];
    return `<h5>${escapeHtml(r.name)}</h5>
      <div class="az-editor-target"><span class="badge mono">${escapeHtml(e.method)}</span> <code>${escapeHtml(e.path)}</code></div>
      <label>${escapeHtml(t('azExpected'))}</label>
      ${azSegHtml('expected', [[null, '—'], ['allow', t('azExpAllow')], ['deny', t('azExpDeny')]], cell.expected)}
      <label>${escapeHtml(t('azObserved'))}</label>
      ${azSegHtml('observed', [[null, t('azObsNone')], ['allowed', t('azObsAllowed')], ['denied', t('azObsDenied')]], cell.observed)}
      ${stText ? `<p class="az-st-line st-${st}">${escapeHtml(stText)}</p>` : ''}
      <label for="azCellNote">${escapeHtml(t('azNote'))}</label>
      <textarea id="azCellNote" rows="3" maxlength="500" placeholder="${escapeHtml(t('azNotePlaceholder'))}">${escapeHtml(cell.note || '')}</textarea>
      <div class="hero-actions">
        <button type="button" class="btn btn-secondary btn-sm" id="azNextCell">${escapeHtml(t('azNextCell'))}</button>
        ${st === 'violation' && !cell.finding_id ? `<button type="button" class="btn btn-primary btn-sm" id="azCellFinding">${escapeHtml(t('azCreateOneFinding'))}</button>` : ''}
        ${cell.finding_id ? `<span class="badge mono">${escapeHtml('FND-' + String(cell.finding_id).padStart(4, '0'))}</span>` : ''}
      </div>`;
  }

  function azRenderEditor(){
    const el = document.getElementById('azEditor');
    if(el) el.innerHTML = azEditorHtml();
  }

  function azRefreshCell(key){
    const [eid, rid] = key.split(':');
    const e = azDoc.endpoints.find(x => x.id === eid);
    const r = azDoc.roles.find(x => x.id === rid);
    const btn = document.querySelector(`#azRoot .az-cell[data-cell="${CSS.escape(key)}"]`);
    if(!btn || !e || !r) return;
    btn.outerHTML = azCellHtml(e, r);
  }

  function azSelect(sel){
    const prev = azSelected;
    azSelected = sel;
    if(prev && prev.kind === 'cell') azRefreshCell(prev.id);
    if(sel && sel.kind === 'cell') azRefreshCell(sel.id);
    azRenderEditor();
  }

  function azSetCell(key, patch){
    const [eid, rid] = key.split(':');
    const cell = Object.assign(AZ.emptyCell(), AZ.getCell(azDoc, eid, rid), patch);
    if(!cell.expected && !cell.observed && !cell.note && !cell.finding_id) delete azDoc.cells[key];
    else azDoc.cells[key] = cell;
    azRefreshCell(key);
    azRefreshCounters();
    azScheduleSave();
  }

  function azRenderView(){
    const content = document.getElementById('pwContent');
    const roles = azDoc.roles, eps = azDoc.endpoints;
    const table = !roles.length ? `
      <div class="empty-state">
        <h3>${escapeHtml(t('azEmptyTitle'))}</h3>
        <p>${escapeHtml(t('azEmptyDesc'))}</p>
        <div class="hero-actions"><button type="button" class="btn btn-primary" id="azDefaultRolesBtn">${escapeHtml(t('azDefaultRolesBtn'))}</button></div>
      </div>` : `
      <div class="az-layout">
        <div class="table-wrap az-table-wrap" id="azTableWrap">
          <table class="table az-table">
            <thead><tr><th>${escapeHtml(t('azEndpointCol'))}</th>${roles.map(r =>
              `<th><button type="button" class="az-role${azSelected && azSelected.kind === 'role' && azSelected.id === r.id ? ' selected' : ''}" data-role="${escapeHtml(r.id)}">${escapeHtml(r.name)}</button></th>`).join('')}</tr></thead>
            <tbody>${eps.length ? eps.map(e => `<tr>
              <th scope="row"><button type="button" class="az-ep" data-ep="${escapeHtml(e.id)}" title="${escapeHtml(e.note || '')}">
                <span class="badge mono">${escapeHtml(e.method)}</span><span class="az-path">${escapeHtml(e.path)}</span></button></th>
              ${roles.map(r => `<td>${azCellHtml(e, r)}</td>`).join('')}</tr>`).join('')
              : `<tr><td colspan="${roles.length + 1}" class="search-empty">${escapeHtml(t('azNoEndpoints'))}</td></tr>`}</tbody>
          </table>
        </div>
        <aside class="az-editor" id="azEditor">${azEditorHtml()}</aside>
      </div>`;
    content.innerHTML = `<div id="azRoot" class="az-root">
      <p class="import-preview-source" style="margin-bottom:12px">${escapeHtml(t('azDesc'))}</p>
      <div class="az-summary" id="azSummary">${azSummaryHtml()}</div>
      <div class="az-toolbar">
        <form id="azAddRoleForm" class="az-inline">
          <input type="text" id="azNewRole" maxlength="60" placeholder="${escapeHtml(t('azNewRolePlaceholder'))}" aria-label="${escapeHtml(t('azNewRolePlaceholder'))}">
          <button type="submit" class="btn btn-secondary btn-sm">${escapeHtml(t('azAddRole'))}</button>
        </form>
        <form id="azAddEpForm" class="az-inline">
          <select id="azNewEpMethod" aria-label="${escapeHtml(t('azMethod'))}">${AZ.METHODS.map(m => `<option>${m}</option>`).join('')}</select>
          <input type="text" id="azNewEpPath" class="mono" maxlength="500" placeholder="/api/users/{id}" aria-label="${escapeHtml(t('azPath'))}">
          <button type="submit" class="btn btn-secondary btn-sm">${escapeHtml(t('azAddEndpoint'))}</button>
        </form>
      </div>
      <div class="az-toolbar">
        <button type="button" class="btn btn-secondary btn-sm" id="azFromSurfaceBtn">${escapeHtml(t('azFromSurface'))}</button>
        <button type="button" class="btn btn-secondary btn-sm" id="azCsvBtn" ${eps.length && roles.length ? '' : 'disabled'}>${escapeHtml(t('azCopyCsv'))}</button>
        <button type="button" class="btn btn-primary btn-sm" id="azFindingsBtn"></button>
        <span class="hint az-save-status" id="azSaveStatus" role="status"></span>
      </div>
      ${table}
    </div>`;
    azRefreshCounters();
    azBindView();
  }

  function renderPwAuthz(){
    const content = document.getElementById('pwContent');
    const pid = currentProjectId;
    if(!AZ){ content.innerHTML = `<div class="search-empty">${escapeHtml(t('azLoadError'))}</div>`; return; }
    content.innerHTML = `<div class="search-empty">${escapeHtml(t('loadingGeneric'))}</div>`;
    apiRequest(`/projects/${pid}/authz-matrix`).then(doc => {
      if(activePwTab !== 'authz' || pid !== currentProjectId) return;
      if(azProjectId !== pid) azSelected = null;
      azProjectId = pid;
      azDoc = { roles: doc.roles || [], endpoints: doc.endpoints || [], cells: doc.cells || {} };
      azRenderView();
      if(doc.updated_at){ const d = parseApiDate(doc.updated_at); if(d) azSetStatus(t('azLastSaved')(d.toLocaleString(t('dateLocale'), { dateStyle: 'medium', timeStyle: 'short' }))); }
    }).catch(err => {
      content.innerHTML = `<div class="search-empty">${escapeHtml(t('azLoadError'))}<br><small>${escapeHtml(err.message || '')}</small></div>`;
    });
  }

  function azNextCellKey(key){
    const keys = [];
    azDoc.endpoints.forEach(e => azDoc.roles.forEach(r => keys.push(AZ.cellKey(e.id, r.id))));
    const i = keys.indexOf(key);
    return keys.length ? keys[(i + 1) % keys.length] : null;
  }

  async function azCreateFindings(list){
    if(!list.length) return;
    const pid = azProjectId;
    const keyOf = (title, endpoint) => `${String(title || '').trim().toLowerCase()}|${String(endpoint || '').trim().toLowerCase()}`;
    const existing = await apiRequest(`/projects/${pid}/findings`);
    const byKey = new Map((existing || []).map(f => [keyOf(f.title, f.endpoint), f.id]));
    const sessionId = currentSession && currentSession.project_id === pid ? currentSession.id : null;
    let created = 0, linked = 0, failed = 0;
    for(const v of list){
      const draft = AZ.findingDraft(azDoc, v, currentLang);
      const k = keyOf(draft.title, draft.endpoint);
      let id = byKey.get(k);
      if(id){ linked++; }
      else{
        try{
          const f = await apiRequest(`/projects/${pid}/findings`, { method: 'POST', body: JSON.stringify(Object.assign({ session_id: sessionId }, draft)) });
          id = f.id; byKey.set(k, id); created++;
        }catch(e){ failed++; continue; }
      }
      const [eid, rid] = v.key.split(':');
      azDoc.cells[v.key] = Object.assign(AZ.emptyCell(), AZ.getCell(azDoc, eid, rid), { finding_id: id });
      azRefreshCell(v.key);
    }
    azRefreshCounters();
    azRenderEditor();
    azScheduleSave();
    showToast(t('azFindingsResult')(created, linked, failed));
  }

  function azRemoveCells(pred){
    Object.keys(azDoc.cells).forEach(k => { if(pred(k)) delete azDoc.cells[k]; });
  }

  function azBindView(){
    const root = document.getElementById('azRoot');
    root.addEventListener('click', e => {
      const cellBtn = e.target.closest('.az-cell');
      if(cellBtn){ azSelect({ kind: 'cell', id: cellBtn.dataset.cell }); return; }
      const roleBtn = e.target.closest('.az-role');
      if(roleBtn){ azSelected = { kind: 'role', id: roleBtn.dataset.role }; azRenderView(); return; }
      const epBtn = e.target.closest('.az-ep');
      if(epBtn){ azSelect({ kind: 'endpoint', id: epBtn.dataset.ep }); return; }
      const seg = e.target.closest('[data-set]');
      if(seg && azSelected && azSelected.kind === 'cell'){
        azSetCell(azSelected.id, { [seg.dataset.set]: seg.dataset.val || null });
        azRenderEditor();
        return;
      }
      if(e.target.closest('#azNextCell') && azSelected){ azSelect({ kind: 'cell', id: azNextCellKey(azSelected.id) }); return; }
      if(e.target.closest('#azCellFinding') && azSelected){
        const v = AZ.violations(azDoc).find(x => x.key === azSelected.id);
        if(v) azCreateFindings([v]).catch(err => showToast(err.message || t('resultSaveError')));
        return;
      }
      if(e.target.closest('#azDefaultRolesBtn')){
        azDoc.roles = AZ.defaultRoles(currentLang);
        azScheduleSave(); azRenderView(); return;
      }
      if(e.target.closest('#azDeleteRole') && azSelected){
        const r = azDoc.roles.find(x => x.id === azSelected.id);
        if(!r || !confirm(t('azDeleteRoleConfirm')(r.name))) return;
        azDoc.roles = azDoc.roles.filter(x => x.id !== r.id);
        azRemoveCells(k => k.split(':')[1] === r.id);
        azSelected = null; azScheduleSave(); azRenderView(); return;
      }
      if(e.target.closest('#azDeleteEndpoint') && azSelected){
        const ep = azDoc.endpoints.find(x => x.id === azSelected.id);
        if(!ep || !confirm(t('azDeleteEndpointConfirm')(`${ep.method} ${ep.path}`))) return;
        azDoc.endpoints = azDoc.endpoints.filter(x => x.id !== ep.id);
        azRemoveCells(k => k.split(':')[0] === ep.id);
        azSelected = null; azScheduleSave(); azRenderView(); return;
      }
      if(e.target.closest('#azCsvBtn')){
        copyToClipboard(AZ.toCsv(azDoc, { method: t('azMethod'), path: t('azPath'), allow: t('azExpAllow'), deny: t('azExpDeny'),
          allowed: t('azObsAllowed'), denied: t('azObsDenied'), none: '—' }));
        return;
      }
      if(e.target.closest('#azFindingsBtn')){
        azCreateFindings(azPendingViolations()).catch(err => showToast(err.message || t('resultSaveError')));
        return;
      }
      if(e.target.closest('#azFromSurfaceBtn')){
        apiRequest(`/projects/${azProjectId}/assets`).then(assets => {
          const items = window.WSTGAttackSurface
            ? window.WSTGAttackSurface.buildSurface(assets, [], new Set()).inventory.filter(r => r.type === 'endpoint').map(r => ({ method: 'GET', path: r.value }))
            : [];
          if(!items.length){ showToast(t('azNoSurfaceEndpoints')); return; }
          const res = AZ.addEndpoints(azDoc, items);
          azDoc = res.doc;
          if(res.added) azScheduleSave();
          azRenderView();
          showToast(t('azSurfaceAdded')(res.added, res.skipped));
        }).catch(err => showToast(err.message || t('resultSaveError')));
      }
    });
    root.addEventListener('input', e => {
      if(e.target.id === 'azCellNote' && azSelected && azSelected.kind === 'cell'){
        const key = azSelected.id;
        const [eid, rid] = key.split(':');
        const cell = Object.assign(AZ.emptyCell(), AZ.getCell(azDoc, eid, rid), { note: e.target.value.slice(0, 500) });
        if(!cell.expected && !cell.observed && !cell.note && !cell.finding_id) delete azDoc.cells[key];
        else azDoc.cells[key] = cell;
        azScheduleSave();
      }
    });
    root.addEventListener('submit', e => {
      e.preventDefault();
      if(e.target.id === 'azAddRoleForm'){
        const name = document.getElementById('azNewRole').value.trim().replace(/\s+/g, ' ');
        if(!name) return;
        if(azDoc.roles.length >= AZ.MAX_ROLES){ showToast(t('azTooManyRoles')(AZ.MAX_ROLES)); return; }
        if(azDoc.roles.some(r => r.name.toLocaleLowerCase(t('dateLocale')) === name.toLocaleLowerCase(t('dateLocale')))){ showToast(t('azRoleExists')); return; }
        azDoc.roles.push({ id: AZ.newId('r'), name: name.slice(0, 60) });
        azScheduleSave(); azRenderView();
        document.getElementById('azNewRole').focus();
      }
      if(e.target.id === 'azAddEpForm'){
        const res = AZ.addEndpoints(azDoc, [{ method: document.getElementById('azNewEpMethod').value, path: document.getElementById('azNewEpPath').value }]);
        if(!res.added){ showToast(t('azEndpointExists')); return; }
        azDoc = res.doc; azScheduleSave(); azRenderView();
        document.getElementById('azNewEpPath').focus();
      }
      if(e.target.id === 'azRoleForm' && azSelected){
        const name = document.getElementById('azRoleRename').value.trim().replace(/\s+/g, ' ');
        const r = azDoc.roles.find(x => x.id === azSelected.id);
        if(!r || !name) return;
        if(azDoc.roles.some(x => x.id !== r.id && x.name.toLocaleLowerCase(t('dateLocale')) === name.toLocaleLowerCase(t('dateLocale')))){ showToast(t('azRoleExists')); return; }
        r.name = name.slice(0, 60); azScheduleSave(); azRenderView();
      }
      if(e.target.id === 'azEndpointForm' && azSelected){
        const ep = azDoc.endpoints.find(x => x.id === azSelected.id);
        if(!ep) return;
        const method = document.getElementById('azEpEditMethod').value;
        const path = AZ.normalizePath(document.getElementById('azEpEditPath').value);
        if(!path) return;
        if(azDoc.endpoints.some(x => x.id !== ep.id && x.method === method && x.path === path)){ showToast(t('azEndpointExists')); return; }
        ep.method = method; ep.path = path; ep.note = document.getElementById('azEpEditNote').value.trim().slice(0, 500);
        azScheduleSave(); azRenderView();
      }
    });
  }

  // ========================
  // YENİDEN TEST (retest)
  // ========================
  // Durum sınıflandırması backend/retest.py'de; burada liste, işaretleme ve rapor.
  let rtFilter = 'pending';
  let rtData = null;
  const RT_FILTERS = ['pending', 'still_open', 'verified', 'other', 'all'];

  function rtMatches(f, filter){
    if(filter === 'all') return true;
    if(filter === 'other') return !f.retest_state && (f.status === 'open' || f.status === 'confirmed');
    return f.retest_state === filter;
  }

  function rtStateBadge(f){
    if(!f.retest_state) return `<span class="finding-status-badge status-${escapeHtml(f.status)}">${escapeHtml(t('findingStatus_' + f.status))}</span>`;
    const cls = { pending: 'amber', still_open: 'red', verified: 'green' }[f.retest_state];
    return `<span class="badge ${cls}">${escapeHtml(t('rtState_' + f.retest_state))}</span>`;
  }

  function rtCardHtml(f){
    const sev = SEVERITIES.indexOf(f.severity) !== -1 ? f.severity : 'info';
    const when = f.retested_at ? parseApiDate(f.retested_at) : null;
    const last = f.retest_result === 'fixed' || f.retest_result === 'not_fixed'
      ? `<span>${escapeHtml(t('rtLastRetest'))}: ${escapeHtml(t('rtResult_' + f.retest_result))}${when ? ' · ' + escapeHtml(when.toLocaleString(t('dateLocale'), { dateStyle: 'medium', timeStyle: 'short' })) : ''}</span>` : '';
    const evidence = (f.evidence || []).map(ev =>
      `<a class="badge mono" href="${escapeHtml(API_BASE + '/evidence/' + Number(ev.id) + '/file')}" target="_blank" rel="noopener noreferrer">${escapeHtml(ev.filename || ('#' + ev.id))}</a>`).join('');
    const canMark = f.retest_state || f.status === 'fixed' || f.status === 'retest_pending';
    const actions = canMark ? `
        <textarea class="rt-note" data-id="${Number(f.id)}" rows="2" maxlength="5000" placeholder="${escapeHtml(t('rtNotePlaceholder'))}">${escapeHtml(f.retest_notes || '')}</textarea>
        <div class="rt-actions">
          <button type="button" class="btn btn-sm rt-fixed" data-act="fixed" data-id="${Number(f.id)}">${escapeHtml(t('rtMarkFixed'))}</button>
          <button type="button" class="btn btn-sm rt-open" data-act="not_fixed" data-id="${Number(f.id)}">${escapeHtml(t('rtMarkOpen'))}</button>
          <label class="btn btn-secondary btn-sm rt-upload">${escapeHtml(t('rtAddEvidence'))}
            <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" data-evidence="${Number(f.id)}" hidden></label>
        </div>`
      : `<div class="rt-actions"><button type="button" class="btn btn-secondary btn-sm" data-act="request" data-id="${Number(f.id)}">${escapeHtml(t('rtRequest'))}</button></div>`;
    return `<div class="finding-card rt-card" data-id="${Number(f.id)}">
      <div class="finding-card-top">
        <span class="finding-code">${escapeHtml(f.finding_code || '')}</span>
        <span class="severity-badge sev-${sev}">${escapeHtml(t('severity_' + sev))}</span>
        ${rtStateBadge(f)}
      </div>
      <div class="finding-card-title">${escapeHtml(f.title || '')}</div>
      <div class="finding-card-meta">
        ${f.endpoint ? `<span>${escapeHtml(f.endpoint)}</span>` : ''}
        ${last}
      </div>
      ${evidence ? `<div class="rt-evidence">${evidence}</div>` : ''}
      ${actions}
    </div>`;
  }

  function rtRenderList(){
    const box = document.getElementById('rtList');
    if(!box || !rtData) return;
    const items = rtData.findings.filter(f => rtMatches(f, rtFilter));
    document.querySelectorAll('#rtFilters button').forEach(b => b.classList.toggle('active', b.dataset.filter === rtFilter));
    box.innerHTML = items.length ? items.map(rtCardHtml).join('') : `<div class="search-empty">${escapeHtml(t('rtEmpty_' + rtFilter))}</div>`;
  }

  function rtCounts(){
    const c = { pending: 0, still_open: 0, verified: 0, other: 0, all: rtData.findings.length };
    rtData.findings.forEach(f => RT_FILTERS.forEach(k => { if(k !== 'all' && rtMatches(f, k)) c[k]++; }));
    return c;
  }

  function rtRenderView(){
    const content = document.getElementById('pwContent');
    const c = rtCounts();
    content.innerHTML = `<div id="rtRoot">
      <p class="import-preview-source" style="margin-bottom:12px">${escapeHtml(t('rtDesc'))}</p>
      <div class="rt-summary">
        <div class="rt-stat pending"><b>${c.pending}</b><span>${escapeHtml(t('rtState_pending'))}</span></div>
        <div class="rt-stat still_open"><b>${c.still_open}</b><span>${escapeHtml(t('rtState_still_open'))}</span></div>
        <div class="rt-stat verified"><b>${c.verified}</b><span>${escapeHtml(t('rtState_verified'))}</span></div>
      </div>
      <div class="az-toolbar">
        <button type="button" class="btn btn-primary btn-sm" id="rtPdfBtn">${escapeHtml(t('rtReportPdf'))}</button>
        <button type="button" class="btn btn-secondary btn-sm" id="rtHtmlBtn">${escapeHtml(t('rtReportHtml'))}</button>
        <label class="recon-auth-check rt-inline-check"><input type="checkbox" id="rtIncludePending" checked><span>${escapeHtml(t('rtIncludePending'))}</span></label>
        <span class="hint" id="rtStatus" role="status"></span>
      </div>
      <div class="az-seg rt-filters" id="rtFilters" role="group">${RT_FILTERS.map(k =>
        `<button type="button" data-filter="${k}">${escapeHtml(t('rtFilter_' + k))} (${c[k]})</button>`).join('')}</div>
      <div id="rtList" class="rt-list"></div>
    </div>`;
    rtRenderList();
    rtBind();
  }

  function renderPwRetest(){
    const content = document.getElementById('pwContent');
    const pid = currentProjectId;
    content.innerHTML = `<div class="search-empty">${escapeHtml(t('loadingGeneric'))}</div>`;
    apiRequest(`/projects/${pid}/retest`).then(data => {
      if(activePwTab !== 'retest' || pid !== currentProjectId) return;
      rtData = data;
      const c = rtCounts();
      if(!c[rtFilter]) rtFilter = c.pending ? 'pending' : c.still_open ? 'still_open' : c.verified ? 'verified' : c.other ? 'other' : 'all';
      rtRenderView();
    }).catch(err => {
      content.innerHTML = `<div class="search-empty">${escapeHtml(err.message || t('resultSaveError'))}</div>`;
    });
  }

  function rtReportPayload(){
    return { lang: currentLang, include_pending: document.getElementById('rtIncludePending').checked };
  }

  function rtBind(){
    const root = document.getElementById('rtRoot');
    const pid = currentProjectId;
    root.addEventListener('click', e => {
      const fb = e.target.closest('#rtFilters button');
      if(fb){ rtFilter = fb.dataset.filter; rtRenderList(); return; }
      const act = e.target.closest('[data-act]');
      if(act){
        const id = Number(act.dataset.id);
        act.disabled = true;
        let req;
        if(act.dataset.act === 'request'){
          req = apiRequest(`/projects/${pid}/findings/${id}`, { method: 'PUT', body: JSON.stringify({ status: 'retest_pending' }) });
        } else {
          const note = root.querySelector(`.rt-note[data-id="${id}"]`);
          req = apiRequest(`/projects/${pid}/findings/${id}/retest`, { method: 'POST',
            body: JSON.stringify({ result: act.dataset.act, notes: note ? note.value : '' }) });
        }
        req.then(() => {
          showToast(t(act.dataset.act === 'fixed' ? 'rtToastFixed' : act.dataset.act === 'not_fixed' ? 'rtToastOpen' : 'rtToastRequested'));
          renderPwRetest();
        }).catch(err => { act.disabled = false; showToast(err.message || t('resultSaveError')); });
        return;
      }
      if(e.target.closest('#rtHtmlBtn')){
        const w = window.open('', '_blank');
        apiFetch(`/projects/${pid}/reports/retest/html`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rtReportPayload()) })
          .then(res => { if(!res.ok) throw new Error('report'); return res.text(); })
          .then(html => { if(w){ w.document.open(); w.document.write(html); w.document.close(); } })
          .catch(() => { if(w) w.close(); showToast(t('resultSaveError')); });
        return;
      }
      if(e.target.closest('#rtPdfBtn')){
        const btn = document.getElementById('rtPdfBtn');
        const status = document.getElementById('rtStatus');
        btn.disabled = true; status.textContent = t('reportPdfGenerating');
        apiFetch(`/projects/${pid}/reports/retest/pdf`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rtReportPayload()) })
          .then(async res => {
            if(!res.ok){ const b = await res.json().catch(() => ({})); throw new Error(b.error || 'PDF'); }
            return res.blob();
          }).then(blob => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `${(currentProjectObj && currentProjectObj.name) || 'proje'}-${t('rtFileSuffix')}.pdf`;
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 4000);
            status.textContent = '';
          }).catch(err => { status.textContent = err.message || t('resultSaveError'); })
          .finally(() => { btn.disabled = false; });
      }
    });
    root.addEventListener('change', e => {
      const input = e.target.closest('input[data-evidence]');
      if(!input || !input.files || !input.files[0]) return;
      const fd = new FormData();
      fd.append('file', input.files[0]);
      fd.append('linked_finding_id', input.dataset.evidence);
      apiFetch(`/projects/${pid}/evidence`, { method: 'POST', body: fd })
        .then(async res => {
          const body = await res.json().catch(() => ({}));
          if(!res.ok) throw new Error(body.error || t('pwEvidenceUploadError'));
          showToast(t('rtToastEvidence'));
          renderPwRetest();
        }).catch(err => showToast(err.message || t('pwEvidenceUploadError')))
        .finally(() => { input.value = ''; });
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

  // --- Pentest Kanban ---
  // Tasarim karari: ayri bir 'kanban card' veri modeli YOK -- kartlar dogrudan
  // TestResult'lar (bkz. backend app.py /kanban rotalari). Surukle-birak icin
  // harici bir kutuphane (orn. SortableJS) EKLENMEDI: bu proje su ana kadar
  // hicbir CDN/harici JS bagimliligi kullanmiyor, native HTML5 Drag and Drop
  // API'si bu olcek icin yeterli.
  const KANBAN_COLUMNS = ['todo', 'testing', 'review', 'confirmed', 'done'];
  let kanbanBoardData = { todo: [], testing: [], review: [], confirmed: [], done: [] };
  let kanbanFilters = { testIdPrefix: '', severity: '', assignee: '', myTasksOnly: false };

  function renderPwKanban(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `<div class="search-empty">${t('loadingSessions')}</div>`;
    apiRequest(`/projects/${currentProjectId}/kanban/board`).then(data => {
      kanbanBoardData = data.columns;
      content.innerHTML = renderKanbanFilterBarHtml() + '<div class="kanban-board" id="kanbanBoard"></div>';
      renderKanbanBoardOnly();
      wireKanbanFilterEvents();
      wireKanbanBoardEvents();
    }).catch(err => {
      content.innerHTML = `<div class="search-empty">${escapeHtml(String(err.message || err))}</div>`;
    });
  }

  function renderKanbanFilterBarHtml(){
    return `
    <div class="filter-bar kanban-filter-bar">
      <input type="text" id="kanbanFilterTestId" placeholder="${t('kanbanFilterTestId')}" value="${escapeHtml(kanbanFilters.testIdPrefix)}">
      <select id="kanbanFilterSeverity">
        <option value="">${t('kanbanFilterAllSeverity')}</option>
        ${SEVERITIES.map(s => `<option value="${s}" ${kanbanFilters.severity===s?'selected':''}>${t('severity_'+s)}</option>`).join('')}
      </select>
      <input type="text" id="kanbanFilterAssignee" placeholder="${t('kanbanFilterAssignee')}" value="${escapeHtml(kanbanFilters.assignee)}">
      <label class="kanban-mytasks-toggle">
        <input type="checkbox" id="kanbanMyTasksToggle" ${kanbanFilters.myTasksOnly ? 'checked' : ''}>
        ${t('kanbanMyTasks')}
      </label>
      <input type="text" id="kanbanMyName" placeholder="${t('kanbanMyName')}" value="${escapeHtml(localStorage.getItem('wstg_kanban_me_v1') || '')}" style="max-width:140px">
    </div>`;
  }

  function kanbanCardMatchesFilters(card){
    if(kanbanFilters.testIdPrefix && !(card.test_id || '').toUpperCase().includes(kanbanFilters.testIdPrefix.toUpperCase())) return false;
    if(kanbanFilters.severity && (card.severity || 'info') !== kanbanFilters.severity) return false;
    if(kanbanFilters.assignee && !(card.assigned_to || '').toLowerCase().includes(kanbanFilters.assignee.toLowerCase())) return false;
    if(kanbanFilters.myTasksOnly){
      const me = (localStorage.getItem('wstg_kanban_me_v1') || '').trim().toLowerCase();
      if(!me || (card.assigned_to || '').trim().toLowerCase() !== me) return false;
    }
    return true;
  }

  function renderKanbanCard(card){
    return `<div class="kanban-card" draggable="true" data-id="${card.id}">
      <div class="kanban-card-top">
        <span class="kanban-card-testid">${escapeHtml(card.test_id)}</span>
        ${card.findings_count ? `<span class="kanban-badge kanban-badge-finding">${card.findings_count} ${t('pwStatFindings').toLowerCase()}</span>` : ''}
      </div>
      <div class="kanban-card-title">${escapeHtml(card.test_title || '')}</div>
      <div class="kanban-card-meta">
        ${card.evidence_count ? `<span>${card.evidence_count} ${t('pwTabEvidence').toLowerCase()}</span>` : ''}
        <span class="kanban-time-row"><input type="number" min="0" class="kanban-time-input" data-id="${card.id}" value="${card.time_spent_minutes || 0}"> ${t('kanbanMinutesShort')}</span>
      </div>
      <input type="text" class="kanban-assignee-input" data-id="${card.id}" placeholder="${t('kanbanAssignPlaceholder')}" value="${escapeHtml(card.assigned_to || '')}">
    </div>`;
  }

  function renderKanbanBoardOnly(){
    const board = document.getElementById('kanbanBoard');
    if(!board) return;
    board.innerHTML = KANBAN_COLUMNS.map(col => {
      const cards = (kanbanBoardData[col] || []).filter(kanbanCardMatchesFilters);
      return `<div class="kanban-column">
        <div class="kanban-column-header">
          <span>${t('kanbanCol_' + col)}</span>
          <span class="kanban-column-count">${cards.length}</span>
        </div>
        <div class="kanban-column-body" data-status="${col}">
          ${cards.map(renderKanbanCard).join('') || `<div class="kanban-empty">${t('kanbanColumnEmpty')}</div>`}
        </div>
      </div>`;
    }).join('');
  }

  function wireKanbanFilterEvents(){
    document.getElementById('kanbanFilterTestId').addEventListener('input', e=>{ kanbanFilters.testIdPrefix = e.target.value; renderKanbanBoardOnly(); });
    document.getElementById('kanbanFilterSeverity').addEventListener('change', e=>{ kanbanFilters.severity = e.target.value; renderKanbanBoardOnly(); });
    document.getElementById('kanbanFilterAssignee').addEventListener('input', e=>{ kanbanFilters.assignee = e.target.value; renderKanbanBoardOnly(); });
    document.getElementById('kanbanMyTasksToggle').addEventListener('change', e=>{ kanbanFilters.myTasksOnly = e.target.checked; renderKanbanBoardOnly(); });
    document.getElementById('kanbanMyName').addEventListener('input', e=>{
      localStorage.setItem('wstg_kanban_me_v1', e.target.value);
      if(kanbanFilters.myTasksOnly) renderKanbanBoardOnly();
    });
  }

  function moveKanbanCard(cardId, newStatus){
    cardId = Number(cardId);
    let card = null;
    for(const col of KANBAN_COLUMNS){
      const idx = (kanbanBoardData[col] || []).findIndex(c => c.id === cardId);
      if(idx !== -1){ card = kanbanBoardData[col].splice(idx, 1)[0]; break; }
    }
    if(!card) return;
    const oldStatus = card.kanban_status;
    card.kanban_status = newStatus;
    kanbanBoardData[newStatus] = kanbanBoardData[newStatus] || [];
    kanbanBoardData[newStatus].push(card);
    renderKanbanBoardOnly();

    apiRequest(`/kanban/card/${cardId}/move`, { method: 'PUT', body: JSON.stringify({ kanban_status: newStatus }) })
      .catch(err => {
        showToast(err.message || t('resultSaveError'));
        card.kanban_status = oldStatus; // basarisiz olursa iyimser guncellemeyi geri al
        renderPwKanban();
      });
  }

  function updateKanbanCard(cardId, patch){
    apiRequest(`/kanban/card/${cardId}`, { method: 'PUT', body: JSON.stringify(patch) })
      .catch(err => showToast(err.message || t('resultSaveError')));
  }

  function wireKanbanBoardEvents(){
    const board = document.getElementById('kanbanBoard');
    if(!board) return;

    board.addEventListener('dragstart', e=>{
      const card = e.target.closest('.kanban-card');
      if(!card) return;
      e.dataTransfer.setData('text/plain', card.dataset.id);
      setTimeout(()=> card.classList.add('dragging'), 0);
    });
    board.addEventListener('dragend', e=>{
      const card = e.target.closest('.kanban-card');
      if(card) card.classList.remove('dragging');
    });
    board.addEventListener('dragover', e=>{
      const colBody = e.target.closest('.kanban-column-body');
      if(!colBody) return;
      e.preventDefault();
      colBody.classList.add('drag-over');
    });
    board.addEventListener('dragleave', e=>{
      const colBody = e.target.closest('.kanban-column-body');
      if(colBody) colBody.classList.remove('drag-over');
    });
    board.addEventListener('drop', e=>{
      const colBody = e.target.closest('.kanban-column-body');
      if(!colBody) return;
      e.preventDefault();
      colBody.classList.remove('drag-over');
      const cardId = e.dataTransfer.getData('text/plain');
      if(cardId) moveKanbanCard(cardId, colBody.dataset.status);
    });
    board.addEventListener('change', e=>{
      if(e.target.classList.contains('kanban-time-input')){
        updateKanbanCard(e.target.dataset.id, { time_spent_minutes: Number(e.target.value) || 0 });
      }
      if(e.target.classList.contains('kanban-assignee-input')){
        updateKanbanCard(e.target.dataset.id, { assigned_to: e.target.value.trim() });
      }
    });
  }

  function renderHtmlReportBuilderHtml(){
    const defaultTitle = currentProjectObj ? `${currentProjectObj.name} Security Assessment` : '';
    return `
      <div class="pro-reports-section">
        <h5>${t('reportBuilderTitle')}</h5>
        <p class="import-preview-source" style="margin-bottom:14px">${t('reportBuilderDesc')}</p>
        <div class="report-builder-form">
          <div class="finding-form-row">
            <div><label>${t('reportTitleLabel')}</label><input type="text" id="reportTitleInput" placeholder="${escapeHtml(defaultTitle)}"></div>
            <div><label>${t('reportClientLabel')}</label><input type="text" id="reportClientInput" value="${escapeHtml((currentProjectObj && currentProjectObj.client) || '')}"></div>
          </div>
          <div class="finding-form-row">
            <div><label>${t('reportPentesterLabel')}</label><input type="text" id="reportPentesterInput"></div>
            <div><label>${t('reportDateRangeLabel')}</label><input type="text" id="reportDateRangeInput" placeholder="2026-08-01 – 2026-08-20"></div>
          </div>
          <div class="finding-form-row">
            <div>
              <label>${t('reportIncludeLabel')}</label>
              <select id="reportIncludeSelect">
                <option value="all">${t('reportIncludeAll')}</option>
                <option value="critical_high">${t('reportIncludeCriticalHigh')}</option>
                <option value="selected">${t('reportIncludeSelected')}</option>
              </select>
            </div>
            <div>
              <label>${t('reportTemplateLabel')}</label>
              <select id="reportTemplateSelect">
                <option value="standard">${t('reportTemplateStandard')}</option>
                <option value="executive">${t('reportTemplateExecutive')}</option>
                <option value="detailed">${t('reportTemplateDetailed')}</option>
              </select>
            </div>
          </div>
          <div id="reportFindingPickerWrap" style="display:none">
            <label>${t('reportFindingPickerLabel')}</label>
            <div id="reportFindingPicker" class="report-finding-picker">
              <div class="search-empty">${t('loadingSessions')}</div>
            </div>
          </div>
          <label class="recon-auth-check">
            <input type="checkbox" id="reportConfidentialCheck">
            <span>${t('reportConfidentialLabel')}</span>
          </label>
          <label data-i18n="reportExecSummaryLabel">${t('reportExecSummaryLabel')}</label>
          <textarea id="reportExecSummaryInput" rows="3" placeholder="${t('reportExecSummaryPlaceholder')}"></textarea>
          <div class="hero-actions" style="margin-top:8px">
            <button type="button" class="btn btn-sm ai-feature" id="reportGenSummaryBtn">${t('reportGenSummaryBtn')}</button>
            <button type="button" class="btn btn-primary btn-sm" id="openHtmlReportBtn">${t('reportOpenHtmlBtn')}</button>
            <button type="button" class="btn btn-primary btn-sm" id="downloadPdfReportBtn">${t('reportDownloadPdfBtn')}</button>
          </div>
          <div class="import-status" id="reportBuilderStatus"></div>
        </div>
      </div>`;
  }

  function loadReportFindingPicker(){
    const wrap = document.getElementById('reportFindingPickerWrap');
    const box = document.getElementById('reportFindingPicker');
    apiRequest(`/projects/${currentProjectId}/findings`).then(list => {
      if(!list.length){
        box.innerHTML = `<div class="search-empty">${t('reportFindingPickerEmpty')}</div>`;
        return;
      }
      box.innerHTML = list.map(f => `
        <label class="report-finding-picker-item">
          <input type="checkbox" class="report-finding-check" value="${f.id}" checked>
          <span class="recon-priority-badge prio-${(f.severity||'info') === 'critical' ? 'high' : (f.severity||'info')}">${escapeHtml((f.severity||'info').toUpperCase())}</span>
          <span>${escapeHtml(f.title || '')}</span>
        </label>`).join('');
    }).catch(()=>{
      box.innerHTML = `<div class="search-empty">${t('resultSaveError')}</div>`;
    });
  }

  function currentReportOptions(){
    const includeSel = document.getElementById('reportIncludeSelect').value;
    let include = includeSel;
    if(includeSel === 'selected'){
      include = Array.from(document.querySelectorAll('.report-finding-check:checked')).map(cb => Number(cb.value));
    }
    return {
      title: document.getElementById('reportTitleInput').value.trim() || undefined,
      client_name: document.getElementById('reportClientInput').value.trim(),
      pentester_name: document.getElementById('reportPentesterInput').value.trim(),
      date_range: document.getElementById('reportDateRangeInput').value.trim(),
      include,
      template: document.getElementById('reportTemplateSelect').value,
      confidential: document.getElementById('reportConfidentialCheck').checked,
      executive_summary: document.getElementById('reportExecSummaryInput').value.trim() || undefined,
      lang: currentLang,
    };
  }

  function wireHtmlReportBuilder(){
    document.getElementById('reportIncludeSelect').addEventListener('change', e=>{
      const wrap = document.getElementById('reportFindingPickerWrap');
      if(e.target.value === 'selected'){
        wrap.style.display = '';
        loadReportFindingPicker();
      } else {
        wrap.style.display = 'none';
      }
    });

    document.getElementById('reportGenSummaryBtn').addEventListener('click', ()=>{
      const statusEl = document.getElementById('reportBuilderStatus');
      statusEl.textContent = t('aiWorking');
      apiRequest(`/projects/${currentProjectId}/ai/executive-summary`, { method: 'POST', body: JSON.stringify({ lang: currentLang }) })
        .then(res => {
          statusEl.textContent = '';
          document.getElementById('reportExecSummaryInput').value = res.summary;
        }).catch(err => {
          statusEl.textContent = (err.body && err.body.ai_configured === false) ? t('aiNotConfigured') : '';
          showToast(err.message || t('resultSaveError'));
        });
    });

    document.getElementById('openHtmlReportBtn').addEventListener('click', ()=>{
      const payload = currentReportOptions();
      // Yeni sekme kullanici tiklamasiyla AYNI ANDA acilir (popup engelleyiciyi
      // atlamak icin) -- icerik fetch tamamlaninca dolduruluyor.
      const reportWindow = window.open('', '_blank');
      apiFetch(`/projects/${currentProjectId}/reports/html`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(res => {
        if(!res.ok) throw new Error('report generation failed');
        return res.text();
      }).then(html => {
        if(reportWindow){
          reportWindow.document.open();
          reportWindow.document.write(html);
          reportWindow.document.close();
        }
      }).catch(()=>{
        if(reportWindow) reportWindow.close();
        showToast(t('resultSaveError'));
      });
    });

    document.getElementById('downloadPdfReportBtn').addEventListener('click', ()=>{
      const btn = document.getElementById('downloadPdfReportBtn');
      const statusEl = document.getElementById('reportBuilderStatus');
      const payload = currentReportOptions();
      btn.disabled = true;
      statusEl.textContent = t('reportPdfGenerating');
      apiFetch(`/projects/${currentProjectId}/reports/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(async res => {
        if(!res.ok){
          const body = await res.json().catch(()=>({}));
          throw new Error(body.error || 'PDF generation failed');
        }
        return res.blob();
      }).then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${(currentProjectObj && currentProjectObj.name) || 'report'}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(()=> URL.revokeObjectURL(url), 4000);
        statusEl.textContent = '';
      }).catch(err => {
        statusEl.textContent = '';
        showToast(err.message || t('resultSaveError'));
      }).finally(()=>{ btn.disabled = false; });
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
              <div class="pro-report-icon"><svg class="i"><use href="#ic-file"/></svg></div>
              <div class="pro-report-name">${t('pwReportTypeTechnical')}</div>
              <div class="pro-report-desc">${t('pwReportTypeTechnicalDesc')}</div>
            </a>
            <a class="pro-report-card" href="${API_BASE}/projects/${currentProjectId}/reports/executive" target="_blank">
              <div class="pro-report-icon"><svg class="i"><use href="#ic-grid"/></svg></div>
              <div class="pro-report-name">${t('pwReportTypeExecutive')}</div>
              <div class="pro-report-desc">${t('pwReportTypeExecutiveDesc')}</div>
            </a>
            <a class="pro-report-card" href="${API_BASE}/projects/${currentProjectId}/reports/developer" target="_blank">
              <div class="pro-report-icon"><svg class="i"><use href="#ic-list"/></svg></div>
              <div class="pro-report-name">${t('pwReportTypeDeveloper')}</div>
              <div class="pro-report-desc">${t('pwReportTypeDeveloperDesc')}</div>
            </a>
          </div>
        </div>` + renderHtmlReportBuilderHtml();

      if(!sessions.length){
        content.innerHTML = proReportsHtml + `<div class="search-empty">${t('pwReportsNoSession')}</div>`;
        wireHtmlReportBuilder();
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
                <span>${escapeHtml(s.tester_name || '—')}</span>
                <span>${new Date(s.created_at).toLocaleString(t('dateLocale'))}</span>
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
      wireHtmlReportBuilder();
    });
  }

  function renderPwEvidence(){
    const content = document.getElementById('pwContent');
    content.innerHTML = `
      <div class="evidence-upload-row">
        <label class="evidence-upload-btn" for="evidenceFileInput">${t('pwEvidenceUploadLabel')}</label>
        <input type="file" id="evidenceFileInput" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none">
        <button type="button" class="evidence-upload-btn" id="toggleHttpEvidenceBtn">${t('pwEvidenceAddHttpLabel')}</button>
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
      apiFetch(`/projects/${currentProjectId}/evidence`, { method: 'POST', body: formData })
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
            ${ev.linked_test_id ? `<div class="evidence-linked">${t('pwEvidenceLinkedTo')}: ${escapeHtml(ev.linked_test_id)}</div>` : ''}
            <label class="evidence-finding-link-label">${t('pwEvidenceLinkFindingLabel')}</label>
            <select class="evidence-finding-select" data-id="${ev.id}">
              <option value="">${t('pwEvidenceLinkFindingNone')}</option>
              ${findingOptions}
            </select>
            <div class="evidence-actions">
              <button class="evidence-delete-btn" data-id="${ev.id}">${t('pwEvidenceDelete')}</button>
            </div>`;

        if(ev.evidence_type === 'http_transaction'){
          return `
          <div class="evidence-card http-evidence-card" data-id="${ev.id}">
            <div class="evidence-body">
              <div class="evidence-top">
                <span class="evidence-filename">${escapeHtml(ev.filename)}</span>
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
                ${ev.ai_suggested_test_ids.map(tid => `<button class="evidence-suggest-chip" data-evidence="${Number(ev.id)}" data-test="${escapeHtml(tid)}">${escapeHtml(tid)} ✓</button>`).join('')}
              </div>` : ''}`;
        } else if(ev.ai_error){
          aiBlock = `<div class="evidence-ai-off">${t('pwEvidenceAiError')}: ${escapeHtml(ev.ai_error)}</div>`;
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

    document.getElementById('themeTrigger').addEventListener('click', cycleTheme);

    // Mobil kenar çubuğu
    document.getElementById('menuToggle').addEventListener('click', ()=>{
      const open = !document.getElementById('sidebar').classList.contains('open');
      document.getElementById('sidebar').classList.toggle('open', open);
      document.getElementById('sidebarScrim').classList.toggle('open', open);
    });
    document.getElementById('sidebarScrim').addEventListener('click', closeSidebar);
    document.querySelectorAll('.sidebar .nav-link[id]').forEach(btn=>{
      if(btn.id !== 'categoryToggle') btn.addEventListener('click', closeSidebar);
    });
    document.getElementById('categoryToggle').addEventListener('click', ()=>{
      const list = document.getElementById('categoryNav');
      const hidden = list.classList.toggle('hidden');
      document.getElementById('categoryToggle').classList.toggle('collapsed', hidden);
    });
    document.getElementById('brandLink').addEventListener('click', e=>{
      e.preventDefault(); window.scrollTo({top:0, behavior:'smooth'});
    });
    document.getElementById('sessionChip').addEventListener('click', ()=> openSessionGate(true));
    document.getElementById('mobileSearchBtn').addEventListener('click', e=>{
      e.stopPropagation();
      document.querySelector('.topbar').classList.add('search-open');
      setTimeout(()=> document.getElementById('globalSearch').focus(), 20);
    });
    document.getElementById('globalSearch').addEventListener('blur', ()=>{
      setTimeout(()=> document.querySelector('.topbar').classList.remove('search-open'), 150);
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
      if(btn.dataset.action === 'complete') setSessionStatusUI(id, 'completed');
      if(btn.dataset.action === 'reopen') setSessionStatusUI(id, 'active');
    });

    document.getElementById('reconNavBtn').addEventListener('click', openReconModal);
    document.getElementById('attackSurfaceNavBtn').addEventListener('click', ()=>{
      if(currentProjectId) openProjectWorkspace(currentProjectId, 'assets');
      else { openProjectsModal(); showToast(t('asNeedProject')); }
    });
    document.getElementById('closeReconOverlay').addEventListener('click', closeReconModal);
    document.getElementById('reconOverlay').addEventListener('click', e=>{
      if(e.target.id === 'reconOverlay') closeReconModal();
    });
    document.getElementById('reconRunBtn').addEventListener('click', runRecon);
    document.getElementById('reconApplyBtn').addEventListener('click', applyReconPriorities);
    document.getElementById('reconResetBtn').addEventListener('click', resetReconState);

    bindNotebookAndStudyEvents();

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

    document.getElementById('aiNextTestNavBtn').addEventListener('click', openAiNextTestModal);
    document.getElementById('closeAiNextTestOverlay').addEventListener('click', closeAiNextTestModal);
    document.getElementById('aiNextTestOverlay').addEventListener('click', e=>{
      if(e.target.id === 'aiNextTestOverlay') closeAiNextTestModal();
    });
    document.getElementById('aiNextTestAskBtn').addEventListener('click', askAiNextTest);

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
    initAiAssistantButtons();
    wireAiSettingsModal();
    wireByokModal();
    updateByokDot();

    document.getElementById('closeDuplicateAlert').addEventListener('click', closeDuplicateAlert);
    document.getElementById('duplicateAlertOverlay').addEventListener('click', e=>{
      if(e.target.id === 'duplicateAlertOverlay') closeDuplicateAlert();
    });
    document.getElementById('dupCreateAnywayBtn').addEventListener('click', ()=>{
      if(pendingFindingPayload) actuallySaveFinding(pendingFindingPayload);
    });
    document.getElementById('dupMergeBtn').addEventListener('click', ()=>{
      const checked = Array.from(document.querySelectorAll('.dup-candidate-check:checked'))
        .map(cb => dupCandidates[Number(cb.dataset.idx)].finding.id);
      if(checked.length < 2){ showToast(t('dupSelectAtLeastTwo')); return; }
      const [primary_id, ...merge_ids] = checked;
      apiRequest(`/projects/${currentProjectId}/findings/merge`, { method: 'POST', body: JSON.stringify({ primary_id, merge_ids }) })
        .then(()=>{
          showToast(t('dupMergeSuccess'));
          closeDuplicateAlert();
          renderPwFindings();
        }).catch(err => showToast(err.message || t('resultSaveError')));
    });
    document.getElementById('dupAlertList').addEventListener('click', e=>{
      const btn = e.target.closest('.dup-view-btn');
      if(!btn) return;
      const m = dupCandidates[Number(btn.dataset.idx)];
      closeDuplicateAlert();
      openFindingModal(m.finding, null);
    });

    document.getElementById('pwTabs').addEventListener('click', e=>{
      const btn = e.target.closest('.pw-tab');
      if(!btn) return;
      switchPwTab(btn.dataset.tab);
    });
    document.getElementById('projectChip').addEventListener('click', ()=>{
      if(currentProjectId) openProjectWorkspace(currentProjectId);
      else openProjectsModal();
    });

    document.getElementById('importNavBtn').addEventListener('click', openImportModal);
    document.getElementById('closeImportOverlay').addEventListener('click', closeImportModal);
    document.getElementById('importOverlay').addEventListener('click', e=>{
      if(e.target.id === 'importOverlay') closeImportModal();
    });
    document.getElementById('importAnalyzeBtn').addEventListener('click', analyzeImportFile);
    document.getElementById('importApplyBtn').addEventListener('click', applyImportSelected);
    document.getElementById('importCreateFindings').addEventListener('change', syncImportHttpOption);
    document.getElementById('importPreviewList').addEventListener('change', e=>{
      const cb = e.target.closest('.import-check');
      if(!cb) return;
      const row = lastImportFindings.find(f => f._rowId === cb.dataset.row);
      if(row) row._checked = cb.checked;
    });

    document.addEventListener('keydown', e=>{
      if(e.key === 'Escape'){
        closeCategory(); closeSidebar(); closeNewSessionOverlay(); closeTop10Detail(); closeImportModal(); closeReconModal(); closePlannerModal(); closeAiNextTestModal();
        closeProjectsModal(); closeNewProjectModal(); closeProjectWorkspace(); closeFindingModal(); closeDuplicateAlert(); closeAiSettingsModal(); closeByokModal();
        closeNoteLightbox(); closeNoteEditor(); closeNotebook(); closeStudyMetrics();
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
    const sortPriorityBtn = document.getElementById('sortPriorityToggle');
    if(sortPriorityBtn){
      sortPriorityBtn.addEventListener('click', ()=>{
        sortByReconPriority = !sortByReconPriority;
        sortPriorityBtn.classList.toggle('active', sortByReconPriority);
        renderTestList();
      });
    }

    document.getElementById('testList').addEventListener('click', e=>{
      const checkBtn = e.target.closest('.test-check');
      if(checkBtn){ e.stopPropagation(); toggleDone(checkBtn.dataset.id); return; }
      const row = e.target.closest('.test-row-item');
      if(row) selectTest(row.dataset.id, { showDetail: true });
    });
    const detailEl = document.getElementById('testDetail');
    detailEl.addEventListener('click', e=>{
      const copyBtn = e.target.closest('.copy-btn');
      if(copyBtn){ copyToClipboard(decodeURIComponent(copyBtn.dataset.copy)); return; }
      if(e.target.closest('[data-action="back"]')) document.getElementById('checklistBody').classList.remove('show-detail');
      const noteBtn = e.target.closest('[data-action="add-note"]');
      if(noteBtn) openNoteEditor(null, noteBtn.dataset.id);
    });
    detailEl.addEventListener('input', e=>{
      const ta = e.target.closest('.finding-textarea');
      if(ta){ scheduleFindingSave(ta.dataset.id); }
    });
    detailEl.addEventListener('change', e=>{
      const sel = e.target.closest('.severity-select');
      if(sel){ saveFinding(sel.dataset.id); }
    });
    document.getElementById('testDetailFoot').addEventListener('click', e=>{
      const btn = e.target.closest('[data-action]');
      if(!btn || btn.disabled) return;
      if(btn.dataset.action === 'toggle-done') toggleDone(btn.dataset.id);
      if(btn.dataset.action === 'prev') stepSelection(-1);
      if(btn.dataset.action === 'next') stepSelection(1);
    });
    // Liste klavyeyle gezilebilir: ↑/↓ test değiştirir (yazı alanındayken devre dışı).
    document.addEventListener('keydown', e=>{
      if(!document.getElementById('categoryOverlay').classList.contains('open')) return;
      if(document.querySelector('.overlay.open:not(#categoryOverlay)')) return;
      if(e.target.matches && e.target.matches('input, textarea, select, [contenteditable]')) return;
      if(e.key === 'ArrowDown'){ e.preventDefault(); stepSelection(1); }
      if(e.key === 'ArrowUp'){ e.preventDefault(); stepSelection(-1); }
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

    document.getElementById('exportBtn').addEventListener('click', ()=>{
      exportReport();
      // AI destekli, PDF/HTML profesyonel rapor (bulgu seçimi, yönetici
      // özeti vb.) Proje bağlamına özeldir -- bunu bilmeyen kullanıcılar
      // sadece bu düz metin dökümünü görüp diğerini hiç bulamıyordu.
      // "Rapor indirildi" toast'ı bitince ikinci bir ipucu toast'ı gösterilir
      // (aynı anda çağrılırsa ilk toast görünmeden üzerine yazılırdı).
      if(!currentProjectId) setTimeout(()=> showToast(t('exportProHint')), 2400);
    });
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

    bindAuthEvents();
    checkDb().then(status => {
      if(!status) return; // no backend -> behave exactly like the original local-only app
      if(status.authenticated){ startOnline(); return; }
      showAuthScreen(status.configured ? 'login' : (status.setup_allowed ? 'setup' : 'setup-remote'));
    });
  });

  // Giriş yapıldıktan sonra (ya da çerez hâlâ geçerliyse) backend'li modu başlatır.
  function startOnline(){
    authBooted = true;
    dbOnline = true;
    setAuthNavVisible(true);
    updateSessionUI();

    renderAiStatusBadge();

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
  }

  // ========================
  // KİMLİK DOĞRULAMA EKRANLARI
  // ========================
  // authMode: null | 'setup' | 'login' | 'setup-remote'. Ekran opaktır; arkadaki
  // veriler görünmez. Çıkışta sayfa yeniden yüklenir (bellekte veri kalmaz).

  function authErrorText(err){
    const body = err && err.body;
    const key = body && window.WSTGAuth.errorKey(body.code);
    if(key) return t(key).replace('{s}', body.retry_after || '');
    if(!body) return t('authErrNetwork');
    return err.message || t('authErrNetwork');
  }

  function setI18nText(el, key){
    el.setAttribute('data-i18n', key);
    el.textContent = t(key);
  }

  function setAuthNavVisible(visible){
    const nav = document.getElementById('authNav');
    if(nav) nav.hidden = !visible;
  }

  function showAuthScreen(mode, noticeKey){
    authMode = mode;
    const screen = document.getElementById('authScreen');
    const form = document.getElementById('authForm');
    const pw = document.getElementById('authPassword');
    const confirm = document.getElementById('authPasswordConfirm');
    const isSetup = mode === 'setup';
    const titleKey = { setup: 'authSetupTitle', login: 'authLoginTitle', 'setup-remote': 'authSetupRemoteTitle' }[mode];
    const descKey = { setup: 'authSetupDesc', login: 'authLoginDesc', 'setup-remote': 'authSetupRemoteDesc' }[mode];
    setI18nText(document.getElementById('authTitle'), titleKey);
    setI18nText(document.getElementById('authDesc'), descKey);
    setI18nText(document.getElementById('authPasswordLabel'), isSetup ? 'authNewPasswordLabel' : 'authPasswordLabel');
    setI18nText(document.getElementById('authSubmit'), isSetup ? 'authSetupBtn' : 'authLoginBtn');
    pw.setAttribute('autocomplete', isSetup ? 'new-password' : 'current-password');
    document.getElementById('authConfirmRow').hidden = !isSetup;
    document.getElementById('authHint').hidden = !isSetup;
    form.hidden = mode === 'setup-remote';
    document.getElementById('authRemote').hidden = mode !== 'setup-remote';
    // Yerel moda geçiş yalnızca ilk açılışta; oturum ortasında düşerse giriş zorunlu.
    document.getElementById('authLocalBtn').hidden = authBooted;
    const noticeEl = document.getElementById('authNotice');
    if(noticeKey) setI18nText(noticeEl, noticeKey);
    else { noticeEl.removeAttribute('data-i18n'); noticeEl.textContent = ''; }
    noticeEl.hidden = !noticeKey;
    document.getElementById('authError').textContent = '';
    pw.value = '';
    confirm.value = '';
    document.getElementById('authLangSelect').value = currentLang;
    screen.classList.add('open');
    document.body.classList.add('auth-locked');
    if(!form.hidden) setTimeout(()=> pw.focus(), 0);
  }

  function hideAuthScreen(){
    authMode = null;
    document.getElementById('authScreen').classList.remove('open');
    document.body.classList.remove('auth-locked');
    document.getElementById('authPassword').value = '';
    document.getElementById('authPasswordConfirm').value = '';
  }

  function handleSessionLost(){
    if(!authBooted || authMode) return; // açılışta zaten giriş ekranı yönetiliyor
    dbOnline = false;
    setAuthNavVisible(false);
    showAuthScreen('login', 'authSessionExpiredNotice');
  }

  function submitAuthForm(e){
    e.preventDefault();
    const pw = document.getElementById('authPassword').value;
    const errEl = document.getElementById('authError');
    const btn = document.getElementById('authSubmit');
    errEl.textContent = '';
    if(authMode === 'setup' && pw !== document.getElementById('authPasswordConfirm').value){
      errEl.textContent = t('authErrPasswordMismatch');
      return;
    }
    const path = authMode === 'setup' ? '/auth/setup' : '/auth/login';
    btn.disabled = true;
    apiRequest(path, { method: 'POST', body: JSON.stringify({ password: pw }) }).then(()=>{
      const wasBooted = authBooted;
      hideAuthScreen();
      if(wasBooted){
        dbOnline = true;
        setAuthNavVisible(true);
        updateSessionUI();
        showToast(t('authReloggedToast'));
      } else {
        startOnline();
      }
    }).catch(err => {
      const code = err.body && err.body.code;
      // Başka bir sekmede kurulum yapıldıysa giriş ekranına geç.
      if(code === 'already_configured'){ showAuthScreen('login', 'authErrAlreadyConfigured'); return; }
      errEl.textContent = authErrorText(err);
      document.getElementById('authPassword').select();
    }).finally(()=>{ btn.disabled = false; });
  }

  function recheckAuthStatus(){
    checkDb().then(status => {
      if(!status){ document.getElementById('authError').textContent = t('authErrNetwork'); return; }
      if(status.authenticated){ hideAuthScreen(); startOnline(); return; }
      showAuthScreen(status.configured ? 'login' : (status.setup_allowed ? 'setup' : 'setup-remote'));
    });
  }

  function openChangePassword(){
    ['cpCurrent', 'cpNew', 'cpConfirm'].forEach(id => { document.getElementById(id).value = ''; });
    document.getElementById('cpError').textContent = '';
    document.getElementById('changePasswordOverlay').classList.add('open');
    closeSidebar();
    setTimeout(()=> document.getElementById('cpCurrent').focus(), 0);
  }

  function closeChangePassword(){
    const overlay = document.getElementById('changePasswordOverlay');
    if(!overlay.classList.contains('open')) return;
    overlay.classList.remove('open');
    ['cpCurrent', 'cpNew', 'cpConfirm'].forEach(id => { document.getElementById(id).value = ''; });
  }

  function submitChangePassword(e){
    e.preventDefault();
    const current = document.getElementById('cpCurrent').value;
    const next = document.getElementById('cpNew').value;
    const errEl = document.getElementById('cpError');
    const btn = document.getElementById('cpSubmit');
    errEl.textContent = '';
    if(next !== document.getElementById('cpConfirm').value){
      errEl.textContent = t('authErrPasswordMismatch');
      return;
    }
    btn.disabled = true;
    apiRequest('/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password: current, new_password: next }) })
      .then(()=>{
        closeChangePassword();
        showToast(t('authChangedToast'));
      })
      .catch(err => {
        if(window.WSTGAuth.isSessionLost(err.status, err.body)){ closeChangePassword(); return; }
        errEl.textContent = authErrorText(err);
      })
      .finally(()=>{ btn.disabled = false; });
  }

  function logout(){
    apiRequest('/auth/logout', { method: 'POST' }).catch(()=>{}).then(()=>{
      window.location.reload();
    });
  }

  function bindAuthEvents(){
    document.getElementById('authForm').addEventListener('submit', submitAuthForm);
    document.getElementById('authRetryBtn').addEventListener('click', recheckAuthStatus);
    document.getElementById('authLocalBtn').addEventListener('click', ()=>{
      hideAuthScreen();
      dbOnline = false;
      updateSessionUI();
    });
    document.getElementById('authLangSelect').addEventListener('change', e => switchLanguage(e.target.value));
    document.getElementById('changePasswordBtn').addEventListener('click', openChangePassword);
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('changePasswordForm').addEventListener('submit', submitChangePassword);
    document.getElementById('closeChangePassword').addEventListener('click', closeChangePassword);
    document.getElementById('changePasswordOverlay').addEventListener('click', e => {
      if(e.target.id === 'changePasswordOverlay') closeChangePassword();
    });
    document.addEventListener('keydown', e => { if(e.key === 'Escape') closeChangePassword(); });
  }
})();
