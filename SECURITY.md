# Security Policy

[Türkçe](#türkçe)

Pentest Workspace stores sensitive data: findings, evidence, target details and AI provider keys. Security reports are taken seriously and are welcome.

## Supported Versions

Security fixes are made on the `main` branch and included in the next release. Please check that the issue still exists on the latest `main` before reporting it.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or use [this link](https://github.com/enesbaldemir/WSTG-Copilot/security/advisories/new).

Please include:

- The affected version or commit.
- Steps to reproduce, and a proof of concept if you have one.
- The impact you expect, for example who can exploit it and what they gain.

What to expect:

- An acknowledgement within 7 days.
- An assessment and, if the report is confirmed, a plan for the fix.
- Credit in the advisory and the release notes, unless you prefer to stay anonymous.

Please give a reasonable time to fix the issue before disclosing it publicly. Test only against your own installation; do not test against instances you don't own.

## Scope

The application is designed to run on the user's own computer, with the API and the frontend bound to `127.0.0.1` by default. Examples of issues that are in scope:

- Bypassing the sign-in, the session checks or the login throttling.
- Cross-site requests that reach the API, or bypasses of the Origin and Host checks.
- Cross-site scripting in the interface or in generated HTML, DOCX or PDF reports.
- Path traversal or arbitrary file access through evidence uploads, backups or reports.
- Command injection through the Tool Runner or Recon.
- Disclosure of stored AI provider keys, or redaction that fails to remove secrets before data is sent to an AI provider.

Usually out of scope:

- Attacks that need prior access to the computer running the application, its files or the user's account on it.
- Problems caused only by exposing the API to a network against the documented defaults, unless the documentation suggests that setup.
- Vulnerabilities in third-party tools started by the Tool Runner, or in AI provider services.
- Missing hardening headers or best practices without a demonstrated impact.

---

## Türkçe

Pentest Workspace hassas veriler saklar: bulgular, kanıtlar, hedef bilgileri ve AI sağlayıcı anahtarları. Güvenlik bildirimleri ciddiye alınır ve memnuniyetle karşılanır.

### Desteklenen Sürümler

Güvenlik düzeltmeleri `main` dalında yapılır ve bir sonraki sürüme eklenir. Bildirmeden önce sorunun en güncel `main` dalında hâlâ var olduğunu kontrol edin.

### Güvenlik Açığı Bildirme

**Güvenlik açıkları için lütfen herkese açık issue açmayın.**

Açığı GitHub üzerinden gizli olarak bildirin: deponun **Security** sekmesini açıp **Report a vulnerability** seçeneğini kullanın ya da [bu bağlantıyı](https://github.com/enesbaldemir/WSTG-Copilot/security/advisories/new) açın.

Lütfen şunları ekleyin:

- Etkilenen sürüm ya da commit.
- Yeniden üretme adımları ve varsa bir kavram kanıtı (PoC).
- Beklediğiniz etki; örneğin açığı kimin kullanabileceği ve ne elde edeceği.

Neler beklenebilir:

- 7 gün içinde bildirimin alındığına dair yanıt.
- Bir değerlendirme ve bildirim doğrulanırsa düzeltme planı.
- İsimsiz kalmayı tercih etmediğiniz sürece güvenlik bülteninde ve sürüm notlarında teşekkür.

Açığı herkese açık paylaşmadan önce düzeltme için makul bir süre tanıyın. Yalnızca kendi kurulumunuz üzerinde test yapın; size ait olmayan kurulumları test etmeyin.

### Kapsam

Uygulama kullanıcının kendi bilgisayarında çalışacak şekilde tasarlanmıştır; API ve arayüz varsayılan olarak `127.0.0.1` adresine bağlanır. Kapsamdaki sorunlara örnekler:

- Giriş ekranını, oturum kontrollerini ya da giriş denemesi sınırlamasını atlatmak.
- API'ye ulaşan siteler arası istekler ya da Origin ve Host kontrollerinin atlatılması.
- Arayüzde ya da üretilen HTML, DOCX veya PDF raporlarında siteler arası betik çalıştırma (XSS).
- Kanıt yükleme, yedekleme ya da raporlar üzerinden path traversal veya istenmeyen dosya erişimi.
- Tool Runner ya da Recon üzerinden komut enjeksiyonu.
- Saklanan AI sağlayıcı anahtarlarının açığa çıkması ya da veriler AI sağlayıcıya gönderilmeden önce gizli bilgilerin maskelenmemesi.

Genellikle kapsam dışı:

- Uygulamanın çalıştığı bilgisayara, dosyalarına ya da kullanıcının oradaki hesabına önceden erişim gerektiren saldırılar.
- Yalnızca API'nin belgelenen varsayılanların aksine ağa açılmasından kaynaklanan sorunlar (belgeler bu kurulumu önermiyorsa).
- Tool Runner'ın başlattığı üçüncü taraf araçlardaki ya da AI sağlayıcı servislerindeki açıklar.
- Somut bir etkisi gösterilmemiş eksik güvenlik başlıkları ya da en iyi uygulama önerileri.
