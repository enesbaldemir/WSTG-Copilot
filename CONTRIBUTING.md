# Contributing

[Türkçe](#türkçe)

Thanks for your interest in Pentest Workspace. Bug reports, ideas, documentation fixes and code are all welcome.

## Before You Start

- For a bug or an idea, open an issue first using one of the templates. For a larger change, describe it in an issue before writing code so we can agree on the approach.
- To report a security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- This tool is for **authorized** security testing. Contributions that make it easier to attack systems without permission will not be accepted.

## Development Setup

Follow [Installation](README.md#installation) and [Running](README.md#running) in the README, or use [Docker](README.md#running-with-docker).

Keep the frontend free of build steps and frameworks: it is plain HTML, CSS and JavaScript and must keep working from a static file server.

## Running the Tests

The same commands run in CI on every pull request:

```bash
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
cd backend && python -m pytest -q        # backend
cd .. && node --test js/tests/*.test.js  # frontend
```

Always run backend tests through `pytest`: `backend/conftest.py` points them at a temporary database and secret key. Running a test file directly (`python test_x.py`) skips that and writes to your real `backend/database/wstg.db`.

Add or update tests for the behavior you change.

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Keep each pull request focused on one change.
3. Sign off your commits with `git commit -s`, which adds a `Signed-off-by` line confirming you have the right to submit the change under the project's licenses.
4. Update the README (both [English](README.md) and [Türkçe](README.tr.md)) if you change behavior, setup or screenshots.
5. Open the pull request and describe what changed and why. The template lists the checks to go through.

## Checklist Data and Licenses

- Code is released under the [MIT License](LICENSE).
- The checklists in [`data/`](data/) are adapted from OWASP material and are released under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Changes to `data/` are released under the same license; keep [`data/LICENSE.md`](data/LICENSE.md) up to date with the sources and changes.
- Keep the English and Turkish data files (`*.en.json` and `*.tr.json`) in sync.

---

## Türkçe

Pentest Workspace'e gösterdiğiniz ilgi için teşekkürler. Hata bildirimleri, fikirler, dokümantasyon düzeltmeleri ve kod katkıları memnuniyetle karşılanır.

### Başlamadan Önce

- Bir hata ya da fikir için önce şablonlardan birini kullanarak issue açın. Daha büyük bir değişiklik için, yaklaşım üzerinde anlaşabilmek adına kod yazmadan önce bir issue'da anlatın.
- Bir güvenlik açığı bildirmek için herkese açık issue açmak yerine [SECURITY.md](SECURITY.md) dosyasındaki adımları izleyin.
- Bu araç **yetkilendirilmiş** güvenlik testleri içindir. İzinsiz sistemlere saldırmayı kolaylaştıran katkılar kabul edilmez.

### Geliştirme Ortamı

README'deki [Kurulum](README.tr.md#kurulum) ve [Çalıştırma](README.tr.md#çalıştırma) adımlarını izleyin ya da [Docker](README.tr.md#docker-ile-çalıştırma) kullanın.

Frontend'i framework ve build adımı gerektirmeyecek şekilde tutun: düz HTML, CSS ve JavaScript'tir ve statik bir dosya sunucusundan çalışmaya devam etmelidir.

### Testleri Çalıştırma

CI her pull request'te aynı komutları çalıştırır:

```bash
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
cd backend && python -m pytest -q        # backend
cd .. && node --test js/tests/*.test.js  # frontend
```

Backend testlerini her zaman `pytest` ile çalıştırın: `backend/conftest.py` onları geçici bir veritabanına ve gizli anahtara yönlendirir. Bir test dosyasını doğrudan çalıştırmak (`python test_x.py`) bunu atlar ve gerçek `backend/database/wstg.db` dosyanıza yazar.

Değiştirdiğiniz davranış için test ekleyin ya da mevcut testleri güncelleyin.

### Pull Request'ler

1. Depoyu fork'layın ve `main` dalından yeni bir dal açın.
2. Her pull request'i tek bir değişikliğe odaklı tutun.
3. Commit'lerinizi `git commit -s` ile imzalayın; bu, değişikliği projenin lisansları altında gönderme hakkınız olduğunu belirten bir `Signed-off-by` satırı ekler.
4. Davranışı, kurulumu ya da ekran görüntülerini değiştiriyorsanız README'yi ([English](README.md) ve [Türkçe](README.tr.md)) güncelleyin.
5. Pull request'i açın ve neyin neden değiştiğini anlatın. Şablon, gözden geçirilecek kontrolleri listeler.

### Checklist Verileri ve Lisanslar

- Kod [MIT Lisansı](LICENSE) ile yayınlanır.
- [`data/`](data/) klasöründeki checklist'ler OWASP içeriklerinden uyarlanmıştır ve [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.tr) ile yayınlanır. `data/` klasöründeki değişiklikler aynı lisansla yayınlanır; kaynakları ve değişiklikleri [`data/LICENSE.md`](data/LICENSE.md) dosyasında güncel tutun.
- İngilizce ve Türkçe veri dosyalarını (`*.en.json` ve `*.tr.json`) birbiriyle uyumlu tutun.
