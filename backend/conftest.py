"""
Backend testleri için geçici veritabanı.

pytest bu dosyayı test modüllerinden ÖNCE yükler. Burada DATABASE_URL'yi
geçici bir SQLite dosyasına yönlendiriyoruz; config.py bu değişkeni okuduğu
için `import app` artık backend/database/wstg.db'ye hiç bağlanmaz (ensure_schema
de geçici dosyada çalışır). load_dotenv() mevcut ortam değişkenlerinin üzerine
yazmadığından .env içindeki bir DATABASE_URL da bunu bozmaz.

Geçici klasör test oturumu bitince silinir.
"""
import os
import shutil
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="wstg-test-db-")
TEST_DB_PATH = os.path.join(_TMP_DIR, "wstg-test.db")
REAL_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "wstg.db")

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
# Testler gerçek backend/instance/secret_key dosyasını üretmesin/okumasın.
os.environ["SECRET_KEY"] = "test-only-secret-key"
os.environ["WSTG_SECRET_KEY_FILE"] = os.path.join(_TMP_DIR, "secret_key")


def pytest_sessionfinish(session, exitstatus):
    try:
        import app as app_module
        from models import db
        with app_module.app.app_context():
            db.session.remove()
            db.engine.dispose()  # Windows'ta dosya kilidini bırakmak için
    except Exception:
        pass
    shutil.rmtree(_TMP_DIR, ignore_errors=True)


# ---------------------------------------------------------------------------
# Kimlik doğrulama
#
# Uygulamada kimlik doğrulamayı kapatan bir ayar/ortam değişkeni YOKTUR. Mevcut
# rota testleri giriş yapmadan çalışsın diye oturum kontrolü burada, yalnızca
# test sürecinde monkeypatch ile "giriş yapılmış" sayılır. Kimlik doğrulamanın
# kendisini test eden modüller `pytestmark = pytest.mark.real_auth` ile bu
# fixture'dan çıkar (bkz. test_auth.py).
# ---------------------------------------------------------------------------
import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "real_auth: gerçek oturum kontrolüyle çalışır (giriş gerekir)")


TEST_UPLOAD_DIR = os.path.join(_TMP_DIR, "uploads")


@pytest.fixture(autouse=True)
def _temp_upload_folder(monkeypatch):
    """Yükleme testleri gerçek backend/uploads klasörüne dosya yazmasın."""
    import app as app_module
    os.makedirs(TEST_UPLOAD_DIR, exist_ok=True)
    monkeypatch.setitem(app_module.app.config, "UPLOAD_FOLDER", TEST_UPLOAD_DIR)
    yield


@pytest.fixture(autouse=True)
def _bypass_login_for_route_tests(request, monkeypatch):
    if request.node.get_closest_marker("real_auth"):
        yield
        return
    import app as app_module
    monkeypatch.setattr(app_module, "_session_is_authenticated", lambda: True)
    yield
