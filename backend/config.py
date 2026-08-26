import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ABSOLUTE PATH KULLAN - Bu çözüm!
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "database", "wstg.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:8000,http://localhost:3000')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    # Evidence Intelligence (opsiyonel): ayarlanırsa yüklenen ekran görüntüleri
    # Claude'un vision API'sine gönderilip WSTG testleriyle eşleştirilir.
    # Ayarlanmazsa özellik sessizce devre dışı kalır — sahte/uydurma analiz
    # ASLA üretilmez.
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')

    # Çok-sağlayıcılı AI katmanı (ai/factory.py). Bunlar sadece FALLBACK'tir --
    # birincil yol artık uygulama içindeki "AI Ayarları" panelidir (bkz.
    # AIProviderSetting modeli, /api/ai/settings rotaları). Burada hiçbiri
    # ayarlanmamışsa ve DB'de de aktif bir sağlayıcı yoksa AI özellikleri
    # sessizce devre dışı kalır, ASLA sahte içerik üretmez.
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'gemini')
    AI_REQUEST_TIMEOUT = int(os.getenv('AI_REQUEST_TIMEOUT', '30'))
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.7-flash')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-5.6-terra')
    ANTHROPIC_MODEL = os.getenv('ANTHROPIC_MODEL', 'claude-sonnet-5')
    OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3.1')

    # AI Ayarları panelinde saklanan API key'lerini şifrelemek için kullanılır
    # (bkz. crypto_utils.py). Ayarlanmazsa SECRET_KEY'den türetilir -- yani
    # SECRET_KEY değişirse önceden kaydedilmiş key'ler çözülemez hale gelir
    # (kullanıcı yeniden girmesi istenir). Sabit bir şifreleme anahtarı
    # istiyorsanız bunu ayrı ayarlayın.
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '')

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'