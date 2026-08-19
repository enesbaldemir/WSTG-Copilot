import os
from dotenv import load_dotenv

# .env dosyasını, script'in çalıştırıldığı dizine (cwd) değil, HER ZAMAN
# bu config.py dosyasının bulunduğu backend/ klasörüne göre arar. Böylece
# uygulama proje kök dizininden, bir IDE'nin "Run" düğmesinden ya da başka
# bir klasörden başlatılsa bile backend/.env doğru şekilde bulunur.
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(_ENV_PATH)

class Config:
    # ABSOLUTE PATH KULLAN - Bu çözüm!
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "database", "wstg.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:8000,http://localhost:3000')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    # ==================== AI / LLM ENTEGRASYONU ====================
    # AI_PROVIDER: 'gemini' | 'openai' | 'anthropic' | 'ollama'
    # Varsayılan 'gemini' çünkü ücretsiz katmanı en cömert olan sağlayıcı.
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'gemini')

    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.5-flash')

    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')

    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
    ANTHROPIC_MODEL = os.getenv('ANTHROPIC_MODEL', 'claude-sonnet-4-6')

    # Ollama tamamen yerel/ücretsiz çalışır, API key gerekmez.
    OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3.1')

    AI_REQUEST_TIMEOUT = int(os.getenv('AI_REQUEST_TIMEOUT', '30'))
    AI_MAX_OUTPUT_TOKENS = int(os.getenv('AI_MAX_OUTPUT_TOKENS', '1500'))
    
class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'