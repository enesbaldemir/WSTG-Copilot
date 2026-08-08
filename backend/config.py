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
    
class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'