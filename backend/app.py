from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from datetime import datetime
import getpass
import os
import sys
import json
import re
import time
import uuid
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from config import DevelopmentConfig, ProductionConfig
from models import db, Session, TestResult, Note, AuthzMatrix, Project, ScopeItem, TimelineEvent, ReconRun, Evidence, CustomTest, ToolRun, Finding, AIInteractionLog, AIProviderSetting, AuthSettings
import auth
import retest as retest_lib
import authz_matrix
import image_types
import mapping as mapping_lib
import notes as notes_lib
import study_metrics
import recon
import attack_chains
import report_builder
import report_html
import report_generator
import report_pdf
import report_retest
import evidence_intel
import tool_runner
import cvss
import redaction
import duplicate_detector
import finding_lifecycle
import ai_report_assistant
import finding_analysis
import next_test_suggestion
import crypto_utils
import security
from ai.factory import get_ai_provider, _build_provider, DEFAULT_MODELS
from ai.base import AIConfigError, AIRequestError

app = Flask(__name__)

env = os.getenv('FLASK_ENV', 'development')
if env == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

# SECRET_KEY tanımlı değilse koddaki sabit değer yerine kalıcı, rastgele bir
# anahtar kullan (bkz. security.load_or_create_secret_key).
if not app.config.get('SECRET_KEY'):
    app.config['SECRET_KEY'], _secret_created = security.load_or_create_secret_key(app.config['SECRET_KEY_FILE'])
    if _secret_created:
        print(f"[güvenlik] SECRET_KEY tanımlı değil; rastgele bir anahtar oluşturuldu: {app.config['SECRET_KEY_FILE']}",
              file=sys.stderr)
elif app.config['SECRET_KEY'] == security.LEGACY_DEFAULT_SECRET:
    print('[güvenlik] UYARI: SECRET_KEY herkesin bildiği varsayılan değere ayarlı; .env dosyasında değiştirin.',
          file=sys.stderr)

db.init_app(app)

# CORS yalnızca izin verilen frontend adreslerine (CORS_ORIGINS) açıktır.
# supports_credentials: frontend oturum çerezini fetch(..., {credentials:
# 'include'}) ile gönderir; bu yalnızca listedeki origin'ler için geçerlidir.
_cors_origins = security.parse_list(app.config['CORS_ORIGINS'])
_allowed_hosts = security.parse_list(app.config['ALLOWED_HOSTS'])
CORS(app, resources={r"/api/*": {"origins": _cors_origins}}, supports_credentials=True)


@app.before_request
def _enforce_local_origin_policy():
    # DNS rebinding: başka bir alan adı 127.0.0.1'e çözülse bile Host başlığı
    # izin verilenler dışında kalır.
    if not security.host_header_allowed(request.host, _allowed_hosts):
        return jsonify({'error': 'Host başlığına izin verilmiyor (ALLOWED_HOSTS).'}), 400
    # CORS yanıtın okunmasını engeller ama isteğin gönderilmesini engellemez;
    # izinsiz bir siteden gelen durum değiştiren istekleri burada reddediyoruz.
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and \
            not security.origin_allowed(request.headers.get('Origin'), _cors_origins):
        return jsonify({'error': 'Bu kaynaktan (Origin) gelen isteğe izin verilmiyor (CORS_ORIGINS).'}), 403
    # Boyut sınırı rotalara girmeden uygulanır: rotalardaki genel
    # `except Exception` blokları Flask'ın 413 hatasını 500'e çeviriyordu.
    limit = app.config.get('MAX_CONTENT_LENGTH')
    if limit and request.content_length and request.content_length > limit:
        return _payload_too_large(None)


@app.after_request
def _add_security_headers(response):
    security.apply_security_headers(response.headers)
    return response


# ========================
# HATA YANITLARI
# ========================
# Beklenmeyen istisnaların metni (str(e)) istemciye GÖNDERİLMEZ: SQL
# hataları, dosya yolları, iç modül adları gibi ayrıntılar taşıyabilir.
# Bunun yerine kısa bir hata kimliği döner; tam traceback aynı kimlikle
# backend terminaline (app.logger) yazılır. Kasıtlı, kullanıcıya yönelik
# mesajlar (doğrulama hataları, NotFoundError, AI yapılandırma/istek
# hataları) kendi yanıtlarıyla olduğu gibi gösterilmeye devam eder.

HTTP_ERROR_MESSAGES = {
    400: 'Geçersiz istek (gövde okunamadı ya da eksik).',
    404: 'Kayıt bulunamadı.',
    405: 'Bu işlem bu adreste desteklenmiyor.',
    415: 'Desteklenmeyen içerik türü (JSON bekleniyordu).',
}


def _log_unexpected(e):
    error_id = uuid.uuid4().hex[:8]
    app.logger.error('Beklenmeyen hata [%s] %s %s', error_id, request.method, request.path,
                     exc_info=(type(e), e, e.__traceback__))
    return error_id


def _error_response(e, public_message=None):
    """Rotalardaki `except Exception as e:` blokları için tek çıkış noktası."""
    try:
        db.session.rollback()
    except Exception:
        pass
    if isinstance(e, HTTPException) and e.code and e.code < 500:
        # ör. get_or_404 -> 404, bozuk JSON -> 400 (eskiden 500 dönüyordu)
        return jsonify({'error': HTTP_ERROR_MESSAGES.get(e.code, e.name)}), e.code
    error_id = _log_unexpected(e)
    message = public_message or 'Beklenmeyen bir sunucu hatası oluştu.'
    return jsonify({'error': f'{message} (hata kimliği: {error_id}; ayrıntı backend terminalinde)',
                    'error_id': error_id}), 500


@app.errorhandler(413)
def _payload_too_large(_e):
    limit_mb = (app.config.get('MAX_CONTENT_LENGTH') or 0) // (1024 * 1024)
    return jsonify({'error': f'İstek çok büyük (en fazla {limit_mb} MB).'}), 413


# ========================
# KİMLİK DOĞRULAMA (bkz. auth.py)
# ========================

# Giriş yapılmadan erişilebilen uçlar. Diğer her istek (bilinmeyen yollar
# dahil) oturum ister; yeni eklenen rotalar varsayılan olarak korunur.
AUTH_OPEN_ENDPOINTS = frozenset({'auth_status', 'auth_setup', 'auth_login', 'auth_logout'})
login_throttle = auth.LoginThrottle()


def _now():
    return time.time()


def _auth_settings():
    return db.session.get(AuthSettings, 1)


def _session_is_authenticated():
    """Çerez geçerli bir girişe mi ait? İmza Flask tarafından doğrulanır;
    burada parola değişiminden önceki oturumlar (session_version) ve
    girişten bu yana PERMANENT_SESSION_LIFETIME'ı aşanlar reddedilir."""
    if not session.get('auth'):
        return False
    settings = _auth_settings()
    if settings is None or session.get('v') != settings.session_version:
        return False
    iat = session.get('iat')
    if not isinstance(iat, (int, float)):
        return False
    return 0 <= _now() - iat <= app.permanent_session_lifetime.total_seconds()


def _start_auth_session(settings):
    session.clear()
    session.permanent = True
    session['auth'] = True
    session['v'] = settings.session_version
    session['iat'] = int(_now())


def _client_key():
    return request.remote_addr or 'unknown'


def _too_many_attempts(wait):
    resp = jsonify({'error': f'Çok fazla hatalı deneme. {wait} saniye sonra tekrar deneyin.',
                    'code': 'too_many_attempts', 'retry_after': wait})
    resp.status_code = 429
    resp.headers['Retry-After'] = str(wait)
    return resp


@app.before_request
def _require_login():
    # Preflight (OPTIONS) çerez taşımaz; CORS yanıtını flask-cors üretir.
    if request.method == 'OPTIONS' or request.endpoint in AUTH_OPEN_ENDPOINTS:
        return None
    if not _session_is_authenticated():
        return jsonify({'error': 'Oturum açmanız gerekiyor.', 'code': 'auth_required'}), 401
    return None


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    configured = _auth_settings() is not None
    return jsonify({
        'configured': configured,
        'authenticated': configured and _session_is_authenticated(),
        'setup_allowed': not configured and auth.is_loopback_addr(request.remote_addr),
        'min_password_length': auth.MIN_PASSWORD_LENGTH,
    })


@app.route('/api/auth/setup', methods=['POST'])
def auth_setup():
    """İlk parola. Yalnızca bu bilgisayardan ve yalnızca bir kez."""
    if not auth.is_loopback_addr(request.remote_addr):
        return jsonify({'error': 'İlk parola yalnızca bu bilgisayardan belirlenebilir '
                                 '(veya: python app.py set-password).', 'code': 'setup_loopback_only'}), 403
    if _auth_settings() is not None:
        return jsonify({'error': 'Parola zaten belirlenmiş.', 'code': 'already_configured'}), 409
    data = request.get_json(silent=True) or {}
    try:
        password_hash = auth.hash_password(data.get('password'))
    except auth.PasswordPolicyError as e:
        return jsonify({'error': str(e), 'code': e.code}), 400
    settings = AuthSettings(id=1, password_hash=password_hash, session_version=1)
    db.session.add(settings)
    try:
        db.session.commit()
    except IntegrityError:  # eşzamanlı ikinci kurulum isteği
        db.session.rollback()
        return jsonify({'error': 'Parola zaten belirlenmiş.', 'code': 'already_configured'}), 409
    _start_auth_session(settings)
    return jsonify({'ok': True}), 201


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    key = _client_key()
    wait = login_throttle.retry_after(key)
    if wait:
        return _too_many_attempts(wait)
    settings = _auth_settings()
    if settings is None:
        return jsonify({'error': 'Önce parola belirlenmeli.', 'code': 'setup_required'}), 409
    data = request.get_json(silent=True) or {}
    if not auth.verify_password(settings.password_hash, data.get('password')):
        login_throttle.failure(key)
        wait = login_throttle.retry_after(key)
        if wait:
            return _too_many_attempts(wait)
        return jsonify({'error': 'Parola hatalı.', 'code': 'invalid_password'}), 401
    login_throttle.success(key)
    _start_auth_session(settings)
    return jsonify({'ok': True})


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/auth/change-password', methods=['POST'])
def auth_change_password():
    """Mevcut parolayı ister. session_version artar: diğer tarayıcılardaki
    oturumlar düşer, bu oturum yeni sürümle devam eder."""
    key = _client_key()
    wait = login_throttle.retry_after(key)
    if wait:
        return _too_many_attempts(wait)
    settings = _auth_settings()
    data = request.get_json(silent=True) or {}
    if not auth.verify_password(settings.password_hash, data.get('current_password')):
        login_throttle.failure(key)
        wait = login_throttle.retry_after(key)
        if wait:
            return _too_many_attempts(wait)
        # 401 değil: frontend 401'i "oturum düştü" olarak yorumlar.
        return jsonify({'error': 'Mevcut parola hatalı.', 'code': 'invalid_current_password'}), 403
    new_password = data.get('new_password')
    try:
        new_hash = auth.hash_password(new_password)
    except auth.PasswordPolicyError as e:
        return jsonify({'error': str(e), 'code': e.code}), 400
    if auth.verify_password(settings.password_hash, new_password):
        return jsonify({'error': 'Yeni parola mevcut paroladan farklı olmalıdır.', 'code': 'password_unchanged'}), 400
    settings.password_hash = new_hash
    settings.session_version = (settings.session_version or 0) + 1
    db.session.commit()
    login_throttle.success(key)
    _start_auth_session(settings)
    return jsonify({'ok': True})

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'evidence'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database'), exist_ok=True)


def ensure_schema():
    """db.create_all() sadece EKSİK tabloları oluşturur, var olan tabloları
    ALTER etmez. Project modülü ile birlikte 'sessions' tablosuna eklenen
    'project_id' kolonu, önceden oluşturulmuş bir veritabanı dosyasında
    eksik kalabilir. Bu fonksiyon önce eksik tabloları yaratır, sonra
    'sessions' tablosunda 'project_id' kolonu yoksa ekler (SQLite'ta basit
    ADD COLUMN ile). Var olan hiçbir veriyi silmez/değiştirmez."""
    db.create_all()
    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(sessions)")).fetchall()]
        if 'project_id' not in cols:
            db.session.execute(text("ALTER TABLE sessions ADD COLUMN project_id VARCHAR(36)"))
            db.session.commit()
    except Exception:
        db.session.rollback()  # muhtemelen SQLite dışında bir DB — sessizce geç

    try:
        # 260eeb6 öncesi veritabanlarında bu sütun zaten vardır; arada
        # oluşturulmuş veritabanlarına eklenir. 'notes' tablosu create_all ile
        # (yoksa) oluşur; varsa içindeki eski notlar olduğu gibi kalır.
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(sessions)")).fetchall()]
        if 'study_group' not in cols:
            db.session.execute(text("ALTER TABLE sessions ADD COLUMN study_group VARCHAR(20)"))
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(test_results)")).fetchall()]
        if 'finding_status' not in cols:
            db.session.execute(text("ALTER TABLE test_results ADD COLUMN finding_status VARCHAR(20) DEFAULT 'open'"))
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(evidence)")).fetchall()]
        if 'linked_finding_id' not in cols:
            db.session.execute(text("ALTER TABLE evidence ADD COLUMN linked_finding_id INTEGER"))
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(evidence)")).fetchall()]
        http_cols = {
            'evidence_type': "VARCHAR(20) DEFAULT 'image'",
            'http_request': "TEXT", 'http_response': "TEXT",
            'http_request_redacted': "TEXT", 'http_response_redacted': "TEXT",
        }
        for col, coltype in http_cols.items():
            if col not in cols:
                db.session.execute(text(f"ALTER TABLE evidence ADD COLUMN {col} {coltype}"))
        # filename/stored_filename artık NOT NULL değil ama SQLite ALTER TABLE
        # ile mevcut NOT NULL kısıtlaması kaldırılamaz -- yeni satırlar zaten
        # models.py üzerinden nullable olarak ekleniyor, sorun teşkil etmez.
        db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(test_results)")).fetchall()]
        kanban_cols = {
            'kanban_status': "VARCHAR(20) DEFAULT 'todo'",
            'assigned_to': "VARCHAR(100)",
            'time_spent_minutes': "INTEGER DEFAULT 0",
        }
        for col, coltype in kanban_cols.items():
            if col not in cols:
                db.session.execute(text(f"ALTER TABLE test_results ADD COLUMN {col} {coltype}"))
        db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(findings)")).fetchall()]
        if 'merged_finding_ids' not in cols:
            db.session.execute(text("ALTER TABLE findings ADD COLUMN merged_finding_ids TEXT"))
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(recon_runs)")).fetchall()]
        recon_cols = {
            'base_url': "VARCHAR(300)",
            'apis': "TEXT",
            'interesting_paths': "TEXT",
            'forms': "TEXT",
            'cookies_present': "BOOLEAN DEFAULT 0",
            'suggestions': "TEXT",
        }
        for col, coltype in recon_cols.items():
            if col not in cols:
                db.session.execute(text(f"ALTER TABLE recon_runs ADD COLUMN {col} {coltype}"))
        db.session.commit()
    except Exception:
        db.session.rollback()


def migrate_legacy_ai_keys():
    """Eski sürümler SECRET_KEY tanımlı değilken AI anahtarlarını sabit bir
    değerden türetilen anahtarla şifreliyordu. Yeni (rastgele) anahtara geçerken
    bu kayıtları yeniden şifreler; böylece kayıtlı anahtarlar kaybolmaz."""
    if app.config.get('SECRET_KEY') == security.LEGACY_DEFAULT_SECRET:
        return 0
    moved = 0
    try:
        for setting in AIProviderSetting.query.all():
            new_token = crypto_utils.reencrypt_from_legacy(
                app.config, setting.api_key_encrypted, [security.LEGACY_DEFAULT_SECRET])
            if new_token:
                setting.api_key_encrypted = new_token
                moved += 1
        if moved:
            db.session.commit()
            print(f'[güvenlik] {moved} kayıtlı AI anahtarı yeni SECRET_KEY ile yeniden şifrelendi.', file=sys.stderr)
    except Exception:
        db.session.rollback()
    return moved


with app.app_context():
    ensure_schema()
    migrate_legacy_ai_keys()


def log_event(project_id, event_type, message, meta=None):
    """Bir proje altında gerçekleşen olayı Timeline'a kaydeder.
    project_id boşsa (proje bağlamı olmayan eski/bağımsız kullanım) hiçbir
    şey yapmaz — mevcut proje-siz akışları etkilemez."""
    if not project_id:
        return
    try:
        event = TimelineEvent(
            project_id=project_id,
            event_type=event_type,
            message=message,
            meta=json.dumps(meta) if meta is not None else None
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        db.session.rollback()

# ========================
# SESSION ENDPOINT'LERİ
# ========================

STUDY_GROUPS = (None, 'ai_assisted', 'control')
STUDY_GROUP_ERROR = "study_group 'ai_assisted', 'control' ya da null olmalıdır"


@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    try:
        query = Session.query
        project_id = request.args.get('project_id')
        if project_id:
            query = query.filter_by(project_id=project_id)
        sessions = query.order_by(Session.created_at.desc()).all()
        return jsonify([s.to_dict() for s in sessions]), 200
    except Exception as e:
        return _error_response(e)

@app.route('/api/sessions/<session_id>', methods=['GET'])
def get_session(session_id):
    session = db.session.get(Session, session_id)
    if not session:
        return jsonify({'error': 'Oturum bulunamadı'}), 404
    return jsonify(session.to_dict()), 200

@app.route('/api/sessions', methods=['POST'])
def create_session():
    try:
        data = request.json
        
        if not data.get('name'):
            return jsonify({'error': 'Oturum adı zorunludur'}), 400

        project_id = data.get('project_id')
        if project_id and not Project.query.get(project_id):
            return jsonify({'error': 'Belirtilen proje bulunamadı'}), 404

        study_group = data.get('study_group') or None
        if study_group not in STUDY_GROUPS:
            return jsonify({'error': STUDY_GROUP_ERROR}), 400

        session = Session(
            study_group=study_group,
            project_id=project_id,
            name=data['name'],
            description=data.get('description', ''),
            tester_name=data.get('tester_name', ''),
            target_url=data.get('target_url', ''),
            target_description=data.get('target_description', ''),
            status='active',
            started_at=datetime.utcnow()
        )
        
        db.session.add(session)
        db.session.commit()

        if project_id:
            log_event(project_id, 'session_created', f"Test oturumu oluşturuldu: {session.name}")
        
        return jsonify(session.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

@app.route('/api/sessions/<session_id>', methods=['PUT'])
def update_session(session_id):
    try:
        session = Session.query.get_or_404(session_id)
        data = request.json
        
        if 'name' in data:
            session.name = data['name']
        if 'description' in data:
            session.description = data['description']
        if 'tester_name' in data:
            session.tester_name = data['tester_name']
        if 'target_url' in data:
            session.target_url = data['target_url']
        if 'target_description' in data:
            session.target_description = data['target_description']
        if 'status' in data:
            session.status = data['status']
            if data['status'] == 'completed':
                session.completed_at = datetime.utcnow()
                if session.project_id:
                    log_event(session.project_id, 'session_completed', f"Test oturumu tamamlandı: {session.name}")
            elif data['status'] == 'active':
                session.completed_at = None
        if 'study_group' in data:
            group = data['study_group'] or None
            if group not in STUDY_GROUPS:
                db.session.rollback()
                return jsonify({'error': STUDY_GROUP_ERROR}), 400
            session.study_group = group

        session.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify(session.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    try:
        session = Session.query.get_or_404(session_id)
        db.session.delete(session)
        db.session.commit()
        return jsonify({'message': 'Oturum silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

# ========================
# TEST RESULT ENDPOINT'LERİ
# ========================

@app.route('/api/sessions/<session_id>/results', methods=['GET'])
def get_test_results(session_id):
    try:
        results = TestResult.query.filter_by(session_id=session_id).all()
        return jsonify([r.to_dict() for r in results]), 200
    except Exception as e:
        return _error_response(e)

@app.route('/api/sessions/<session_id>/results/<test_id>', methods=['GET'])
def get_test_result(session_id, test_id):
    result = TestResult.query.filter_by(session_id=session_id, test_id=test_id).first()
    if not result:
        return jsonify({'error': 'Test sonucu bulunamadı'}), 404
    return jsonify(result.to_dict()), 200

@app.route('/api/sessions/<session_id>/results', methods=['POST'])
def create_test_result(session_id):
    try:
        data = request.json
        
        session = Session.query.get_or_404(session_id)
        
        existing = TestResult.query.filter_by(
            session_id=session_id,
            test_id=data['test_id']
        ).first()
        
        if existing:
            return jsonify({'error': 'Bu test zaten kaydedilmiş'}), 409
        
        result = TestResult(
            session_id=session_id,
            test_id=data['test_id'],
            category_id=data.get('category_id', ''),
            status=data.get('status', 'pending'),
            severity=data.get('severity', 'info'),
            notes=data.get('notes', ''),
            evidence=data.get('evidence', ''),
            finding=data.get('finding', ''),
            finding_status=data.get('finding_status') if data.get('finding_status') in VALID_FINDING_STATUSES else 'open',
            started_at=datetime.utcnow()
        )
        
        db.session.add(result)
        db.session.commit()

        if session.project_id:
            if result.finding and result.finding.strip():
                log_event(session.project_id, 'finding_created',
                          f"Yeni bulgu: {result.test_id} ({result.severity or 'info'})",
                          {'session_id': session_id, 'test_id': result.test_id, 'severity': result.severity})
            if result.status in ['passed', 'failed', 'skipped']:
                log_event(session.project_id, 'test_completed',
                          f"{result.test_id} → {result.status}", {'session_id': session_id, 'test_id': result.test_id})
        
        return jsonify(result.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

@app.route('/api/sessions/<session_id>/results/<test_id>', methods=['PUT'])
def update_test_result(session_id, test_id):
    try:
        result = TestResult.query.filter_by(
            session_id=session_id,
            test_id=test_id
        ).first_or_404()
        
        data = request.json
        session_obj = Session.query.get(session_id)
        had_finding_before = bool(result.finding and result.finding.strip())
        old_finding_status = result.finding_status
        
        if 'status' in data:
            result.status = data['status']
            if data['status'] in ['passed', 'failed', 'skipped']:
                result.completed_at = datetime.utcnow()
                if session_obj and session_obj.project_id:
                    log_event(session_obj.project_id, 'test_completed',
                              f"{test_id} → {data['status']}", {'session_id': session_id, 'test_id': test_id})
        if 'severity' in data:
            result.severity = data['severity']
        if 'notes' in data:
            result.notes = data['notes']
        if 'evidence' in data:
            result.evidence = data['evidence']
        if 'finding' in data:
            result.finding = data['finding']
        if 'finding_status' in data:
            if data['finding_status'] not in VALID_FINDING_STATUSES:
                return jsonify({'error': 'Geçersiz finding_status değeri'}), 400
            result.finding_status = data['finding_status']
        if 'progress' in data:
            result.progress = data['progress']
        
        result.updated_at = datetime.utcnow()
        db.session.commit()

        has_finding_now = bool(result.finding and result.finding.strip())
        if has_finding_now and not had_finding_before and session_obj and session_obj.project_id:
            log_event(session_obj.project_id, 'finding_created',
                      f"Yeni bulgu: {test_id} ({result.severity or 'info'})",
                      {'session_id': session_id, 'test_id': test_id, 'severity': result.severity})

        if session_obj and session_obj.project_id and result.finding_status != old_finding_status:
            log_event(session_obj.project_id, 'finding_status_changed',
                      f"{test_id}: {old_finding_status} → {result.finding_status}",
                      {'session_id': session_id, 'test_id': test_id,
                       'from': old_finding_status, 'to': result.finding_status})
        
        return jsonify(result.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

@app.route('/api/sessions/<session_id>/results/<test_id>', methods=['DELETE'])
def delete_test_result(session_id, test_id):
    try:
        result = TestResult.query.filter_by(
            session_id=session_id,
            test_id=test_id
        ).first_or_404()
        
        db.session.delete(result)
        db.session.commit()
        
        return jsonify({'message': 'Test sonucu silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

# ========================
# NOT DEFTERİ
# ========================
# Oturuma bağlı serbest not defteri (görsel kanıt, CVSS/CWE, false-positive
# kararı). Doğrulama notes.py'de. 260eeb6 ile kaldırılan uçların geri
# getirilmiş hâli; istek/yanıt biçimi eskisiyle aynıdır.

def _session_or_none(session_id):
    return db.session.get(Session, session_id)


@app.route('/api/sessions/<session_id>/notes', methods=['GET'])
def get_notes(session_id):
    if not _session_or_none(session_id):
        return jsonify({'error': 'Oturum bulunamadı'}), 404
    query = Note.query.filter_by(session_id=session_id)
    test_id = request.args.get('test_id')
    if test_id:
        query = query.filter_by(test_id=test_id)
    notes = query.order_by(Note.created_at.desc(), Note.id.desc()).all()
    return jsonify([n.to_dict() for n in notes]), 200


@app.route('/api/sessions/<session_id>/notes', methods=['POST'])
def create_note(session_id):
    if not _session_or_none(session_id):
        return jsonify({'error': 'Oturum bulunamadı'}), 404
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'JSON gövde bekleniyordu'}), 400
    note = Note(session_id=session_id)
    try:
        notes_lib.apply_fields(note, data, creating=True)
    except notes_lib.NoteValidationError as e:
        return jsonify({'error': str(e)}), 400
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201


@app.route('/api/sessions/<session_id>/notes/<int:note_id>', methods=['PUT'])
def update_note(session_id, note_id):
    note = Note.query.filter_by(session_id=session_id, id=note_id).first()
    if not note:
        return jsonify({'error': 'Not bulunamadı'}), 404
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'JSON gövde bekleniyordu'}), 400
    try:
        notes_lib.apply_fields(note, data)
    except notes_lib.NoteValidationError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
    note.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(note.to_dict()), 200


@app.route('/api/sessions/<session_id>/notes/<int:note_id>', methods=['DELETE'])
def delete_note(session_id, note_id):
    note = Note.query.filter_by(session_id=session_id, id=note_id).first()
    if not note:
        return jsonify({'error': 'Not bulunamadı'}), 404
    db.session.delete(note)
    db.session.commit()
    return jsonify({'message': 'Not silindi'}), 200


@app.route('/api/mapping/wstg/<test_id>', methods=['GET'])
def wstg_mapping(test_id):
    """Bir WSTG testi için ilişkili OWASP Top 10 kategorileri ve önerilen
    CWE'ler (not editöründeki CWE önerileri buradan beslenir)."""
    lang = 'en' if request.args.get('lang') == 'en' else 'tr'
    return jsonify({
        'test_id': test_id,
        'owasp_matches': mapping_lib.get_mapping_for_test(test_id, lang),
        'suggested_cwes': mapping_lib.suggest_cwes_for_test(test_id, lang),
    }), 200


# ========================
# DENEYSEL A/B KARŞILAŞTIRMA (çalışma metrikleri)
# ========================

@app.route('/api/study/metrics', methods=['GET'])
def study_metrics_endpoint():
    """'ai_assisted' / 'control' grubuna atanmış oturumların metrikleri ve
    iki grubun karşılaştırması. Grubu olmayan oturumlar hesaplamaya girmez,
    yalnızca 'unassigned_sessions_count' ile sayılır.

    Bulgular: oturumun notları + o oturuma bağlı Finding kayıtları (bugün
    bulguların çoğu Finding olarak tutuluyor). AI çağrıları: session_id'si bu
    oturum olan kayıtlar + bu oturumun Finding'leri üzerinden yapılanlar."""
    per_session = []
    unassigned = 0
    for s in Session.query.order_by(Session.created_at.asc()).all():
        if not s.study_group:
            unassigned += 1
            continue
        session_findings = Finding.query.filter_by(session_id=s.id).all()
        finding_ids = [f.id for f in session_findings]
        log_filter = AIInteractionLog.session_id == s.id
        if finding_ids:
            log_filter = db.or_(log_filter, AIInteractionLog.finding_id.in_(finding_ids))
        logs = AIInteractionLog.query.filter(log_filter).all()
        findings = [n.to_dict() for n in s.notes] + [
            {'severity': f.severity, 'is_false_positive': None, 'source': 'finding'}
            for f in session_findings
        ]
        per_session.append(study_metrics.compute_session_metrics(
            s.to_dict(), [r.to_dict() for r in s.results], findings, [l.to_dict() for l in logs],
        ))
    return jsonify({
        'sessions': per_session,
        'comparison': study_metrics.compare_groups(per_session),
        'unassigned_sessions_count': unassigned,
    }), 200

# ========================
# RAPOR ENDPOINT'İ
# ========================

@app.route('/api/sessions/<session_id>/report', methods=['GET'])
def generate_report(session_id):
    try:
        session = Session.query.get_or_404(session_id)
        results = TestResult.query.filter_by(session_id=session_id).all()
        
        total = len(results)
        passed = len([r for r in results if r.status == 'passed'])
        failed = len([r for r in results if r.status == 'failed'])
        skipped = len([r for r in results if r.status == 'skipped'])
        pending = len([r for r in results if r.status == 'pending'])
        
        report = {
            'session': session.to_dict(),
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'pending': pending,
                'completion_rate': round((passed + failed) / total * 100, 2) if total > 0 else 0
            },
            'results': [r.to_dict() for r in results],
            'generated_at': datetime.utcnow().isoformat()
        }
        
        return jsonify(report), 200
    except Exception as e:
        return _error_response(e)

# ========================
# ATTACK SURFACE DISCOVERY (RECON) ENDPOINT'İ
# ========================
#
# Bu endpoint yalnızca kullanıcının kendi makinesinde, kendi belirttiği
# hedefe karşı PASİF (crt.sh CT log) ve HAFİF-AKTİF (tek istek + WSTG'nin
# kendi önerdiği küçük, bilinen yol listesi) bir keşif yapar. Kullanıcı
# `confirm_authorized: true` göndermezse istek reddedilir — bu, aracın
# yanlışlıkla yetkisiz bir hedefe karşı kullanılmasının önüne geçmek
# için bilinçli olarak konmuş bir zorunluluktur ve gevşetilmemelidir.
@app.route('/api/recon', methods=['POST'])
def run_recon():
    try:
        data = request.json or {}
        if not data.get('confirm_authorized'):
            return jsonify({'error': 'Bu hedefi test etmeye yetkili olduğunuzu onaylamalısınız (confirm_authorized).'}), 400

        target = data.get('target', '')
        try:
            result = recon.run_discovery(target)
        except recon.ReconError as e:
            return jsonify({'error': str(e)}), 400

        project_id = data.get('project_id')
        if project_id and Project.query.get(project_id):
            try:
                run = ReconRun(
                    project_id=project_id,
                    target=result.get('target'),
                    base_url=result.get('baseUrl'),
                    subdomains=json.dumps(result.get('subdomains', [])),
                    technologies=json.dumps(result.get('technologies', [])),
                    endpoints=json.dumps(list(dict.fromkeys(
                        (result.get('endpoints') or []) + [p['path'] for p in (result.get('interestingPaths') or [])]
                    ))),
                    apis=json.dumps(result.get('apis', [])),
                    interesting_paths=json.dumps(result.get('interestingPaths', [])),
                    forms=json.dumps(result.get('forms', [])),
                    cookies_present=bool(result.get('cookiesPresent')),
                    suggestions=json.dumps(result.get('suggestions', {})),
                )
                db.session.add(run)
                db.session.commit()
                log_event(project_id, 'recon_run', f"Attack Surface Discovery çalıştırıldı: {result.get('target')}",
                          {'subdomains': len(result.get('subdomains', [])), 'technologies': result.get('technologies', [])})
            except Exception:
                db.session.rollback()

        return jsonify(result), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/recon/latest', methods=['GET'])
def get_latest_recon(project_id):
    """Bir projenin en son Attack Surface Discovery taramasını döner.
    Bu sayede kullanıcı Attack Surface Discovery penceresini kapatıp tekrar
    açtığında (ya da proje değiştirdiğinde) daha önce bulduğu subdomain/
    teknoloji/endpoint/öneri listesini yeniden taramadan görebilir. Hiç
    tarama yapılmamışsa 'run': null döner (hata değildir)."""
    try:
        _project_or_404(project_id)
        run = ReconRun.query.filter_by(project_id=project_id).order_by(ReconRun.created_at.desc()).first()
        return jsonify({'run': run.to_dict() if run else None}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/recon', methods=['DELETE'])
def clear_project_recon(project_id):
    """Bir projenin tüm recon geçmişini temizler -- kullanıcı farklı bir
    hedefe karşı sıfırdan taramak istediğinde ('Sıfırla / Yeniden Tara')
    kullanılır. Bulgu/oturum verisine dokunmaz."""
    try:
        _project_or_404(project_id)
        ReconRun.query.filter_by(project_id=project_id).delete()
        db.session.commit()
        log_event(project_id, 'recon_cleared', 'Attack Surface Discovery geçmişi temizlendi')
        return jsonify({'message': 'Recon geçmişi temizlendi'}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)

# ========================
# PROJECT / ENGAGEMENT ENDPOINT'LERİ
# ========================

class NotFoundError(Exception):
    """Werkzeug'un get_or_404()/first_or_404() fırlattığı NotFound, bu
    dosyadaki geniş 'except Exception' bloklarına yakalanıp yanlışlıkla
    500'e çevriliyordu (var olmayan/başka projeye ait bir kayıt 404 yerine
    500 dönüyordu). Bunun yerine kendi NotFoundError'ımızı kullanıp her
    endpoint'te ayrıca yakalayarak doğru 404 döndürüyoruz."""
    pass

def _project_or_404(project_id):
    project = Project.query.get(project_id)
    if not project:
        raise NotFoundError('Proje bulunamadı')
    return project

def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None

VALID_PROJECT_STATUSES = {'planning', 'active', 'paused', 'completed', 'archived'}
VALID_SCOPE_TYPES = {'domain', 'subdomain', 'ip', 'cidr'}
VALID_FINDING_STATUSES = {'open', 'retesting', 'fixed', 'resolved', 'wont_fix', 'accepted_risk'}


@app.route('/api/projects', methods=['GET'])
def get_projects():
    try:
        projects = Project.query.order_by(Project.updated_at.desc()).all()
        return jsonify([p.to_dict() for p in projects]), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects', methods=['POST'])
def create_project():
    try:
        data = request.json or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'Proje adı zorunludur'}), 400

        status = data.get('status', 'planning')
        if status not in VALID_PROJECT_STATUSES:
            status = 'planning'

        project = Project(
            name=name,
            client=(data.get('client') or '').strip(),
            description=data.get('description', ''),
            status=status,
            start_date=_parse_date(data.get('start_date')),
            end_date=_parse_date(data.get('end_date'))
        )
        db.session.add(project)
        db.session.commit()

        log_event(project.id, 'project_created', f"Proje oluşturuldu: {project.name}")

        return jsonify(project.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>', methods=['GET'])
def get_project(project_id):
    try:
        project = _project_or_404(project_id)
        return jsonify(project.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>', methods=['PUT'])
def update_project(project_id):
    try:
        project = _project_or_404(project_id)
        data = request.json or {}

        if 'name' in data:
            name = (data['name'] or '').strip()
            if not name:
                return jsonify({'error': 'Proje adı boş olamaz'}), 400
            project.name = name
        if 'client' in data:
            project.client = data['client']
        if 'description' in data:
            project.description = data['description']
        if 'status' in data:
            if data['status'] not in VALID_PROJECT_STATUSES:
                return jsonify({'error': 'Geçersiz durum'}), 400
            project.status = data['status']
        if 'start_date' in data:
            project.start_date = _parse_date(data['start_date'])
        if 'end_date' in data:
            project.end_date = _parse_date(data['end_date'])

        project.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify(project.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>', methods=['DELETE'])
def delete_project(project_id):
    try:
        project = _project_or_404(project_id)
        # Sessions/test sonuçları bilerek silinmiyor — sadece proje bağı
        # kaldırılıyor, böylece o oturumdaki test verisi/bulgular kaybolmaz.
        for s in project.sessions:
            s.project_id = None
        db.session.delete(project)
        db.session.commit()
        return jsonify({'message': 'Proje silindi'}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/dashboard', methods=['GET'])
def project_dashboard(project_id):
    try:
        project = _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        all_results = []
        for s in sessions:
            all_results.extend(s.results)

        total_tests = len(all_results)
        completed_tests = len([r for r in all_results if r.status != 'pending'])
        findings = [r for r in all_results if r.finding and r.finding.strip()]

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for r in findings:
            sev = (r.severity or 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        recon_runs = ReconRun.query.filter_by(project_id=project_id).all()
        asset_set = set()
        for run in recon_runs:
            try:
                asset_set.update(json.loads(run.subdomains or '[]'))
            except Exception:
                pass

        # --- Framework Coverage (WSTG / LLM Security / Custom) ---
        # report_builder.WSTG_INDEX iki resmi checklist'i (WSTG-04 + LLM Top10
        # 2025) zaten birleştirmiş durumda; test_id önekine göre ayırıyoruz.
        wstg_total = len([k for k in report_builder.WSTG_INDEX if k.startswith('WSTG-')])
        llm_total = len([k for k in report_builder.WSTG_INDEX if k.startswith('LLM-')])
        custom_total = CustomTest.query.filter_by(project_id=project_id).count()

        wstg_completed_ids, llm_completed_ids, custom_completed_ids = set(), set(), set()
        for r in all_results:
            if r.status == 'pending':
                continue
            if r.test_id.startswith('WSTG-'):
                wstg_completed_ids.add(r.test_id)
            elif r.test_id.startswith('LLM-'):
                llm_completed_ids.add(r.test_id)
            elif r.test_id.startswith('CUSTOM-'):
                custom_completed_ids.add(r.test_id)

        def _coverage(completed_n, total_n):
            return {'completed': completed_n, 'total': total_n,
                    'pct': round((completed_n / total_n) * 100, 1) if total_n else 0}

        coverage = {
            'wstg': _coverage(len(wstg_completed_ids), wstg_total),
            'llm': _coverage(len(llm_completed_ids), llm_total),
            'custom': _coverage(len(custom_completed_ids), custom_total),
        }

        # --- Findings by Category (Finding.test_id önekinden WSTG kategorisi) ---
        pro_findings = Finding.query.filter_by(project_id=project_id).all()
        findings_by_category = {}
        for f in pro_findings:
            cat_name = f.owasp_category
            if not cat_name and f.test_id:
                meta = report_builder.WSTG_INDEX.get(f.test_id)
                cat_name = meta['category_name'] if meta else None
            cat_name = cat_name or 'Diğer / Kategorisiz'
            findings_by_category[cat_name] = findings_by_category.get(cat_name, 0) + 1

        # --- Most Tested Endpoints (Finding.endpoint sıklığı) ---
        endpoint_counts = {}
        for f in pro_findings:
            if f.endpoint:
                endpoint_counts[f.endpoint] = endpoint_counts.get(f.endpoint, 0) + 1
        top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return jsonify({
            'project': project.to_dict(),
            'session_count': len(sessions),
            'total_tests': total_tests,
            'completed_tests': completed_tests,
            'progress_pct': round((completed_tests / total_tests) * 100, 1) if total_tests else 0,
            'finding_count': len(findings),
            'severity_counts': severity_counts,
            'asset_count': len(asset_set),
            'recon_run_count': len(recon_runs),
            'coverage': coverage,
            'findings_by_category': findings_by_category,
            'top_endpoints': [{'endpoint': e, 'count': c} for e, c in top_endpoints],
            'pro_finding_count': len(pro_findings),
        }), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/assets', methods=['GET'])
def project_assets(project_id):
    try:
        _project_or_404(project_id)
        runs = ReconRun.query.filter_by(project_id=project_id).order_by(ReconRun.created_at.desc()).all()
        subdomains, technologies, endpoints = set(), set(), set()
        for run in runs:
            try:
                subdomains.update(json.loads(run.subdomains or '[]'))
                technologies.update(json.loads(run.technologies or '[]'))
                endpoints.update(json.loads(run.endpoints or '[]'))
            except Exception:
                pass
        return jsonify({
            'subdomains': sorted(subdomains),
            'technologies': sorted(technologies),
            'endpoints': sorted(endpoints),
            'runs': [r.to_dict() for r in runs]
        }), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/scope', methods=['GET'])
def get_scope(project_id):
    try:
        _project_or_404(project_id)
        items = ScopeItem.query.filter_by(project_id=project_id).order_by(ScopeItem.created_at.desc()).all()
        return jsonify([i.to_dict() for i in items]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/scope', methods=['POST'])
def add_scope_item(project_id):
    try:
        _project_or_404(project_id)
        data = request.json or {}
        value = (data.get('value') or '').strip()
        scope_type = data.get('type', 'domain')
        if not value:
            return jsonify({'error': 'Değer zorunludur'}), 400
        if scope_type not in VALID_SCOPE_TYPES:
            return jsonify({'error': 'Geçersiz kapsam türü'}), 400

        item = ScopeItem(
            project_id=project_id,
            type=scope_type,
            value=value,
            description=data.get('description', ''),
            in_scope=bool(data.get('in_scope', True))
        )
        db.session.add(item)
        db.session.commit()
        log_event(project_id, 'scope_updated', f"Kapsama eklendi: {value} ({'in-scope' if item.in_scope else 'out-of-scope'})")
        return jsonify(item.to_dict()), 201
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/scope/<int:scope_id>', methods=['DELETE'])
def delete_scope_item(project_id, scope_id):
    try:
        # IDOR koruması: kayıt hem id hem de bu project_id'ye ait olmalı —
        # başka bir projenin scope kaydı bu URL üzerinden silinemez. Bilinçli
        # olarak first_or_404() KULLANILMADI: Werkzeug'un fırlattığı NotFound
        # istisnası aşağıdaki 'except Exception' bloğuna düşüp 500'e
        # dönüşüyordu — bunun yerine 404'ü açıkça döndürüyoruz.
        item = ScopeItem.query.filter_by(id=scope_id, project_id=project_id).first()
        if not item:
            return jsonify({'error': 'Kapsam kaydı bulunamadı'}), 404
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Kapsam kaydı silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/timeline', methods=['GET'])
def get_timeline(project_id):
    try:
        _project_or_404(project_id)
        events = TimelineEvent.query.filter_by(project_id=project_id).order_by(TimelineEvent.created_at.desc()).limit(200).all()
        return jsonify([e.to_dict() for e in events]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/attack-chains', methods=['GET'])
def get_attack_chains(project_id):
    try:
        _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        findings = []
        for s in sessions:
            for r in s.results:
                if r.finding and r.finding.strip():
                    findings.append({'test_id': r.test_id, 'severity': r.severity})
        chains = attack_chains.detect_chains(findings)
        return jsonify({'chains': chains, 'finding_count': len(findings)}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


# ========================
# YETKİLENDİRME MATRİSİ (roller x endpoint'ler; bkz. authz_matrix.py)
# ========================
# Uygulama hedefe istek atmaz: matristeki her "gözlenen" sonucu pentester
# kendi testine göre girer.

def _matrix_response(project_id, row):
    doc = authz_matrix.empty()
    if row and row.data:
        try:
            doc = authz_matrix.validate(json.loads(row.data))
        except (ValueError, TypeError):
            doc = authz_matrix.empty()
    doc['summary'] = authz_matrix.summarize(doc)
    doc['updated_at'] = row.updated_at.isoformat() if row and row.updated_at else None
    return jsonify(doc), 200


@app.route('/api/projects/<project_id>/authz-matrix', methods=['GET'])
def get_authz_matrix(project_id):
    try:
        _project_or_404(project_id)
        return _matrix_response(project_id, AuthzMatrix.query.filter_by(project_id=project_id).first())
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/authz-matrix', methods=['PUT'])
def put_authz_matrix(project_id):
    try:
        _project_or_404(project_id)
        data = request.get_json(silent=True)
        try:
            doc = authz_matrix.validate(data)
        except authz_matrix.MatrixValidationError as e:
            return jsonify({'error': str(e)}), 400
        row = AuthzMatrix.query.filter_by(project_id=project_id).first()
        if not row:
            row = AuthzMatrix(project_id=project_id)
            db.session.add(row)
        row.data = json.dumps(doc, ensure_ascii=False)
        row.updated_at = datetime.utcnow()
        db.session.commit()
        return _matrix_response(project_id, row)
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/lifecycle', methods=['GET'])
def get_lifecycle(project_id):
    """Vulnerability Lifecycle özeti: checklist notları + profesyonel
    bulgular (bkz. finding_lifecycle.py) için durum dağılımı
    (open/retesting/fixed/resolved/wont_fix/accepted_risk), aktif risk kalan
    (open+retesting) bulguların severity dağılımı ve giderilme oranı
    (resolved / toplam bulgu)."""
    try:
        _project_or_404(project_id)
        quick = [{'session_id': r.session_id, 'test_id': r.test_id, 'finding': r.finding,
                  'finding_status': r.finding_status, 'severity': r.severity}
                 for sess in Session.query.filter_by(project_id=project_id).all() for r in sess.results]
        pro = [{'session_id': f.session_id, 'test_id': f.test_id, 'status': f.status, 'severity': f.severity}
               for f in Finding.query.filter_by(project_id=project_id).all()]
        summary = finding_lifecycle.summarize(quick, pro)

        events = TimelineEvent.query.filter_by(
            project_id=project_id, event_type='finding_status_changed'
        ).order_by(TimelineEvent.created_at.desc()).limit(50).all()

        summary['recent_transitions'] = [e.to_dict() for e in events]
        return jsonify(summary), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


VALID_REPORT_TYPES = {'technical', 'executive', 'developer'}


@app.route('/api/projects/<project_id>/reports/<report_type>', methods=['GET'])
def generate_project_report(project_id, report_type):
    """Profesyonel DOCX rapor üretir: technical | executive | developer.
    Projedeki TÜM oturumların bulgularını ve test sonuçlarını birleştirir."""
    try:
        project = _project_or_404(project_id)
        if report_type not in VALID_REPORT_TYPES:
            return jsonify({'error': 'Geçersiz rapor türü'}), 400

        sessions = Session.query.filter_by(project_id=project_id).all()
        all_results = []
        for s in sessions:
            all_results.extend(s.results)

        findings = [r.to_dict() for r in all_results if r.finding and r.finding.strip()]
        results_dicts = [r.to_dict() for r in all_results]

        builder = report_builder.REPORT_BUILDERS[report_type]
        buf = builder(project.to_dict(), [s.to_dict() for s in sessions], findings, results_dicts)

        safe_name = ''.join(c if c.isalnum() or c in ' -_' else '_' for c in project.name)[:60]
        filename = f"{safe_name}_{report_type}_report.docx"

        return send_file(
            buf,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


# ========================
# EVIDENCE INTELLIGENCE
# ========================
#
# Guvenlik notlari (bilerek boyle tasarlandi):
# - Diskteki dosya adi HICBIR ZAMAN kullanicinin yukledigi dosya adindan
#   turetilmez -- her zaman sunucu tarafinda uretilen bir UUID kullanilir.
#   Bu, path traversal / dosya adi enjeksiyonunu yapisal olarak engeller.
# - Dosya turu istemcinin gonderdigi Content-Type'tan DEGIL, icerigin ilk
#   baytlarindan belirlenir (image_types.py); yalnizca PNG/JPEG/WEBP/GIF.
#   Sunulurken diskteki icerik yeniden kontrol edilir: bu kontrolden once
#   yuklenmis, gorsel olmayan bir dosya tarayicida acilmaz, indirilir.
# - AI analizi TAMAMEN OPSIYONELDIR (bkz. evidence_intel.py docstring).

def _evidence_dir(project_id):
    path = os.path.join(app.config['UPLOAD_FOLDER'], 'evidence', project_id)
    os.makedirs(path, exist_ok=True)
    return path


@app.route('/api/projects/<project_id>/evidence', methods=['GET'])
def list_evidence(project_id):
    try:
        _project_or_404(project_id)
        items = Evidence.query.filter_by(project_id=project_id).order_by(Evidence.created_at.desc()).all()
        return jsonify([e.to_dict() for e in items]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/evidence', methods=['POST'])
def upload_evidence(project_id):
    try:
        _project_or_404(project_id)

        if 'file' not in request.files:
            return jsonify({'error': 'Dosya bulunamadı (form alanı: file)'}), 400
        file = request.files['file']
        if not file or not file.filename:
            return jsonify({'error': 'Geçersiz dosya'}), 400

        file_bytes = file.read()
        if len(file_bytes) == 0:
            return jsonify({'error': 'Dosya boş'}), 400

        linked_finding_id = None
        raw_fid = (request.form.get('linked_finding_id') or '').strip()
        if raw_fid:
            if not raw_fid.isdigit() or not Finding.query.filter_by(id=int(raw_fid), project_id=project_id).first():
                return jsonify({'error': 'Bağlanacak bulgu bu projede bulunamadı'}), 400
            linked_finding_id = int(raw_fid)

        # Tür, istemcinin söylediğinden değil içerikten belirlenir.
        image_type = image_types.detect_image_type(file_bytes)
        if not image_type:
            return jsonify({'error': 'Dosya içeriği PNG, JPEG, WEBP veya GIF görseli değil.'}), 400
        mime_type = image_types.MIME_BY_TYPE[image_type]

        stored_filename = f"{uuid.uuid4().hex}{image_types.EXT_BY_TYPE[image_type]}"
        dest_path = os.path.join(_evidence_dir(project_id), stored_filename)
        with open(dest_path, 'wb') as f:
            f.write(file_bytes)

        original_name = secure_filename(file.filename) or 'evidence'

        evidence = Evidence(
            project_id=project_id,
            filename=original_name,
            stored_filename=stored_filename,
            mime_type=mime_type,
            size_bytes=len(file_bytes),
            linked_session_id=request.form.get('linked_session_id') or None,
            linked_test_id=request.form.get('linked_test_id') or None,
            linked_finding_id=linked_finding_id,
            review_status='manual' if request.form.get('linked_test_id') or linked_finding_id else 'pending'
        )
        db.session.add(evidence)
        db.session.commit()

        # AI Vision analizi -- SADECE ANTHROPIC_API_KEY ayarlıysa denenir.
        api_key = app.config.get('ANTHROPIC_API_KEY')
        if evidence_intel.is_configured(api_key):
            valid_ids = set(report_builder.WSTG_INDEX.keys())
            analysis, error = evidence_intel.analyze_screenshot(api_key, file_bytes, mime_type, valid_ids)
            if analysis:
                evidence.ai_analysis = analysis['description']
                evidence.ai_suggested_test_ids = json.dumps(analysis['suggested_test_ids'])
                evidence.ai_confidence = analysis['confidence']
            else:
                evidence.ai_error = error
            db.session.commit()

        log_event(project_id, 'evidence_uploaded', f"Kanıt yüklendi: {original_name}")

        return jsonify(evidence.to_dict()), 201
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except HTTPException:
        raise   # ör. 413 (Content-Length olmadan gönderilen büyük gövde)
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/evidence/<int:evidence_id>/file', methods=['GET'])
def get_evidence_file(evidence_id):
    try:
        evidence = Evidence.query.get(evidence_id)
        if not evidence:
            return jsonify({'error': 'Kanıt bulunamadı'}), 404
        if evidence.evidence_type != 'image':
            return jsonify({'error': 'Bu kanıt bir dosya değil (http_transaction)'}), 400
        stored = os.path.basename(evidence.stored_filename or '')
        path = os.path.join(_evidence_dir(evidence.project_id), stored)
        if not stored or not os.path.isfile(path):
            return jsonify({'error': 'Dosya diskte bulunamadı'}), 404
        actual_mime = image_types.sniff_file(path)
        if actual_mime:
            response = send_file(path, mimetype=actual_mime, conditional=True)
        else:
            # İçerik doğrulaması gelmeden önce yüklenmiş, görsel olmayan dosya:
            # tarayıcıda yorumlanmasın, yalnızca indirilsin.
            response = send_file(path, mimetype='application/octet-stream', as_attachment=True,
                                 download_name=secure_filename(evidence.filename or '') or 'evidence.bin')
        response.headers['Content-Security-Policy'] = security.UPLOADED_FILE_CSP
        response.headers['Cache-Control'] = 'private, no-cache'
        return response
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/evidence/http', methods=['POST'])
def create_http_evidence(project_id):
    """HTTP Request/Response Evidence (roadmap: 'HTTP Request/Response Evidence').
    Ham metin HER ZAMAN saklanır, ama redakte edilmiş versiyon da hesaplanıp
    ayrıca saklanır -- varsayılan görüntüleme/export bunu kullanır (bkz.
    backend/redaction.py). Dosya yükleme YOK, salt metin girişi."""
    try:
        _project_or_404(project_id)
        data = request.json or {}
        http_request = data.get('http_request', '').strip()
        http_response = data.get('http_response', '').strip()
        if not http_request and not http_response:
            return jsonify({'error': 'En az bir request veya response girilmelidir'}), 400

        label = data.get('label') or f"HTTP Transaction {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"

        evidence = Evidence(
            project_id=project_id,
            evidence_type='http_transaction',
            filename=label,
            stored_filename='',  # http_transaction tipinde kullanılmaz; eski DB'lerdeki NOT NULL kısıtlamasını (SQLite ALTER TABLE ile kaldırılamıyor) aşmak için placeholder
            http_request=http_request,
            http_response=http_response,
            http_request_redacted=redaction.redact(http_request),
            http_response_redacted=redaction.redact(http_response),
            linked_session_id=data.get('linked_session_id') or None,
            linked_test_id=data.get('linked_test_id') or None,
            linked_finding_id=data.get('linked_finding_id') or None,
            review_status='manual' if data.get('linked_test_id') or data.get('linked_finding_id') else 'pending',
        )
        db.session.add(evidence)
        db.session.commit()

        log_event(project_id, 'evidence_uploaded', f"HTTP kanıtı eklendi: {label}")

        return jsonify(evidence.to_dict()), 201
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/evidence/<int:evidence_id>/raw', methods=['GET'])
def get_evidence_raw(evidence_id):
    """Ham (redakte edilmemiş) HTTP request/response metnini döner. Bu,
    açık bir kullanıcı eylemi gerektirir (varsayılan liste endpoint'i bu
    alanları döndürmez) -- bkz. redaction.py tasarım notu."""
    try:
        evidence = Evidence.query.get(evidence_id)
        if not evidence:
            return jsonify({'error': 'Kanıt bulunamadı'}), 404
        if evidence.evidence_type != 'http_transaction':
            return jsonify({'error': 'Bu kanıt bir HTTP transaction değil'}), 400
        return jsonify(evidence.to_dict(include_raw=True)), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/evidence/<int:evidence_id>', methods=['PUT'])
def update_evidence(evidence_id):
    try:
        evidence = Evidence.query.get(evidence_id)
        if not evidence:
            return jsonify({'error': 'Kanıt bulunamadı'}), 404
        data = request.json or {}

        if 'review_status' in data:
            if data['review_status'] not in {'pending', 'accepted', 'rejected', 'manual'}:
                return jsonify({'error': 'Geçersiz review_status'}), 400
            evidence.review_status = data['review_status']
        if 'linked_session_id' in data:
            evidence.linked_session_id = data['linked_session_id'] or None
        if 'linked_test_id' in data:
            evidence.linked_test_id = data['linked_test_id'] or None
        if 'linked_finding_id' in data:
            evidence.linked_finding_id = data['linked_finding_id'] or None

        db.session.commit()

        if evidence.review_status == 'accepted' and evidence.linked_test_id:
            log_event(evidence.project_id, 'evidence_linked',
                      f"Kanıt {evidence.filename} → {evidence.linked_test_id} ile ilişkilendirildi")
        if evidence.linked_finding_id:
            log_event(evidence.project_id, 'evidence_linked',
                      f"Kanıt {evidence.filename} → FND-{evidence.linked_finding_id:04d} ile ilişkilendirildi")

        return jsonify(evidence.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/evidence/<int:evidence_id>', methods=['DELETE'])
def delete_evidence(evidence_id):
    try:
        evidence = Evidence.query.get(evidence_id)
        if not evidence:
            return jsonify({'error': 'Kanıt bulunamadı'}), 404
        path = os.path.join(_evidence_dir(evidence.project_id), evidence.stored_filename)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
        db.session.delete(evidence)
        db.session.commit()
        return jsonify({'message': 'Kanıt silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


# ========================
# CUSTOM TESTS (kuruluşa özel test maddeleri)
#
# WSTG 5.0 henüz yayınlanmadığı için (bkz. proje geçmişi) resmi bir 5.0
# içeriği eklenemez; bunun yerine roadmap'in "Custom -> Organization-
# specific tests" düğümü burada gerçekleniyor. Bir kuruluşun kendi
# checklist maddelerini eklemesini sağlar; bu maddeler frontend'de resmi
# WSTG kategorileriyle birlikte, ayrı bir "Custom Tests" kategorisi
# altında normal bir test gibi işaretlenebilir/bulgu eklenebilir olur.
# ========================

@app.route('/api/projects/<project_id>/custom-tests', methods=['GET'])
def get_custom_tests(project_id):
    try:
        _project_or_404(project_id)
        items = CustomTest.query.filter_by(project_id=project_id).order_by(CustomTest.created_at.asc()).all()
        return jsonify([i.to_dict() for i in items]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/custom-tests', methods=['POST'])
def add_custom_test(project_id):
    try:
        _project_or_404(project_id)
        data = request.json or {}
        title = (data.get('title') or '').strip()
        if not title:
            return jsonify({'error': 'Başlık zorunludur'}), 400

        item = CustomTest(
            project_id=project_id,
            test_id=f"CUSTOM-{uuid.uuid4().hex[:8]}",
            title=title,
            description=data.get('description', '')
        )
        db.session.add(item)
        db.session.commit()
        log_event(project_id, 'custom_test_added', f"Özel test eklendi: {title}")
        return jsonify(item.to_dict()), 201
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/custom-tests/<test_id>', methods=['DELETE'])
def delete_custom_test(project_id, test_id):
    try:
        # IDOR koruması: kayıt hem test_id hem de bu project_id'ye ait olmalı.
        item = CustomTest.query.filter_by(test_id=test_id, project_id=project_id).first()
        if not item:
            return jsonify({'error': 'Özel test bulunamadı'}), 404
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Özel test silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


# ========================
# TOOL INTEGRATION (nmap / httpx / whatweb / subfinder / dnsx)
#
# Guvenlik notlari (bkz. tool_runner.py docstring'i icin tam detay):
# - Komutlar HER ZAMAN argv listesi olarak calistirilir, shell=True
#   ASLA kullanilmadi -- shell injection yapisal olarak imkansiz.
# - Her aracin komut sablonu SABIT; kullanici keyfi flag veremez.
# - Hedef, recon.py'nin SSRF korumali normalize_target() fonksiyonuyla
#   dogrulanir (private/loopback/link-local IP'ler reddedilir).
# - confirm_authorized olmadan hicbir arac calistirilmaz.
# - nuclei ve ffuf BILINCLI OLARAK burada YOK (bkz. tool_runner.py).
# ========================

@app.route('/api/tools', methods=['GET'])
def list_tools():
    try:
        return jsonify(tool_runner.list_tools()), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/tools/preview', methods=['POST'])
def preview_tool_command():
    """Onay ekraninda gosterilecek TAM komutu doner -- HICBIR SEY calistirmaz."""
    try:
        data = request.json or {}
        preview = tool_runner.preview_command(data.get('tool'), data.get('target', ''))
        return jsonify(preview), 200
    except (tool_runner.ToolError, recon.ReconError) as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/tools/run', methods=['POST'])
def run_project_tool(project_id):
    try:
        _project_or_404(project_id)
        data = request.json or {}

        if not data.get('confirm_authorized'):
            return jsonify({'error': 'Bu hedefi test etmeye yetkili olduğunuzu onaylamalısınız (confirm_authorized).'}), 400

        tool = data.get('tool')
        target = data.get('target', '')

        try:
            result = tool_runner.run_tool(tool, target)
        except tool_runner.ToolError as e:
            return jsonify({'error': str(e)}), 400
        except recon.ReconError as e:
            return jsonify({'error': str(e)}), 400

        run = ToolRun(
            project_id=project_id,
            tool=tool,
            target=result['target'],
            command=result['command'],
            status=result['status'],
            exit_code=result['exit_code'],
            stdout=result['stdout'],
            stderr=result['stderr'],
        )
        db.session.add(run)
        db.session.commit()

        log_event(project_id, 'tool_run',
                  f"{tool} çalıştırıldı: {result['target']} ({result['status']})",
                  {'tool': tool, 'target': result['target'], 'status': result['status']})

        return jsonify(run.to_dict()), 201
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/tools/runs', methods=['GET'])
def list_project_tool_runs(project_id):
    try:
        _project_or_404(project_id)
        runs = ToolRun.query.filter_by(project_id=project_id).order_by(ToolRun.created_at.desc()).limit(50).all()
        return jsonify([r.to_dict() for r in runs]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


# ========================
# CVSS v3.1 CALCULATOR (stateless)
# ========================

@app.route('/api/cvss/calculate', methods=['POST'])
def calculate_cvss():
    try:
        data = request.json or {}
        metrics = {k: data.get(k) for k in ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')}
        result = cvss.compute(metrics)
        return jsonify(result), 200
    except cvss.CvssError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return _error_response(e)


# ========================
# FINDINGS (profesyonel Finding nesneleri — roadmap: 'Findings sistemi + CVSS')
#
# Bilinçli tasarım: TestResult.finding (basit metin) HİÇ değiştirilmedi.
# Finding, üzerine katman olarak eklenen daha zengin bir yapı. IDOR
# koruması: her endpoint hem finding_id hem project_id ile filtreler.
# ========================

VALID_FINDING_STATUS_VALUES = {'open', 'confirmed', 'fixed', 'retest_pending', 'resolved', 'wont_fix', 'accepted_risk'}
VALID_RETEST_RESULTS = {'not_tested', 'fixed', 'not_fixed'}


@app.route('/api/projects/<project_id>/findings', methods=['GET'])
def list_findings(project_id):
    try:
        _project_or_404(project_id)
        items = Finding.query.filter_by(project_id=project_id).order_by(Finding.created_at.desc()).all()
        return jsonify([f.to_dict() for f in items]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings', methods=['POST'])
def create_finding(project_id):
    try:
        _project_or_404(project_id)
        data = request.json or {}
        title = (data.get('title') or '').strip()
        if not title:
            return jsonify({'error': 'Başlık zorunludur'}), 400

        severity = data.get('severity', 'info')
        cvss_score = data.get('cvss_score')
        # CVSS skoru varsa severity'yi ondan türet (tutarlılık için)
        if cvss_score is not None:
            try:
                severity = cvss.severity_label(float(cvss_score))
            except Exception:
                pass

        finding = Finding(
            project_id=project_id,
            session_id=data.get('session_id') or None,
            test_id=data.get('test_id') or None,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=data.get('cvss_vector'),
            cwe=data.get('cwe'),
            owasp_category=data.get('owasp_category'),
            endpoint=data.get('endpoint'),
            parameter=data.get('parameter'),
            description=data.get('description', ''),
            impact=data.get('impact'),
            remediation=data.get('remediation'),
            references=data.get('references'),
            status=data.get('status', 'open') if data.get('status') in VALID_FINDING_STATUS_VALUES else 'open',
            assigned_to=data.get('assigned_to'),
        )
        db.session.add(finding)
        db.session.commit()

        log_event(project_id, 'finding_record_created',
                  f"Finding oluşturuldu: FND-{finding.id:04d} — {title} ({severity})",
                  {'finding_id': finding.id, 'severity': severity})

        return jsonify(finding.to_dict()), 201
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/<int:finding_id>', methods=['GET'])
def get_finding(project_id, finding_id):
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        return jsonify(finding.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/<int:finding_id>', methods=['PUT'])
def update_finding(project_id, finding_id):
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        data = request.json or {}
        old_status = finding.status

        simple_fields = ['test_id', 'session_id', 'cvss_vector', 'cwe', 'owasp_category',
                          'endpoint', 'parameter', 'description', 'impact', 'remediation',
                          'references', 'assigned_to', 'retest_notes']
        for field in simple_fields:
            if field in data:
                setattr(finding, field, data[field])

        if 'title' in data:
            title = (data['title'] or '').strip()
            if not title:
                return jsonify({'error': 'Başlık boş olamaz'}), 400
            finding.title = title

        if 'cvss_score' in data:
            finding.cvss_score = data['cvss_score']
            if data['cvss_score'] is not None:
                try:
                    finding.severity = cvss.severity_label(float(data['cvss_score']))
                except Exception:
                    pass
        if 'severity' in data and data.get('cvss_score') is None:
            finding.severity = data['severity']

        if 'status' in data:
            if data['status'] not in VALID_FINDING_STATUS_VALUES:
                return jsonify({'error': 'Geçersiz status değeri'}), 400
            finding.status = data['status']

        if 'retest_result' in data:
            if data['retest_result'] not in VALID_RETEST_RESULTS:
                return jsonify({'error': 'Geçersiz retest_result değeri'}), 400
            finding.retest_result = data['retest_result']
            finding.retested_at = datetime.utcnow()

        finding.updated_at = datetime.utcnow()
        db.session.commit()

        if finding.status != old_status:
            log_event(project_id, 'finding_status_changed',
                      f"FND-{finding.id:04d}: {old_status} → {finding.status}",
                      {'finding_id': finding.id, 'from': old_status, 'to': finding.status})

        return jsonify(finding.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/<int:finding_id>/retest', methods=['POST'])
def retest_finding(project_id, finding_id):
    """Yeniden test sonucunu kaydeder (bkz. retest.py): fixed -> resolved,
    not_fixed -> open. Tarih sunucuda atanır; zaman çizelgesine yazılır."""
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Bulgu bulunamadı'}), 404
        data = request.get_json(silent=True) or {}
        try:
            fields = retest_lib.transition(data.get('result'), data.get('notes'))
        except retest_lib.RetestError as e:
            return jsonify({'error': str(e)}), 400
        old_status = finding.status
        for k, v in fields.items():
            setattr(finding, k, v)
        finding.retested_at = datetime.utcnow()
        finding.updated_at = finding.retested_at
        db.session.commit()
        label = 'düzeldi' if fields['retest_result'] == 'fixed' else 'hâlâ açık'
        log_event(project_id, 'finding_retested', f"FND-{finding.id:04d} yeniden test: {label}",
                  {'finding_id': finding.id, 'result': fields['retest_result'], 'from': old_status, 'to': finding.status})
        return jsonify(finding.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/retest', methods=['GET'])
def retest_overview(project_id):
    """Yeniden test ekranı: kapsamdaki bulgular durumlarıyla + özet."""
    try:
        _project_or_404(project_id)
        evidence_by_finding = {}
        for ev in Evidence.query.filter(Evidence.project_id == project_id, Evidence.linked_finding_id.isnot(None)).all():
            evidence_by_finding.setdefault(ev.linked_finding_id, []).append({
                'id': ev.id, 'evidence_type': ev.evidence_type or 'image', 'filename': ev.filename,
                'created_at': ev.created_at.isoformat() if ev.created_at else None})
        items = []
        for f in Finding.query.filter_by(project_id=project_id).order_by(Finding.id.asc()).all():
            d = f.to_dict()
            d['retest_state'] = retest_lib.classify(d)
            d['evidence'] = evidence_by_finding.get(f.id, [])
            items.append(d)
        return jsonify({'findings': items, 'summary': retest_lib.summarize(items)}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/<int:finding_id>', methods=['DELETE'])
def delete_finding(project_id, finding_id):
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        db.session.delete(finding)
        db.session.commit()
        return jsonify({'message': 'Finding silindi'}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


# ========================
# DUPLICATE FINDING DETECTION
# ========================

@app.route('/api/projects/<project_id>/findings/check-duplicates', methods=['POST'])
def check_duplicate_findings(project_id):
    """Taslak bir bulguyu (henuz kaydedilmemis veya duzenlenmekte olan) projedeki
    mevcut bulgularla karsilastirir. Salt hesaplama duplicate_detector.py'de --
    burada sadece DB sorgusu ve JSON sozlesmesi var."""
    try:
        _project_or_404(project_id)
        data = request.json or {}
        draft = {
            'title': data.get('title'),
            'description': data.get('description'),
            'endpoint': data.get('endpoint'),
            'cwe': data.get('cwe'),
            'test_id': data.get('test_id'),
        }
        exclude_id = data.get('exclude_id')
        exclude_id = int(exclude_id) if exclude_id not in (None, '') else None

        candidates = [f.to_dict() for f in Finding.query.filter_by(project_id=project_id).all()]
        matches = duplicate_detector.find_similar_findings(candidates, draft, exclude_id=exclude_id)
        return jsonify({'matches': matches}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/merge', methods=['POST'])
def merge_findings(project_id):
    """Birden fazla bulguyu tek bir 'primary' bulguda birlestirir:
    - endpoint/parameter birlestirilir (virgulle ayrilmis, tekillestirilmis)
    - description/impact/remediation icin EN UZUN (en kapsamli) metin korunur
    - merge edilen bulgulara bagli Evidence kayitlari primary'ye yeniden baglanir
    - merge edilen bulgular silinir, ID'leri primary.merged_finding_ids'e yazilir"""
    try:
        _project_or_404(project_id)
        data = request.json or {}
        primary_id = data.get('primary_id')
        merge_ids = data.get('merge_ids') or []
        if not primary_id or not merge_ids:
            return jsonify({'error': 'primary_id ve merge_ids zorunludur'}), 400

        primary = Finding.query.filter_by(id=primary_id, project_id=project_id).first()
        if not primary:
            return jsonify({'error': 'Primary finding bulunamadı'}), 404

        merge_ids = [int(i) for i in merge_ids if int(i) != int(primary_id)]
        to_merge = Finding.query.filter(
            Finding.id.in_(merge_ids), Finding.project_id == project_id
        ).all()
        if not to_merge:
            return jsonify({'error': 'Birleştirilecek geçerli bulgu bulunamadı'}), 400

        def _union_csv(a, b):
            items = [x.strip() for x in (a or '').split(',') if x.strip()]
            for x in (b or '').split(','):
                x = x.strip()
                if x and x not in items:
                    items.append(x)
            return ', '.join(items)

        def _longest(a, b):
            a, b = (a or ''), (b or '')
            return a if len(a) >= len(b) else b

        merged_ids_seen = []
        try:
            merged_ids_seen = json.loads(primary.merged_finding_ids) if primary.merged_finding_ids else []
        except Exception:
            merged_ids_seen = []

        for other in to_merge:
            primary.endpoint = _union_csv(primary.endpoint, other.endpoint)
            primary.parameter = _union_csv(primary.parameter, other.parameter)
            primary.description = _longest(primary.description, other.description)
            primary.impact = _longest(primary.impact, other.impact)
            primary.remediation = _longest(primary.remediation, other.remediation)
            primary.references = _union_csv(primary.references, other.references)

            Evidence.query.filter_by(linked_finding_id=other.id).update({'linked_finding_id': primary.id})
            merged_ids_seen.append(other.id)
            db.session.delete(other)

        primary.merged_finding_ids = json.dumps(merged_ids_seen)
        primary.updated_at = datetime.utcnow()
        db.session.commit()

        log_event(project_id, 'findings_merged',
                  f"FND-{primary.id:04d} içine {len(to_merge)} bulgu birleştirildi",
                  {'primary_id': primary.id, 'merged_ids': [o.id for o in to_merge]})

        return jsonify(primary.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


# ========================
# AI REPORT ASSISTANT
# ========================
#
# Tasarim ilkesi (mevcut finding_analysis.py / evidence_intel.py ile ayni):
# saglayici yapilandirilmamissa (.env'de ilgili API key yoksa) ozellik
# SESSIZCE degil ama ACIKCA basarisiz olur -- 503 + net bir hata mesaji
# doner, ASLA sahte/uydurma icerik uretilmez. Uretilen metin DOGRUDAN
# hicbir alana yazilmaz; frontend kullaniciya gosterir, kullanici isterse
# mevcut PUT /findings/<id> ile kaydeder.

def _ai_overrides_from_request():
    """BYOK (Bring Your Own Key): kullanıcı tarayıcıdan kendi API key'ini
    girip 'bu oturum için kendi key'imle kullan' seçtiğinde, frontend bu
    değerleri isteğe header olarak ekler:

        X-AI-Provider: gemini | openai | anthropic | ollama
        X-AI-Api-Key:  <kullanıcının kendi key'i>
        X-AI-Model:    <opsiyonel, model adı>
        X-AI-Base-Url: <opsiyonel, sadece ollama için>

    Bu değerler HİÇBİR ZAMAN sunucuda saklanmaz/loglanmaz; sadece o anki
    istek için ai/factory.get_ai_provider()'a iletilir ve orada, kayıtlı
    hiçbir ayarı değiştirmeden, geçici bir sağlayıcı kurmak için kullanılır.
    Header yoksa (veya boşsa) davranış tamamen eskisi gibi kalır -- paylaşılan
    kurulum (DB ayarı / .env) devreye girer."""
    provider = request.headers.get('X-AI-Provider')
    if not provider:
        return None
    return {
        'provider': provider,
        'api_key': request.headers.get('X-AI-Api-Key'),
        'model': request.headers.get('X-AI-Model'),
        'base_url': request.headers.get('X-AI-Base-Url'),
    }


def _handle_ai_error(e):
    if isinstance(e, AIConfigError):
        return jsonify({'error': str(e), 'ai_configured': False}), 503
    if isinstance(e, AIRequestError):
        return jsonify({'error': str(e)}), 502
    return _error_response(e)


def _log_ai_interaction(purpose, ai_result=None, error=None, project_id=None, finding_id=None, session_id=None):
    try:
        log = AIInteractionLog(
            project_id=project_id,
            finding_id=finding_id,
            session_id=session_id,
            purpose=purpose,
            provider=getattr(ai_result, 'provider', None),
            model=getattr(ai_result, 'model', None),
            success=error is None,
            error_message=str(error) if error else None,
            latency_ms=getattr(ai_result, 'latency_ms', None) if ai_result else getattr(error, 'latency_ms', None),
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


@app.route('/api/projects/<project_id>/findings/<int:finding_id>/ai/description', methods=['POST'])
def ai_generate_description(project_id, finding_id):
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        lang = (request.json or {}).get('lang', 'tr')
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        try:
            text, ai_result = ai_report_assistant.generate_description(provider, finding.to_dict(), lang)
        except (AIConfigError, AIRequestError) as e:
            _log_ai_interaction('finding_description', error=e, project_id=project_id, finding_id=finding_id)
            raise
        _log_ai_interaction('finding_description', ai_result=ai_result, project_id=project_id, finding_id=finding_id)
        return jsonify({'description': text, 'provider': ai_result.provider}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except (AIConfigError, AIRequestError) as e:
        return _handle_ai_error(e)
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/<int:finding_id>/ai/remediation', methods=['POST'])
def ai_generate_remediation(project_id, finding_id):
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        lang = (request.json or {}).get('lang', 'tr')
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        try:
            text, ai_result = ai_report_assistant.generate_remediation(provider, finding.to_dict(), lang)
        except (AIConfigError, AIRequestError) as e:
            _log_ai_interaction('finding_remediation', error=e, project_id=project_id, finding_id=finding_id)
            raise
        _log_ai_interaction('finding_remediation', ai_result=ai_result, project_id=project_id, finding_id=finding_id)
        return jsonify({'remediation': text, 'provider': ai_result.provider}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except (AIConfigError, AIRequestError) as e:
        return _handle_ai_error(e)
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/findings/<int:finding_id>/ai/analyze', methods=['POST'])
def ai_analyze_finding(project_id, finding_id):
    """Mevcut (daha once app.py'den kopmus) finding_analysis.py'yi Finding modeline
    baglar: CWE/severity/CVSS/false-positive onerisi. Kaynak: 1261b55 'AI entagration'."""
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        lang = (request.json or {}).get('lang', 'tr')
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        content = finding.description or finding.impact or ''
        try:
            analysis, ai_result = finding_analysis.analyze_finding(
                provider, finding.title, content, test_id=finding.test_id, lang=lang
            )
        except (AIConfigError, AIRequestError) as e:
            _log_ai_interaction('finding_analysis', error=e, project_id=project_id, finding_id=finding_id)
            raise
        except finding_analysis.FindingAnalysisError as e:
            return jsonify({'error': str(e)}), 502
        _log_ai_interaction('finding_analysis', ai_result=ai_result, project_id=project_id, finding_id=finding_id)
        analysis['provider'] = ai_result.provider
        return jsonify(analysis), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except (AIConfigError, AIRequestError) as e:
        return _handle_ai_error(e)
    except Exception as e:
        return _error_response(e)


@app.route('/api/ai/rewrite', methods=['POST'])
def ai_rewrite_text():
    try:
        data = request.json or {}
        text = data.get('text', '')
        lang = data.get('lang', 'tr')
        if not text.strip():
            return jsonify({'error': 'text zorunludur'}), 400
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        try:
            rewritten, ai_result = ai_report_assistant.rewrite_professional(provider, text, lang)
        except (AIConfigError, AIRequestError) as e:
            _log_ai_interaction('rewrite_professional', error=e)
            raise
        _log_ai_interaction('rewrite_professional', ai_result=ai_result)
        return jsonify({'text': rewritten, 'provider': ai_result.provider}), 200
    except (AIConfigError, AIRequestError) as e:
        return _handle_ai_error(e)
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/ai/executive-summary', methods=['POST'])
def ai_project_executive_summary(project_id):
    try:
        project = _project_or_404(project_id)
        lang = (request.json or {}).get('lang', 'tr')
        findings = [f.to_dict() for f in Finding.query.filter_by(project_id=project_id).all()]
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        try:
            summary, ai_result = ai_report_assistant.generate_project_executive_summary(
                provider, project.to_dict(), findings, lang
            )
        except (AIConfigError, AIRequestError) as e:
            _log_ai_interaction('executive_summary', error=e, project_id=project_id)
            raise
        _log_ai_interaction('executive_summary', ai_result=ai_result, project_id=project_id)
        return jsonify({'summary': summary, 'provider': ai_result.provider}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except (AIConfigError, AIRequestError) as e:
        return _handle_ai_error(e)
    except Exception as e:
        return _error_response(e)


# ========================
# HTML PROFESSIONAL REPORT
# ========================

@app.route('/api/projects/<project_id>/reports/pdf', methods=['GET', 'POST'])
def generate_pdf_report(project_id):
    """generate_html_report ile birebir ayni secenekler/govde (title,
    client_name, pentester_name, date_range, include, template,
    confidential, executive_summary, lang) -- tek fark, tarayici print
    diyalogu yerine dogrudan indirilebilir bir .pdf dosyasi donmesi."""
    try:
        project = _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        all_results = []
        for s in sessions:
            all_results.extend([r.to_dict() for r in s.results])

        findings = [f.to_dict() for f in Finding.query.filter_by(project_id=project_id).all()]

        if request.method == 'POST':
            body = request.json or {}
        else:
            body = {}
        args = request.args
        include = body.get('include') or args.get('include') or 'all'
        if include not in ('all', 'critical_high'):
            try:
                include = [int(x) for x in include.split(',')] if isinstance(include, str) else include
            except Exception:
                include = 'all'

        options = {
            'title': body.get('title') or args.get('title'),
            'client_name': body.get('client_name') or args.get('client_name'),
            'pentester_name': body.get('pentester_name') or args.get('pentester_name'),
            'date_range': body.get('date_range') or args.get('date_range'),
            'logo_data_uri': body.get('logo_data_uri'),
            'include': include,
            'template': body.get('template') or args.get('template') or 'standard',
            'confidential': str(body.get('confidential') or args.get('confidential') or '').lower() in ('1', 'true', 'yes'),
        }
        lang = body.get('lang') or args.get('lang') or 'tr'
        executive_summary = body.get('executive_summary')

        pdf_buf = report_pdf.build_pdf_report(
            project.to_dict(), findings, all_results, options=options,
            executive_summary=executive_summary, lang=lang
        )

        safe_name = ''.join(c if c.isalnum() or c in ' -_' else '_' for c in project.name)[:60]
        filename = f"{safe_name}_report.pdf"
        return send_file(pdf_buf, as_attachment=True, download_name=filename, mimetype='application/pdf')
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except report_pdf.PdfReportError as e:
        return _error_response(e, 'PDF oluşturulamadı.')
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/reports/retest/<fmt>', methods=['GET', 'POST'])
def generate_retest_report(project_id, fmt):
    """Yeniden Test Raporu (bkz. report_retest.py). fmt: html | pdf."""
    try:
        if fmt not in ('html', 'pdf'):
            return jsonify({'error': 'Biçim html ya da pdf olmalı'}), 404
        project = _project_or_404(project_id)
        body = (request.get_json(silent=True) or {}) if request.method == 'POST' else {}
        args = request.args
        pick = lambda k: body.get(k) if body.get(k) not in (None, '') else args.get(k)
        truthy = lambda v, default: default if v is None else str(v).lower() in ('1', 'true', 'yes', 'on')
        options = {
            'title': pick('title'), 'client_name': pick('client_name'), 'pentester_name': pick('pentester_name'),
            'retest_date': pick('retest_date'), 'template': pick('template') or 'standard',
            'confidential': truthy(pick('confidential'), False),
            'include_pending': truthy(pick('include_pending'), True),
        }
        lang = 'en' if pick('lang') == 'en' else 'tr'
        findings = [f.to_dict() for f in Finding.query.filter_by(project_id=project_id).all()]
        if fmt == 'html':
            return report_retest.build_html(project.to_dict(), findings, options, lang), 200, {'Content-Type': 'text/html; charset=utf-8'}
        pdf_buf = report_retest.build_pdf(project.to_dict(), findings, options, lang)
        safe_name = ''.join(c if c.isalnum() or c in ' -_' else '_' for c in project.name)[:60]
        return send_file(pdf_buf, as_attachment=True, download_name=f"{safe_name}_retest.pdf", mimetype='application/pdf')
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except report_pdf.PdfReportError as e:
        return _error_response(e, 'PDF oluşturulamadı.')
    except Exception as e:
        return _error_response(e)


@app.route('/api/projects/<project_id>/reports/html', methods=['GET', 'POST'])
def generate_html_report(project_id):
    """GET: query string ile basit secenekler (link olarak yeni sekmede acilabilsin diye).
    POST: logo_data_uri gibi buyuk/karmasik secenekler icin JSON body (opsiyonel)."""
    try:
        project = _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        all_results = []
        for s in sessions:
            all_results.extend([r.to_dict() for r in s.results])

        findings = [f.to_dict() for f in Finding.query.filter_by(project_id=project_id).all()]

        if request.method == 'POST':
            body = request.json or {}
        else:
            body = {}
        args = request.args
        include = body.get('include') or args.get('include') or 'all'
        if include not in ('all', 'critical_high'):
            try:
                include = [int(x) for x in include.split(',')] if isinstance(include, str) else include
            except Exception:
                include = 'all'

        options = {
            'title': body.get('title') or args.get('title'),
            'client_name': body.get('client_name') or args.get('client_name'),
            'pentester_name': body.get('pentester_name') or args.get('pentester_name'),
            'date_range': body.get('date_range') or args.get('date_range'),
            'logo_data_uri': body.get('logo_data_uri'),
            'include': include,
            'template': body.get('template') or args.get('template') or 'standard',
            'confidential': str(body.get('confidential') or args.get('confidential') or '').lower() in ('1', 'true', 'yes'),
        }
        lang = body.get('lang') or args.get('lang') or 'tr'
        executive_summary = body.get('executive_summary')

        html_doc = report_html.build_html_report(
            project.to_dict(), findings, all_results, options=options,
            executive_summary=executive_summary, lang=lang
        )
        return html_doc, 200, {'Content-Type': 'text/html; charset=utf-8'}
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


# ========================
# PENTEST KANBAN
# ========================
#
# Tasarim karari: ayri bir 'kanban_cards' tablosu YOK. Kanban, mevcut
# TestResult uzerine bir GORUNUM katmani -- bir testin durumu icin TEK
# dogru kaynak hep TestResult kalir (kanban_status alani onun uzerine
# eklendi). findings_count/evidence_count her istekte hesaplanir, DB'de
# saklanmaz (bayatlama riski olmasin diye).

VALID_KANBAN_STATUSES = {'todo', 'testing', 'review', 'confirmed', 'done'}


def _kanban_card_dict(result, test_index):
    d = result.to_dict()
    meta = test_index.get(result.test_id, {})
    d['test_title'] = meta.get('title', '')
    d['findings_count'] = Finding.query.filter_by(session_id=result.session_id, test_id=result.test_id).count()
    d['evidence_count'] = Evidence.query.filter_by(
        linked_session_id=result.session_id, linked_test_id=result.test_id
    ).count()
    return d


@app.route('/api/projects/<project_id>/kanban/board', methods=['GET'])
def get_kanban_board(project_id):
    try:
        _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        session_ids = [s.id for s in sessions]
        results = TestResult.query.filter(TestResult.session_id.in_(session_ids)).all() if session_ids else []

        test_index = dict(report_builder.WSTG_INDEX)

        board = {status: [] for status in VALID_KANBAN_STATUSES}
        for r in results:
            board.setdefault(r.kanban_status or 'todo', []).append(_kanban_card_dict(r, test_index))

        return jsonify({'columns': board}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


@app.route('/api/kanban/card/<int:test_result_id>/move', methods=['PUT'])
def move_kanban_card(test_result_id):
    try:
        result = TestResult.query.get(test_result_id)
        if not result:
            return jsonify({'error': 'Test sonucu bulunamadı'}), 404
        data = request.json or {}
        new_status = data.get('kanban_status')
        if new_status not in VALID_KANBAN_STATUSES:
            return jsonify({'error': 'Geçersiz kanban_status değeri'}), 400

        old_status = result.kanban_status or 'todo'
        result.kanban_status = new_status
        result.updated_at = datetime.utcnow()
        db.session.commit()

        session = Session.query.get(result.session_id)
        if session and session.project_id and old_status != new_status:
            log_event(session.project_id, 'kanban_card_moved',
                      f"{result.test_id}: {old_status} → {new_status}",
                      {'test_result_id': result.id, 'from': old_status, 'to': new_status})

        return jsonify(result.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/kanban/card/<int:test_result_id>', methods=['PUT'])
def update_kanban_card(test_result_id):
    try:
        result = TestResult.query.get(test_result_id)
        if not result:
            return jsonify({'error': 'Test sonucu bulunamadı'}), 404
        data = request.json or {}
        if 'assigned_to' in data:
            result.assigned_to = data['assigned_to']
        if 'time_spent_minutes' in data:
            try:
                result.time_spent_minutes = max(0, int(data['time_spent_minutes']))
            except (TypeError, ValueError):
                return jsonify({'error': 'time_spent_minutes bir tam sayı olmalı'}), 400
        if 'kanban_status' in data:
            if data['kanban_status'] not in VALID_KANBAN_STATUSES:
                return jsonify({'error': 'Geçersiz kanban_status değeri'}), 400
            result.kanban_status = data['kanban_status']
        result.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify(result.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/projects/<project_id>/kanban/stats', methods=['GET'])
def get_kanban_stats(project_id):
    try:
        _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        session_ids = [s.id for s in sessions]
        results = TestResult.query.filter(TestResult.session_id.in_(session_ids)).all() if session_ids else []

        status_counts = {status: 0 for status in VALID_KANBAN_STATUSES}
        assignee_counts = {}
        for r in results:
            status_counts[r.kanban_status or 'todo'] = status_counts.get(r.kanban_status or 'todo', 0) + 1
            if r.assigned_to:
                assignee_counts[r.assigned_to] = assignee_counts.get(r.assigned_to, 0) + 1

        return jsonify({'status_counts': status_counts, 'assignee_counts': assignee_counts, 'total': len(results)}), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _error_response(e)


# ========================
# AI AYARLARI (API key yönetimi — .env yerine uygulama arayüzünden)
# ========================
#
# Tasarim ilkesi: key'ler DB'de SADECE sifreli (crypto_utils/Fernet) saklanir
# ve hicbir response/log ASLA ham key icermez -- sadece crypto_utils.mask_key
# ile maskelenmis hali (orn. 'AIza...ab12'). ai/factory.py bu tablodaki aktif
# kaydi .env/app.config'ten ONCE kontrol eder; kayit yoksa mevcut .env
# davranisina sessizce doner (geriye donuk uyumluluk).

VALID_AI_PROVIDERS = {'gemini', 'openai', 'anthropic', 'ollama'}


def _masked_setting_dict(setting):
    api_key = crypto_utils.decrypt(app.config, setting.api_key_encrypted) if setting.api_key_encrypted else ''
    return setting.to_dict(masked_key=crypto_utils.mask_key(api_key))


@app.route('/api/ai/settings', methods=['GET'])
def list_ai_settings():
    try:
        settings = AIProviderSetting.query.order_by(AIProviderSetting.provider).all()
        return jsonify([_masked_setting_dict(s) for s in settings]), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/ai/settings', methods=['POST'])
def upsert_ai_setting():
    try:
        data = request.json or {}
        provider = (data.get('provider') or '').strip().lower()
        if provider not in VALID_AI_PROVIDERS:
            return jsonify({'error': f"Geçersiz provider. Geçerli seçenekler: {', '.join(sorted(VALID_AI_PROVIDERS))}"}), 400

        setting = AIProviderSetting.query.filter_by(provider=provider).first()
        if not setting:
            setting = AIProviderSetting(provider=provider)
            db.session.add(setting)

        api_key = data.get('api_key')
        if api_key:  # boş/None ise mevcut key korunur (örn. sadece model değiştirmek için)
            setting.api_key_encrypted = crypto_utils.encrypt(app.config, api_key.strip())
        if 'model' in data:
            setting.model = (data.get('model') or '').strip() or None
        if 'base_url' in data:
            setting.base_url = (data.get('base_url') or '').strip() or None
        setting.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify(_masked_setting_dict(setting)), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/ai/settings/<provider>', methods=['DELETE'])
def delete_ai_setting(provider):
    try:
        setting = AIProviderSetting.query.filter_by(provider=provider.lower()).first()
        if not setting:
            return jsonify({'error': 'Kayıtlı ayar bulunamadı'}), 404
        db.session.delete(setting)
        db.session.commit()
        return jsonify({'message': 'Silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


@app.route('/api/ai/settings/activate', methods=['POST'])
def activate_ai_setting():
    try:
        data = request.json or {}
        provider = (data.get('provider') or '').strip().lower()
        setting = AIProviderSetting.query.filter_by(provider=provider).first()
        if not setting:
            return jsonify({'error': 'Bu sağlayıcı için önce ayar kaydedin'}), 404
        AIProviderSetting.query.update({'is_active': False})
        setting.is_active = True
        db.session.commit()
        return jsonify(_masked_setting_dict(setting)), 200
    except Exception as e:
        db.session.rollback()
        return _error_response(e)


def _classify_ai_error(message):
    m = re.search(r'\((\d{3})\)', message or '')
    if not m:
        return 'network_error' if message else 'unknown'
    code = int(m.group(1))
    if code in (401, 403):
        return 'auth_error'
    if code == 429:
        return 'rate_limited'
    if code >= 500:
        return 'server_error'
    return 'request_failed'


def _ping_provider(provider):
    """Küçük bir test isteği atar; sonucu (ok, provider, model, latency_ms,
    error, error_type) olarak döner. Ham API key ASLA döndürülmez."""
    try:
        ai_result = provider.chat(system_prompt="", user_prompt="ping — sadece 'ok' yanıtla", max_tokens=20)
        return {'ok': True, 'provider': ai_result.provider, 'model': ai_result.model, 'latency_ms': ai_result.latency_ms}
    except AIConfigError as e:
        return {'ok': False, 'provider': getattr(provider, 'name', None), 'error': str(e), 'error_type': 'not_configured'}
    except AIRequestError as e:
        return {
            'ok': False, 'provider': getattr(provider, 'name', None), 'error': str(e),
            'error_type': _classify_ai_error(str(e)), 'latency_ms': e.latency_ms,
        }
    except Exception as e:
        error_id = _log_unexpected(e)
        return {'ok': False, 'provider': getattr(provider, 'name', None), 'error_type': 'unknown',
                'error': f'Beklenmeyen hata (hata kimliği: {error_id}; ayrıntı backend terminalinde).'}


@app.route('/api/ai/settings/test', methods=['POST'])
def test_ai_setting():
    try:
        data = request.json or {}
        provider = (data.get('provider') or '').strip().lower()
        if provider not in VALID_AI_PROVIDERS:
            return jsonify({'error': 'Geçersiz provider'}), 400

        timeout = app.config.get('AI_REQUEST_TIMEOUT', 30)
        if data.get('api_key') or data.get('base_url'):
            # Kaydedilmemiş bir aday key/model'i doğrudan test et (UI'nin
            # "kaydetmeden önce test et" akışı) -- DB'ye hiçbir şey yazılmaz.
            test_provider = _build_provider(
                provider, data.get('api_key', ''), data.get('model') or DEFAULT_MODELS.get(provider),
                data.get('base_url'), timeout
            )
        else:
            setting = AIProviderSetting.query.filter_by(provider=provider).first()
            if not setting:
                return jsonify({'error': 'Bu sağlayıcı için kayıtlı ayar yok'}), 404
            api_key = crypto_utils.decrypt(app.config, setting.api_key_encrypted) if setting.api_key_encrypted else ''
            test_provider = _build_provider(provider, api_key, setting.model, setting.base_url, timeout)

        result = _ping_provider(test_provider)
        return jsonify(result), 200 if result['ok'] else 503
    except Exception as e:
        return _error_response(e)


@app.route('/api/ai/status', methods=['GET'])
def ai_status():
    """Ana ekrandaki 'hangi sağlayıcı aktif' rozeti için -- /api/ai/ping'in
    aksine GERÇEK bir ağ isteği ATMAZ (sadece is_configured() kontrolü),
    böylece her sayfa yüklemesinde gereksiz API kotası tüketilmez."""
    try:
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        return jsonify({
            'provider': getattr(provider, 'name', None),
            'model': getattr(provider, 'model', None),
            'configured': provider.is_configured(),
        }), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/ai/ping', methods=['GET', 'POST'])
def ai_ping():
    try:
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        result = _ping_provider(provider)
        return jsonify(result), 200 if result['ok'] else 503
    except Exception as e:
        return _error_response(e)


@app.route('/api/ai/logs', methods=['GET'])
def get_ai_logs():
    try:
        query = AIInteractionLog.query
        if request.args.get('session_id'):
            query = query.filter_by(session_id=request.args.get('session_id'))
        if request.args.get('project_id'):
            query = query.filter_by(project_id=request.args.get('project_id'))
        if request.args.get('purpose'):
            query = query.filter_by(purpose=request.args.get('purpose'))
        logs = query.order_by(AIInteractionLog.created_at.desc()).limit(200).all()
        return jsonify([l.to_dict() for l in logs]), 200
    except Exception as e:
        return _error_response(e)


# ========================
# RESTORED AI ROUTES (Bölüm A.1)
# ========================
#
# NOT: /api/ai/analyze-finding ve /api/ai/suggest-next-test, projedeki daha
# yeni AI rotalarından (ai/description, ai/remediation, .../ai/analyze —
# 503 dönen) FARKLI bir kontrat kullanır: yapılandırılmamış sağlayıcı için
# 200 + {'error':...} döner. Bu, bu rotaların orijinal ('AI entagration'
# commit'i) davranışıdır ve mevcut test dosyaları (test_ai_analyze_route.py,
# test_next_test_route.py) bunu bekler -- bilinçli olarak korunmuştur,
# yanlışlıkla tutarsızlık değildir.

@app.route('/api/ai/analyze-finding', methods=['POST'])
def ai_analyze_finding_generic():
    data = request.json or {}
    content = data.get('content', '')
    if not (content or '').strip():
        return jsonify({'error': 'content zorunludur'}), 400

    title = data.get('title', '')
    test_id = data.get('test_id')
    session_id = data.get('session_id')
    lang = data.get('lang', 'tr')

    try:
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        analysis, ai_result = finding_analysis.analyze_finding(provider, title, content, test_id=test_id, lang=lang)
    except AIConfigError as e:
        return jsonify({'error': str(e)}), 200
    except AIRequestError as e:
        _log_ai_interaction('finding_analysis', error=e, session_id=session_id)
        return jsonify({'error': str(e)}), 502
    except finding_analysis.FindingAnalysisError as e:
        _log_ai_interaction('finding_analysis', error=e, session_id=session_id)
        return jsonify({'error': str(e)}), 502
    except Exception as e:
        return _error_response(e)

    _log_ai_interaction('finding_analysis', ai_result=ai_result, session_id=session_id)
    analysis['provider'] = ai_result.provider
    return jsonify(analysis), 200


@app.route('/api/ai/suggest-next-test', methods=['POST'])
def ai_suggest_next_test():
    data = request.json or {}
    session_id = data.get('session_id')
    lang = data.get('lang', 'tr')
    completed_test_ids = data.get('completed_test_ids')
    findings = data.get('findings')

    # session_id verilip completed_test_ids/findings verilmediyse, mevcut
    # oturum durumundan otomatik türet -- caller'ın bunları elle toplayıp
    # göndermesi gerekmez (eski rotanın istediği ama pratikte can sıkıcı olan şey).
    if session_id and completed_test_ids is None:
        session = Session.query.get(session_id)
        if session:
            completed_test_ids = [r.test_id for r in session.results if r.status != 'pending']
    if session_id and findings is None:
        findings = [
            {'title': f.title, 'severity': f.severity, 'cwe_id': f.cwe, 'test_id': f.test_id}
            for f in Finding.query.filter_by(session_id=session_id).all()
        ]

    completed_test_ids = completed_test_ids or []
    findings = findings or []

    try:
        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        suggestion, ai_result = next_test_suggestion.suggest_next_test(provider, completed_test_ids, findings, lang=lang)
    except AIConfigError as e:
        return jsonify({'error': str(e)}), 200
    except AIRequestError as e:
        _log_ai_interaction('next_test_suggestion', error=e, session_id=session_id)
        return jsonify({'error': str(e)}), 502
    except next_test_suggestion.NextTestSuggestionError as e:
        _log_ai_interaction('next_test_suggestion', error=e, session_id=session_id)
        return jsonify({'error': str(e)}), 502
    except Exception as e:
        return _error_response(e)

    if ai_result is not None:
        _log_ai_interaction('next_test_suggestion', ai_result=ai_result, session_id=session_id)
        suggestion['provider'] = ai_result.provider
    else:
        suggestion['provider'] = None  # all_done=True kısayolu -- AI hiç çağrılmadı
    return jsonify(suggestion), 200


# ========================
# SESSION RAPORU (Bölüm A.1 — report_generator.py'nin restore edilmesi)
# ========================
#
# report_generator.py eski bir 'Note' şemasına göre yazılmıştı (content,
# cwe_id/cwe_name). O model artık yok; onun yerine bu route'lar mevcut
# Finding kayıtlarını (session_id ile ilişkili olanlar) report_generator'ın
# beklediği sözlük şekline çeviriyor. report_generator.py'nin kendisi
# DEĞİŞTİRİLMEDİ -- sadece bu adaptör.

VALID_REPORT_DOWNLOAD_FORMATS = {'md', 'docx'}


def _session_findings_for_report(session_id):
    findings = Finding.query.filter_by(session_id=session_id).all()
    return [
        {
            'id': f.id,
            'title': f.title,
            'content': f.description or '',
            'severity': f.severity,
            'test_id': f.test_id,
            'cwe_id': f.cwe,
            'cwe_name': None,
            'cvss_score': f.cvss_score,
            'cvss_vector': f.cvss_vector,
        }
        for f in findings
    ]


@app.route('/api/sessions/<session_id>/report/data', methods=['GET'])
def get_session_report_data(session_id):
    try:
        session = Session.query.get(session_id)
        if not session:
            return jsonify({'error': 'Oturum bulunamadı'}), 404
        lang = request.args.get('lang', 'tr')
        results = [r.to_dict() for r in session.results]
        notes = _session_findings_for_report(session_id)
        report_data = report_generator.build_report_data(session.to_dict(), results, notes, lang=lang)
        return jsonify(report_data), 200
    except Exception as e:
        return _error_response(e)


@app.route('/api/sessions/<session_id>/report/summary', methods=['POST'])
def generate_session_report_summary(session_id):
    try:
        session = Session.query.get(session_id)
        if not session:
            return jsonify({'error': 'Oturum bulunamadı'}), 404
        data = request.json or {}
        lang = data.get('lang', 'tr')
        results = [r.to_dict() for r in session.results]
        notes = _session_findings_for_report(session_id)
        report_data = report_generator.build_report_data(session.to_dict(), results, notes, lang=lang)

        provider = get_ai_provider(app.config, overrides=_ai_overrides_from_request())
        try:
            summary, ai_result = report_generator.generate_executive_summary(provider, report_data, lang=lang)
        except (AIConfigError, AIRequestError) as e:
            _log_ai_interaction('report_generation', error=e, session_id=session_id)
            raise
        _log_ai_interaction('report_generation', ai_result=ai_result, session_id=session_id)
        return jsonify({'summary': summary, 'provider': ai_result.provider}), 200
    except (AIConfigError, AIRequestError) as e:
        return _handle_ai_error(e)
    except Exception as e:
        return _error_response(e)


@app.route('/api/sessions/<session_id>/report/download', methods=['POST'])
def download_session_report(session_id):
    try:
        session = Session.query.get(session_id)
        if not session:
            return jsonify({'error': 'Oturum bulunamadı'}), 404
        data = request.json or {}
        fmt = data.get('format', 'md')
        if fmt not in VALID_REPORT_DOWNLOAD_FORMATS:
            return jsonify({'error': 'Geçersiz format (md veya docx olmalı)'}), 400
        lang = data.get('lang', 'tr')
        executive_summary = data.get('executive_summary')

        results = [r.to_dict() for r in session.results]
        notes = _session_findings_for_report(session_id)
        report_data = report_generator.build_report_data(session.to_dict(), results, notes, lang=lang)

        if fmt == 'md':
            text_body = report_generator.render_markdown(report_data, executive_summary=executive_summary, lang=lang)
            return text_body, 200, {'Content-Type': 'text/markdown; charset=utf-8'}

        buf = report_generator.render_docx(report_data, executive_summary=executive_summary, lang=lang)
        safe_name = ''.join(c if c.isalnum() or c in ' -_' else '_' for c in (session.name or 'report'))[:60]
        return send_file(
            buf, as_attachment=True, download_name=f"{safe_name}.docx",
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
    except Exception as e:
        return _error_response(e)


# ========================
# VERİTABANI BAŞLATMA
# ========================

def set_password_command(prompt=None, out=None, err=None):
    """`python app.py set-password`: parolayı terminalden belirler/sıfırlar.

    Parola komut satırı argümanı olarak alınmaz (shell geçmişine düşmesin).
    session_version artar; açık tüm oturumlar düşer."""
    prompt = prompt or getpass.getpass
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        password = prompt('Yeni parola: ')
        confirm = prompt('Yeni parola (tekrar): ')
    except (EOFError, KeyboardInterrupt):
        print('\nİptal edildi.', file=err)
        return 1
    if password != confirm:
        print('Parolalar eşleşmiyor.', file=err)
        return 1
    try:
        password_hash = auth.hash_password(password)
    except auth.PasswordPolicyError as e:
        print(str(e), file=err)
        return 1
    with app.app_context():
        ensure_schema()
        settings = _auth_settings()
        if settings is None:
            db.session.add(AuthSettings(id=1, password_hash=password_hash, session_version=1))
        else:
            settings.password_hash = password_hash
            settings.session_version = (settings.session_version or 0) + 1
        db.session.commit()
    print('Parola kaydedildi. Açık oturumlar kapatıldı.', file=out)
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv == ['set-password']:
        return set_password_command()
    if argv:
        print('Kullanım: python app.py [set-password]', file=sys.stderr)
        return 2

    # Varsayılan: yalnızca 127.0.0.1, debug kapalı. Debug ancak FLASK_DEBUG=1 ile
    # ve yalnızca localhost'ta açılabilir (bkz. security.run_settings).
    try:
        run = security.run_settings()
    except ValueError as e:
        print(f'[güvenlik] {e}', file=sys.stderr)
        return 2
    if not security.is_loopback(run['host']):
        print(f"[güvenlik] UYARI: API {run['host']} adresinde ağa açık. Trafik şifresiz (HTTP); "
              "ilk parola yalnızca bu bilgisayardan veya `python app.py set-password` ile belirlenebilir. "
              "Erişecek makinenin adını/IP'sini ALLOWED_HOSTS'a, frontend adresini CORS_ORIGINS'e ekleyin.",
              file=sys.stderr)
    with app.app_context():
        ensure_schema()
        print('Veritabanı hazır.')
        if _auth_settings() is None:
            print('Henüz parola yok: arayüzü bu bilgisayarda açıp parolayı belirleyin '
                  '(veya: python app.py set-password).')
    app.run(host=run['host'], port=run['port'], debug=run['debug'])
    return 0


if __name__ == '__main__':
    sys.exit(main())