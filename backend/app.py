from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
import os
import json
import io
from config import DevelopmentConfig, ProductionConfig
from models import db, Session, TestResult, Note, AIInteractionLog
from ai import get_ai_provider, AIConfigError, AIRequestError
import cvss as cvss_lib
import mapping as mapping_lib
import finding_analysis
import next_test_suggestion
import report_generator
import study_metrics

app = Flask(__name__)

env = os.getenv('FLASK_ENV', 'development')
if env == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

db.init_app(app)
_cors_origins = [o.strip() for o in app.config['CORS_ORIGINS'].split(',') if o.strip()]
CORS(app, resources={r"/*": {"origins": _cors_origins}})
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database'), exist_ok=True)

with app.app_context():
    db.create_all()

    # ---- Hafif otomatik migrasyon (SQLite) ----
    # db.create_all() sadece EKSİK TABLOLARI oluşturur, var olan bir tabloya
    # yeni eklenen sütunları eklemez. Faz'lar ilerledikçe modele yeni alanlar
    # eklendiğinde (örn. Faz 1'deki CVSS/CWE sütunları) mevcut geliştiricilerin
    # veritabanını silmek zorunda kalmaması için eksik sütunları burada tespit
    # edip ALTER TABLE ile ekliyoruz.
    def _run_lightweight_sqlite_migrations():
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        table_names = inspector.get_table_names()

        tables_and_columns = {
            'notes': {
                'cvss_vector': 'VARCHAR(120)',
                'cvss_score': 'FLOAT',
                'cvss_rating': 'VARCHAR(20)',
                'cwe_id': 'VARCHAR(20)',
                'cwe_name': 'VARCHAR(200)',
                'is_false_positive': 'BOOLEAN',
            },
            'sessions': {
                'study_group': 'VARCHAR(20)',
            },
        }
        with db.engine.begin() as conn:
            for table, wanted_cols in tables_and_columns.items():
                if table not in table_names:
                    continue
                existing_cols = {c['name'] for c in inspector.get_columns(table)}
                for col, col_type in wanted_cols.items():
                    if col not in existing_cols:
                        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {col_type}'))
                        print(f"🔧 Migrasyon: {table}.{col} sütunu eklendi")

    _run_lightweight_sqlite_migrations()

# ========================
# SESSION ENDPOINT'LERİ
# ========================

@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    try:
        sessions = Session.query.order_by(Session.created_at.desc()).all()
        return jsonify([s.to_dict() for s in sessions]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>', methods=['GET'])
def get_session(session_id):
    try:
        session = Session.query.get_or_404(session_id)
        return jsonify(session.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/api/sessions', methods=['POST'])
def create_session():
    try:
        data = request.json
        
        if not data.get('name'):
            return jsonify({'error': 'Oturum adı zorunludur'}), 400

        study_group = data.get('study_group') or None
        if study_group not in (None, 'ai_assisted', 'control'):
            return jsonify({'error': "study_group 'ai_assisted', 'control' ya da null olmalıdır"}), 400

        session = Session(
            name=data['name'],
            description=data.get('description', ''),
            tester_name=data.get('tester_name', ''),
            target_url=data.get('target_url', ''),
            target_description=data.get('target_description', ''),
            status='active',
            study_group=study_group,
            started_at=datetime.utcnow()
        )
        
        db.session.add(session)
        db.session.commit()
        
        return jsonify(session.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

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
        if 'study_group' in data:
            group = data['study_group']
            if group not in (None, '', 'ai_assisted', 'control'):
                return jsonify({'error': "study_group 'ai_assisted', 'control' ya da null olmalıdır"}), 400
            session.study_group = group or None
        
        session.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify(session.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    try:
        session = Session.query.get_or_404(session_id)
        db.session.delete(session)
        db.session.commit()
        return jsonify({'message': 'Oturum silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ========================
# TEST RESULT ENDPOINT'LERİ
# ========================

@app.route('/api/sessions/<session_id>/results', methods=['GET'])
def get_test_results(session_id):
    try:
        results = TestResult.query.filter_by(session_id=session_id).all()
        return jsonify([r.to_dict() for r in results]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/results/<test_id>', methods=['GET'])
def get_test_result(session_id, test_id):
    try:
        result = TestResult.query.filter_by(
            session_id=session_id, 
            test_id=test_id
        ).first_or_404()
        return jsonify(result.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 404

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
            started_at=datetime.utcnow()
        )
        
        db.session.add(result)
        db.session.commit()
        
        return jsonify(result.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/results/<test_id>', methods=['PUT'])
def update_test_result(session_id, test_id):
    try:
        result = TestResult.query.filter_by(
            session_id=session_id,
            test_id=test_id
        ).first_or_404()
        
        data = request.json
        
        if 'status' in data:
            result.status = data['status']
            if data['status'] in ['passed', 'failed', 'skipped']:
                result.completed_at = datetime.utcnow()
        if 'severity' in data:
            result.severity = data['severity']
        if 'notes' in data:
            result.notes = data['notes']
        if 'evidence' in data:
            result.evidence = data['evidence']
        if 'finding' in data:
            result.finding = data['finding']
        if 'progress' in data:
            result.progress = data['progress']
        
        result.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify(result.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

# ========================
# NOT DEFTERİ ENDPOINT'LERİ
# ========================
# Bu uçlar, checklist maddesindeki tekil 'notes/finding' alanından ayrı,
# oturuma (siteye) bağlı serbest bir not defteri sağlar. Her not dilerse
# belirli bir WSTG test maddesine (test_id) bağlanabilir, dilerse genel
# (test_id=null) bir not olarak kalabilir. Kanıt için görsel eklenebilir
# (base64 data-URL listesi olarak saklanır).

MAX_NOTE_IMAGES = 8
MAX_IMAGE_BYTES = 4 * 1024 * 1024  # tek görsel için kabaca üst sınır


def _sanitize_images(raw_images):
    """Gelen görsel listesini doğrular ve JSON string'e çevirir."""
    if not raw_images:
        return json.dumps([])
    if not isinstance(raw_images, list):
        raise ValueError('images bir liste olmalıdır')
    if len(raw_images) > MAX_NOTE_IMAGES:
        raise ValueError(f'En fazla {MAX_NOTE_IMAGES} görsel eklenebilir')
    cleaned = []
    for img in raw_images:
        if not isinstance(img, dict):
            continue
        data = img.get('data', '')
        if not isinstance(data, str) or not data.startswith('data:image/'):
            raise ValueError('Geçersiz görsel verisi')
        if len(data) > MAX_IMAGE_BYTES * 1.4:  # base64 şişmesi için kaba pay
            raise ValueError('Görsel çok büyük')
        cleaned.append({
            'name': str(img.get('name', 'kanit'))[:200],
            'data': data
        })
    return json.dumps(cleaned)


def _apply_cvss_and_cwe(note, data):
    """
    Not/finding kaydına CVSS ve CWE alanlarını uygular. CVSS skoru/rating'i
    HER ZAMAN sunucu tarafında cvss.calculate() ile yeniden hesaplanır —
    istemciden gelen skor asla doğrudan güvenilmez (tutarlılık ve
    ileride Faz 4'teki otomatik rapor üretiminin doğruluğu için önemli).
    """
    if 'cvss_vector' in data:
        vector = (data.get('cvss_vector') or '').strip()
        if not vector:
            note.cvss_vector = None
            note.cvss_score = None
            note.cvss_rating = None
        else:
            try:
                result = cvss_lib.calculate(vector)
            except cvss_lib.CVSSError as e:
                raise ValueError(f"Geçersiz CVSS vektörü: {e}")
            note.cvss_vector = result['vector']
            note.cvss_score = result['score']
            note.cvss_rating = result['rating']

    if 'cwe_id' in data:
        note.cwe_id = (data.get('cwe_id') or '').strip() or None
    if 'cwe_name' in data:
        note.cwe_name = (data.get('cwe_name') or '').strip() or None


@app.route('/api/sessions/<session_id>/notes', methods=['GET'])
def get_notes(session_id):
    try:
        Session.query.get_or_404(session_id)
        test_id = request.args.get('test_id')
        query = Note.query.filter_by(session_id=session_id)
        if test_id:
            query = query.filter_by(test_id=test_id)
        notes = query.order_by(Note.created_at.desc()).all()
        return jsonify([n.to_dict() for n in notes]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/notes', methods=['POST'])
def create_note(session_id):
    try:
        Session.query.get_or_404(session_id)
        data = request.json or {}

        if not (data.get('content') or '').strip() and not data.get('images'):
            return jsonify({'error': 'Not içeriği veya en az bir görsel gereklidir'}), 400

        note = Note(
            session_id=session_id,
            test_id=data.get('test_id') or None,
            category_id=data.get('category_id') or None,
            title=data.get('title', ''),
            content=data.get('content', ''),
            severity=data.get('severity', 'info'),
            images=_sanitize_images(data.get('images'))
        )
        if 'is_false_positive' in data:
            val = data['is_false_positive']
            note.is_false_positive = bool(val) if val is not None else None
        _apply_cvss_and_cwe(note, data)

        db.session.add(note)
        db.session.commit()

        return jsonify(note.to_dict()), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/notes/<int:note_id>', methods=['PUT'])
def update_note(session_id, note_id):
    try:
        note = Note.query.filter_by(session_id=session_id, id=note_id).first_or_404()
        data = request.json or {}

        if 'title' in data:
            note.title = data['title']
        if 'content' in data:
            note.content = data['content']
        if 'severity' in data:
            note.severity = data['severity']
        if 'test_id' in data:
            note.test_id = data['test_id'] or None
        if 'category_id' in data:
            note.category_id = data['category_id'] or None
        if 'images' in data:
            note.images = _sanitize_images(data['images'])
        if 'is_false_positive' in data:
            val = data['is_false_positive']
            note.is_false_positive = bool(val) if val is not None else None
        _apply_cvss_and_cwe(note, data)

        note.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify(note.to_dict()), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/notes/<int:note_id>', methods=['DELETE'])
def delete_note(session_id, note_id):
    try:
        note = Note.query.filter_by(session_id=session_id, id=note_id).first_or_404()
        db.session.delete(note)
        db.session.commit()
        return jsonify({'message': 'Not silindi'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ========================
# AI / LLM ENDPOINT'LERİ (Faz 0)
# ========================
# Bu bölüm şimdilik yalnızca altyapıyı doğrulamaya yarayan bir "ping" ve
# geçmiş çağrıları listeleyen bir "logs" ucu içerir. Faz 2+'da eklenecek
# gerçek analiz uçları (finding analizi, sonraki test önerisi, otomatik
# rapor) hep aynı log_ai_interaction() yardımcısını kullanacak, böylece
# Faz 5'teki deneysel karşılaştırma için veri en baştan tutarlı toplanır.

def log_ai_interaction(purpose, provider=None, model=None, prompt=None,
                        response=None, success=True, error_message=None,
                        latency_ms=None, session_id=None):
    try:
        log = AIInteractionLog(
            session_id=session_id,
            purpose=purpose,
            provider=provider,
            model=model,
            prompt=prompt,
            response=response,
            success=success,
            error_message=error_message,
            latency_ms=latency_ms
        )
        db.session.add(log)
        db.session.commit()
        return log
    except Exception:
        db.session.rollback()
        return None


@app.route('/api/ai/ping', methods=['GET'])
def ai_ping():
    """
    Aktif AI sağlayıcısının doğru yapılandırıldığını ve gerçekten
    yanıt verdiğini doğrulamak için basit bir bağlantı testi.
    """
    session_id = request.args.get('session_id')
    try:
        provider = get_ai_provider(app.config)
    except ValueError as e:
        return jsonify({'configured': False, 'error': str(e)}), 400

    if not provider.is_configured():
        return jsonify({
            'configured': False,
            'provider': provider.name,
            'error': f"'{provider.name}' için API key/config eksik. backend/.env dosyasını kontrol edin."
        }), 200

    test_prompt = "Sadece 'WSTG-Copilot AI bağlantısı çalışıyor.' cümlesiyle cevap ver."
    try:
        result = provider.chat(system_prompt="", user_prompt=test_prompt, max_tokens=200)
        log_ai_interaction(
            purpose='ping', provider=result.provider, model=result.model,
            prompt=test_prompt, response=result.text, success=True,
            latency_ms=result.latency_ms, session_id=session_id
        )
        return jsonify({
            'configured': True,
            'provider': result.provider,
            'model': result.model,
            'latency_ms': result.latency_ms,
            'sample_response': result.text
        }), 200
    except (AIConfigError, AIRequestError) as e:
        log_ai_interaction(
            purpose='ping', provider=provider.name, model=getattr(provider, 'model', None),
            prompt=test_prompt, success=False, error_message=str(e),
            latency_ms=getattr(e, 'latency_ms', None), session_id=session_id
        )
        return jsonify({'configured': True, 'provider': provider.name, 'error': str(e)}), 502


@app.route('/api/ai/logs', methods=['GET'])
def ai_logs():
    """Faz 5'teki metrik/dashboard çalışması için ham AI çağrı geçmişi."""
    session_id = request.args.get('session_id')
    purpose = request.args.get('purpose')
    query = AIInteractionLog.query
    if session_id:
        query = query.filter_by(session_id=session_id)
    if purpose:
        query = query.filter_by(purpose=purpose)
    logs = query.order_by(AIInteractionLog.created_at.desc()).limit(200).all()
    return jsonify([l.to_dict() for l in logs]), 200


@app.route('/api/ai/analyze-finding', methods=['POST'])
def ai_analyze_finding():
    """
    Faz 2: Bir bulguyu (title + content, dilerse bağlı test_id) AI'a
    gönderip CWE/severity/CVSS önerisi + false-positive değerlendirmesi
    alır. Notu OTOMATİK GÜNCELLEMEZ — sadece öneri döner; uygulamak
    isteyen istemci mevcut PUT /notes/<id> ucunu kullanır.
    """
    data = request.json or {}
    title = data.get('title', '')
    content = (data.get('content') or '').strip()
    test_id = data.get('test_id') or None
    lang = data.get('lang', 'tr')
    session_id = data.get('session_id') or None
    note_id = data.get('note_id')  # sadece loglama amaçlı, opsiyonel

    if not content:
        return jsonify({'error': 'Analiz için bulgu içeriği (content) gereklidir'}), 400

    try:
        provider = get_ai_provider(app.config)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    if not provider.is_configured():
        return jsonify({
            'error': f"'{provider.name}' için API key/config eksik. backend/.env dosyasını kontrol edin."
        }), 200

    try:
        analysis, ai_result = finding_analysis.analyze_finding(
            provider, title, content, test_id=test_id, lang=lang
        )
        log_ai_interaction(
            purpose='finding_analysis', provider=ai_result.provider, model=ai_result.model,
            prompt=f"title={title!r} test_id={test_id!r} content_len={len(content)}",
            response=ai_result.text, success=True, latency_ms=ai_result.latency_ms,
            session_id=session_id
        )
        return jsonify({
            **analysis,
            'provider': ai_result.provider,
            'model': ai_result.model,
            'latency_ms': ai_result.latency_ms,
            'note_id': note_id
        }), 200
    except (AIConfigError, AIRequestError, finding_analysis.FindingAnalysisError) as e:
        log_ai_interaction(
            purpose='finding_analysis', provider=provider.name, model=getattr(provider, 'model', None),
            prompt=f"title={title!r} test_id={test_id!r} content_len={len(content)}",
            success=False, error_message=str(e),
            latency_ms=getattr(e, 'latency_ms', None), session_id=session_id
        )
        return jsonify({'error': str(e)}), 502


@app.route('/api/ai/suggest-next-test', methods=['POST'])
def ai_suggest_next_test():
    """
    Faz 3: Tamamlanan testler + bulgulara bakarak sırada hangi WSTG
    testinin yapılmasının en mantıklı olacağını önerir. Öneri sadece
    "henüz yapılmamış" havuzundan doğrulanır (suggestion_grounded).
    """
    data = request.json or {}
    completed_test_ids = data.get('completed_test_ids') or []
    findings = data.get('findings') or []
    lang = data.get('lang', 'tr')
    session_id = data.get('session_id') or None

    if not isinstance(completed_test_ids, list):
        return jsonify({'error': "'completed_test_ids' bir liste olmalıdır"}), 400

    try:
        provider = get_ai_provider(app.config)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    if not provider.is_configured():
        return jsonify({
            'error': f"'{provider.name}' için API key/config eksik. backend/.env dosyasını kontrol edin."
        }), 200

    try:
        suggestion, ai_result = next_test_suggestion.suggest_next_test(
            provider, completed_test_ids, findings, lang=lang
        )
        if ai_result is None:  # tüm testler tamamlanmış, AI'a hiç gidilmedi
            return jsonify(suggestion), 200

        log_ai_interaction(
            purpose='next_test_suggestion', provider=ai_result.provider, model=ai_result.model,
            prompt=f"completed={len(completed_test_ids)} findings={len(findings)}",
            response=ai_result.text, success=True, latency_ms=ai_result.latency_ms,
            session_id=session_id
        )
        return jsonify({
            **suggestion,
            'provider': ai_result.provider,
            'model': ai_result.model,
            'latency_ms': ai_result.latency_ms
        }), 200
    except (AIConfigError, AIRequestError, next_test_suggestion.NextTestSuggestionError) as e:
        log_ai_interaction(
            purpose='next_test_suggestion', provider=provider.name, model=getattr(provider, 'model', None),
            prompt=f"completed={len(completed_test_ids)} findings={len(findings)}",
            success=False, error_message=str(e),
            latency_ms=getattr(e, 'latency_ms', None), session_id=session_id
        )
        return jsonify({'error': str(e)}), 502

# ========================
# CVSS / WSTG↔OWASP↔CWE ENDPOINT'LERİ (Faz 1)
# ========================

@app.route('/api/cvss/calculate', methods=['POST'])
def cvss_calculate():
    """Bir CVSS 3.1 vektöründen skor/rating hesaplar (durum tutmaz, sadece hesap makinesi)."""
    data = request.json or {}
    vector = (data.get('vector') or '').strip()
    if not vector:
        return jsonify({'error': "'vector' alanı gereklidir"}), 400
    try:
        result = cvss_lib.calculate(vector)
        return jsonify(result), 200
    except cvss_lib.CVSSError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/mapping/wstg/<test_id>', methods=['GET'])
def wstg_mapping(test_id):
    """
    Bir WSTG test ID'si için ilişkili OWASP Top 10 kategorileri ve
    önerilen CWE'leri döner. Not editöründeki CWE önerisi ve Faz 2'deki
    AI bulgu analizine verilecek bağlam bu uçtan beslenir.
    """
    lang = request.args.get('lang', 'tr')
    matches = mapping_lib.get_mapping_for_test(test_id, lang)
    suggested_cwes = mapping_lib.suggest_cwes_for_test(test_id, lang)
    return jsonify({
        'test_id': test_id,
        'owasp_matches': matches,
        'suggested_cwes': suggested_cwes
    }), 200

# ========================
# RAPOR ENDPOINT'İ
# ========================

@app.route('/api/sessions/<session_id>/report', methods=['GET'])
def generate_report(session_id):
    try:
        session = Session.query.get_or_404(session_id)
        results = TestResult.query.filter_by(session_id=session_id).all()
        notes = Note.query.filter_by(session_id=session_id).order_by(Note.created_at.asc()).all()
        
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
            'notes': [n.to_dict() for n in notes],
            'generated_at': datetime.utcnow().isoformat()
        }
        
        return jsonify(report), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========================
# FAZ 4: OTOMATİK RAPOR ÜRETİMİ
# ========================

def _load_report_data(session_id, lang):
    session = Session.query.get_or_404(session_id)
    results = TestResult.query.filter_by(session_id=session_id).all()
    notes = Note.query.filter_by(session_id=session_id).all()
    return report_generator.build_report_data(
        session.to_dict(), [r.to_dict() for r in results], [n.to_dict() for n in notes], lang=lang
    )


@app.route('/api/sessions/<session_id>/report/data', methods=['GET'])
def report_data(session_id):
    """Faz 4 rapor önizlemesi için zenginleştirilmiş (CVSS/CWE/OWASP dahil) veri."""
    lang = request.args.get('lang', 'tr')
    try:
        return jsonify(_load_report_data(session_id, lang)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions/<session_id>/report/summary', methods=['POST'])
def report_ai_summary(session_id):
    """
    AI ile yönetici özeti taslağı üretir. Rapora HENÜZ İŞLENMEZ —
    döndürülen metin frontend'de düzenlenebilir bir kutuda gösterilir;
    nihai rapora ancak pentester onaylayıp indirme isteğine bu metni
    dahil ederse girer (bkz. /report/download).
    """
    data = request.json or {}
    lang = data.get('lang', 'tr')

    try:
        provider = get_ai_provider(app.config)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    if not provider.is_configured():
        return jsonify({
            'error': f"'{provider.name}' için API key/config eksik. backend/.env dosyasını kontrol edin."
        }), 200

    try:
        report = _load_report_data(session_id, lang)
        summary, ai_result = report_generator.generate_executive_summary(provider, report, lang=lang)
        log_ai_interaction(
            purpose='report_generation', provider=ai_result.provider, model=ai_result.model,
            prompt=f"session={session_id} findings={report['stats']['total_findings']}",
            response=summary, success=True, latency_ms=ai_result.latency_ms, session_id=session_id
        )
        return jsonify({
            'summary': summary,
            'provider': ai_result.provider,
            'model': ai_result.model,
            'latency_ms': ai_result.latency_ms
        }), 200
    except (AIConfigError, AIRequestError) as e:
        log_ai_interaction(
            purpose='report_generation', provider=provider.name, model=getattr(provider, 'model', None),
            success=False, error_message=str(e), latency_ms=getattr(e, 'latency_ms', None), session_id=session_id
        )
        return jsonify({'error': str(e)}), 502


@app.route('/api/sessions/<session_id>/report/download', methods=['POST'])
def report_download(session_id):
    """
    Nihai rapor dosyasını üretir. Gövdede opsiyonel 'executive_summary'
    (pentester tarafından düzenlenmiş/onaylanmış metin) ve 'format'
    ('docx' | 'md') beklenir.
    """
    data = request.json or {}
    fmt = (data.get('format') or 'md').lower()
    lang = data.get('lang', 'tr')
    executive_summary = (data.get('executive_summary') or '').strip() or None

    if fmt not in ('docx', 'md'):
        return jsonify({'error': "format 'docx' ya da 'md' olmalıdır"}), 400

    try:
        report = _load_report_data(session_id, lang)
        session_name = (report['session'].get('name') or 'pentest-raporu').strip().replace(' ', '_')

        if fmt == 'md':
            content = report_generator.render_markdown(report, executive_summary, lang=lang)
            buf = io.BytesIO(content.encode('utf-8'))
            return send_file(buf, mimetype='text/markdown', as_attachment=True,
                              download_name=f"{session_name}.md")

        buf = report_generator.render_docx(report, executive_summary, lang=lang)
        return send_file(
            buf,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True, download_name=f"{session_name}.docx"
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========================
# FAZ 5: DENEYSEL A/B KARŞILAŞTIRMA
# ========================

@app.route('/api/study/metrics', methods=['GET'])
def study_metrics_endpoint():
    """
    Çalışma grubuna ('ai_assisted' / 'control') atanmış tüm oturumların
    metriklerini ve iki grup arası karşılaştırmayı döner. Etiketlenmemiş
    oturumlar (study_group=None) hesaplamaya dahil edilmez ama şeffaflık
    için 'unassigned_sessions_count' alanında sayısı belirtilir.
    """
    try:
        all_sessions = Session.query.all()
        per_session = []
        unassigned_count = 0

        for session in all_sessions:
            if not session.study_group:
                unassigned_count += 1
                continue
            results = TestResult.query.filter_by(session_id=session.id).all()
            notes = Note.query.filter_by(session_id=session.id).all()
            ai_logs = AIInteractionLog.query.filter_by(session_id=session.id).all()
            per_session.append(study_metrics.compute_session_metrics(
                session.to_dict(),
                [r.to_dict() for r in results],
                [n.to_dict() for n in notes],
                [l.to_dict() for l in ai_logs],
            ))

        comparison = study_metrics.compare_groups(per_session)
        return jsonify({
            'sessions': per_session,
            'comparison': comparison,
            'unassigned_sessions_count': unassigned_count,
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========================
# VERİTABANI BAŞLATMA
# ========================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('✅ Veritabanı oluşturuldu!')
    # Debug modu ve dış ağa açık bind (0.0.0.0) birlikte AÇIK OLURSA Werkzeug'un
    # interaktif debugger'ı ağdan erişilebilir hale gelir (bilinen bir RCE riski).
    # Bu yüzden ikisi de config/env'den okunuyor; varsayılan sadece localhost'a bind eder.
    host = os.getenv('FLASK_RUN_HOST', '127.0.0.1')
    app.run(host=host, port=5000, debug=app.config['DEBUG'])