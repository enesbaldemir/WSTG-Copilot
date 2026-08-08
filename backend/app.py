from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
import os
import json
from config import DevelopmentConfig, ProductionConfig
from models import db, Session, TestResult, Note

app = Flask(__name__)

env = os.getenv('FLASK_ENV', 'development')
if env == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

db.init_app(app)
CORS(app, resources={r"/*": {"origins": "*"}})
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database'), exist_ok=True)

with app.app_context():
    db.create_all()

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
        
        session = Session(
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
# VERİTABANI BAŞLATMA
# ========================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('✅ Veritabanı oluşturuldu!')
    app.run(host='0.0.0.0', port=5000, debug=True)