from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
import os
import json
from config import DevelopmentConfig, ProductionConfig
from models import db, Session, TestResult

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
        return jsonify({'error': str(e)}), 500

# ========================
# VERİTABANI BAŞLATMA
# ========================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('✅ Veritabanı oluşturuldu!')
    app.run(host='0.0.0.0', port=5000, debug=True)