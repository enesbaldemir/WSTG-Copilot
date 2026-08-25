from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
import os
import json
import uuid
from werkzeug.utils import secure_filename
from sqlalchemy import text
from config import DevelopmentConfig, ProductionConfig
from models import db, Session, TestResult, Project, ScopeItem, TimelineEvent, ReconRun, Evidence, CustomTest, ToolRun, Finding, AIInteractionLog
import recon
import attack_chains
import report_builder
import report_html
import evidence_intel
import tool_runner
import cvss
import redaction
import duplicate_detector
import ai_report_assistant
import finding_analysis
from ai.factory import get_ai_provider
from ai.base import AIConfigError, AIRequestError

app = Flask(__name__)

env = os.getenv('FLASK_ENV', 'development')
if env == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

db.init_app(app)
CORS(app, resources={r"/*": {"origins": "*"}})
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


with app.app_context():
    ensure_schema()


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

        project_id = data.get('project_id')
        if project_id and not Project.query.get(project_id):
            return jsonify({'error': 'Belirtilen proje bulunamadı'}), 404

        session = Session(
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
                if session.project_id:
                    log_event(session.project_id, 'session_completed', f"Test oturumu tamamlandı: {session.name}")
        
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
        return jsonify({'error': str(e)}), 500

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
                    subdomains=json.dumps(result.get('subdomains', [])),
                    technologies=json.dumps(result.get('technologies', [])),
                    endpoints=json.dumps(list(dict.fromkeys(
                        (result.get('endpoints') or []) + [p['path'] for p in (result.get('interestingPaths') or [])]
                    )))
                )
                db.session.add(run)
                db.session.commit()
                log_event(project_id, 'recon_run', f"Attack Surface Discovery çalıştırıldı: {result.get('target')}",
                          {'subdomains': len(result.get('subdomains', [])), 'technologies': result.get('technologies', [])})
            except Exception:
                db.session.rollback()

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>', methods=['GET'])
def get_project(project_id):
    try:
        project = _project_or_404(project_id)
        return jsonify(project.to_dict()), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/scope', methods=['GET'])
def get_scope(project_id):
    try:
        _project_or_404(project_id)
        items = ScopeItem.query.filter_by(project_id=project_id).order_by(ScopeItem.created_at.desc()).all()
        return jsonify([i.to_dict() for i in items]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/timeline', methods=['GET'])
def get_timeline(project_id):
    try:
        _project_or_404(project_id)
        events = TimelineEvent.query.filter_by(project_id=project_id).order_by(TimelineEvent.created_at.desc()).limit(200).all()
        return jsonify([e.to_dict() for e in events]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/lifecycle', methods=['GET'])
def get_lifecycle(project_id):
    """Vulnerability Lifecycle özeti: bulguların remediation durumuna göre
    dağılımı (open/retesting/fixed/resolved/wont_fix/accepted_risk),
    aktif risk kalan (open+retesting) bulguların severity dağılımı, ve
    remediation oranı (resolved / toplam bulgu)."""
    try:
        _project_or_404(project_id)
        sessions = Session.query.filter_by(project_id=project_id).all()
        findings = []
        for s in sessions:
            for r in s.results:
                if r.finding and r.finding.strip():
                    findings.append(r)

        status_counts = {k: 0 for k in VALID_FINDING_STATUSES}
        active_severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for r in findings:
            st = r.finding_status if r.finding_status in VALID_FINDING_STATUSES else 'open'
            status_counts[st] += 1
            if st in ('open', 'retesting'):
                sev = (r.severity or 'info').lower()
                if sev in active_severity_counts:
                    active_severity_counts[sev] += 1

        total = len(findings)
        resolved = status_counts['resolved']
        remediation_rate = round((resolved / total) * 100, 1) if total else 0

        events = TimelineEvent.query.filter_by(
            project_id=project_id, event_type='finding_status_changed'
        ).order_by(TimelineEvent.created_at.desc()).limit(50).all()

        return jsonify({
            'total_findings': total,
            'status_counts': status_counts,
            'active_severity_counts': active_severity_counts,
            'remediation_rate': remediation_rate,
            'recent_transitions': [e.to_dict() for e in events]
        }), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


# ========================
# EVIDENCE INTELLIGENCE
# ========================
#
# Guvenlik notlari (bilerek boyle tasarlandi):
# - Diskteki dosya adi HICBIR ZAMAN kullanicinin yukledigi dosya adindan
#   turetilmez -- her zaman sunucu tarafinda uretilen bir UUID kullanilir.
#   Bu, path traversal / dosya adi enjeksiyonunu yapisal olarak engeller.
# - Sadece bilinen imaj MIME turlerine izin verilir (evidence_intel.
#   SUPPORTED_MIME_TYPES).
# - AI analizi TAMAMEN OPSIYONELDIR (bkz. evidence_intel.py docstring).

def _evidence_dir(project_id):
    path = os.path.join(app.config['UPLOAD_FOLDER'], 'evidence', project_id)
    os.makedirs(path, exist_ok=True)
    return path


EXT_BY_MIME = {'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif'}


@app.route('/api/projects/<project_id>/evidence', methods=['GET'])
def list_evidence(project_id):
    try:
        _project_or_404(project_id)
        items = Evidence.query.filter_by(project_id=project_id).order_by(Evidence.created_at.desc()).all()
        return jsonify([e.to_dict() for e in items]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/evidence', methods=['POST'])
def upload_evidence(project_id):
    try:
        _project_or_404(project_id)

        if 'file' not in request.files:
            return jsonify({'error': 'Dosya bulunamadı (form alanı: file)'}), 400
        file = request.files['file']
        if not file or not file.filename:
            return jsonify({'error': 'Geçersiz dosya'}), 400

        mime_type = file.mimetype
        if mime_type not in evidence_intel.SUPPORTED_MIME_TYPES:
            return jsonify({'error': f'Desteklenmeyen dosya türü: {mime_type}. Sadece PNG/JPEG/WEBP/GIF kabul edilir.'}), 400

        file_bytes = file.read()
        if len(file_bytes) == 0:
            return jsonify({'error': 'Dosya boş'}), 400

        stored_filename = f"{uuid.uuid4().hex}{EXT_BY_MIME.get(mime_type, '')}"
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
            review_status='manual' if request.form.get('linked_test_id') else 'pending'
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
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/evidence/<int:evidence_id>/file', methods=['GET'])
def get_evidence_file(evidence_id):
    try:
        evidence = Evidence.query.get(evidence_id)
        if not evidence:
            return jsonify({'error': 'Kanıt bulunamadı'}), 404
        if evidence.evidence_type != 'image':
            return jsonify({'error': 'Bu kanıt bir dosya değil (http_transaction)'}), 400
        path = os.path.join(_evidence_dir(evidence.project_id), evidence.stored_filename)
        if not os.path.isfile(path):
            return jsonify({'error': 'Dosya diskte bulunamadı'}), 404
        return send_file(path, mimetype=evidence.mime_type)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/tools/runs', methods=['GET'])
def list_project_tool_runs(project_id):
    try:
        _project_or_404(project_id)
        runs = ToolRun.query.filter_by(project_id=project_id).order_by(ToolRun.created_at.desc()).limit(50).all()
        return jsonify([r.to_dict() for r in runs]), 200
    except NotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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

def _handle_ai_error(e):
    if isinstance(e, AIConfigError):
        return jsonify({'error': str(e), 'ai_configured': False}), 503
    if isinstance(e, AIRequestError):
        return jsonify({'error': str(e)}), 502
    return jsonify({'error': str(e)}), 500


def _log_ai_interaction(purpose, ai_result=None, error=None, project_id=None, finding_id=None):
    try:
        log = AIInteractionLog(
            project_id=project_id,
            finding_id=finding_id,
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
        provider = get_ai_provider(app.config)
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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/findings/<int:finding_id>/ai/remediation', methods=['POST'])
def ai_generate_remediation(project_id, finding_id):
    try:
        _project_or_404(project_id)
        finding = Finding.query.filter_by(id=finding_id, project_id=project_id).first()
        if not finding:
            return jsonify({'error': 'Finding bulunamadı'}), 404
        lang = (request.json or {}).get('lang', 'tr')
        provider = get_ai_provider(app.config)
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
        return jsonify({'error': str(e)}), 500


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
        provider = get_ai_provider(app.config)
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
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/rewrite', methods=['POST'])
def ai_rewrite_text():
    try:
        data = request.json or {}
        text = data.get('text', '')
        lang = data.get('lang', 'tr')
        if not text.strip():
            return jsonify({'error': 'text zorunludur'}), 400
        provider = get_ai_provider(app.config)
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
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects/<project_id>/ai/executive-summary', methods=['POST'])
def ai_project_executive_summary(project_id):
    try:
        project = _project_or_404(project_id)
        lang = (request.json or {}).get('lang', 'tr')
        findings = [f.to_dict() for f in Finding.query.filter_by(project_id=project_id).all()]
        provider = get_ai_provider(app.config)
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
        return jsonify({'error': str(e)}), 500


# ========================
# HTML PROFESSIONAL REPORT
# ========================

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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500


# ========================
# VERİTABANI BAŞLATMA
# ========================

if __name__ == '__main__':
    with app.app_context():
        ensure_schema()
        print('✅ Veritabanı oluşturuldu!')
    app.run(host='0.0.0.0', port=5000, debug=True)