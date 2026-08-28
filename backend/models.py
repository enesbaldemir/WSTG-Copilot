from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import json

db = SQLAlchemy()

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    client = db.Column(db.String(200))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='planning')  # planning|active|paused|completed|archived

    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scope_items = db.relationship('ScopeItem', backref='project', lazy=True, cascade='all, delete-orphan')
    timeline_events = db.relationship('TimelineEvent', backref='project', lazy=True, cascade='all, delete-orphan')
    recon_runs = db.relationship('ReconRun', backref='project', lazy=True, cascade='all, delete-orphan')
    evidence_items = db.relationship('Evidence', backref='project', lazy=True, cascade='all, delete-orphan')
    custom_tests = db.relationship('CustomTest', backref='project', lazy=True, cascade='all, delete-orphan')
    tool_runs = db.relationship('ToolRun', backref='project', lazy=True, cascade='all, delete-orphan')
    findings = db.relationship('Finding', backref='project', lazy=True, cascade='all, delete-orphan')
    # Sessions are NOT cascade-deleted with a project — a session's test data
    # should survive even if the parent project is removed; see delete_project().
    sessions = db.relationship('Session', backref='project', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'client': self.client,
            'description': self.description,
            'status': self.status,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'session_count': len(self.sessions) if self.sessions else 0
        }


class ScopeItem(db.Model):
    __tablename__ = 'scope_items'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # domain|subdomain|ip|cidr
    value = db.Column(db.String(300), nullable=False)
    description = db.Column(db.String(300))
    in_scope = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'type': self.type,
            'value': self.value,
            'description': self.description,
            'in_scope': self.in_scope,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class TimelineEvent(db.Model):
    __tablename__ = 'timeline_events'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    meta = db.Column(db.Text)  # JSON-encoded extra context, optional
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        meta_parsed = None
        if self.meta:
            try:
                meta_parsed = json.loads(self.meta)
            except Exception:
                meta_parsed = self.meta
        return {
            'id': self.id,
            'project_id': self.project_id,
            'event_type': self.event_type,
            'message': self.message,
            'meta': meta_parsed,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Finding(db.Model):
    """Profesyonel Finding nesnesi (roadmap: 'Findings sistemi + CVSS').

    Bilinçli tasarım kararı: TestResult.finding (basit metin alanı) HİÇ
    değiştirilmedi -- Attack Chains, raporlar ve lifecycle dashboard hâlâ
    ona dayanıyor. Finding, üzerine KATMAN olarak eklenen, daha zengin bir
    yapı: CVSS, CWE, endpoint/parametre, remediation, atanan kişi, retest
    takibi. Bir TestResult'tan "Professional Finding'e Yükselt" ile
    oluşturulabilir, ya da bağımsız olarak da eklenebilir (session_id/
    test_id nullable)."""
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=True)
    test_id = db.Column(db.String(50), nullable=True)  # WSTG-* / LLM-* / CUSTOM-*

    title = db.Column(db.String(300), nullable=False)
    severity = db.Column(db.String(20), default='info')  # cvss varsa severity_label'dan türetilir

    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(80))
    cwe = db.Column(db.String(50))
    owasp_category = db.Column(db.String(100))

    endpoint = db.Column(db.String(300))
    parameter = db.Column(db.String(200))

    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    remediation = db.Column(db.Text)
    references = db.Column(db.Text)  # satır satır URL

    status = db.Column(db.String(20), default='open')  # open|confirmed|fixed|retest_pending|resolved|wont_fix|accepted_risk
    assigned_to = db.Column(db.String(100))

    retest_result = db.Column(db.String(20))  # not_tested|fixed|not_fixed
    retest_notes = db.Column(db.Text)
    retested_at = db.Column(db.DateTime)

    # Merge Findings ozelligi: bu bulgu baska bulgu(lar)in icine birlestirildiyse
    # (bkz. duplicate_detector.py + POST /findings/merge), birlestirilen orijinal
    # ID'lerin JSON listesi -- denetim/izlenebilirlik icin. Silinmez, sadece kayit.
    merged_finding_ids = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        merged_ids = []
        if self.merged_finding_ids:
            try:
                merged_ids = json.loads(self.merged_finding_ids)
            except Exception:
                merged_ids = []
        return {
            'id': self.id,
            'finding_code': f'FND-{self.id:04d}' if self.id else None,
            'project_id': self.project_id,
            'session_id': self.session_id,
            'test_id': self.test_id,
            'title': self.title,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cwe': self.cwe,
            'owasp_category': self.owasp_category,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'references': self.references,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'retest_result': self.retest_result,
            'retest_notes': self.retest_notes,
            'retested_at': self.retested_at.isoformat() if self.retested_at else None,
            'merged_finding_ids': merged_ids,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class ToolRun(db.Model):
    """Tool Integration: gerçek bir CLI aracının (nmap/httpx/whatweb/
    subfinder/dnsx) kullanıcının kendi makinesinde çalıştırılmasının
    kaydı. Komut her zaman argv listesi olarak çalıştırılır — bkz.
    backend/tool_runner.py docstring'i."""
    __tablename__ = 'tool_runs'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)
    tool = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(300), nullable=False)
    command = db.Column(db.String(500))
    status = db.Column(db.String(20), default='completed')  # completed|failed|timeout
    exit_code = db.Column(db.Integer)
    stdout = db.Column(db.Text)
    stderr = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'tool': self.tool,
            'target': self.target,
            'command': self.command,
            'status': self.status,
            'exit_code': self.exit_code,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class CustomTest(db.Model):
    """Kuruluşa özel test maddeleri (roadmap: 'Custom -> Organization-specific
    tests'). Bunlar resmi WSTG-04 veri setinden gelmez ama checklist'te
    normal bir WSTG testi gibi davranır: işaretlenebilir, bulgu eklenebilir.
    OWASP WSTG 5.0 henüz yayınlanmadığı için (bkz. proje notları) bu,
    şu an gerçekten uygulanabilecek 'version-aware / genişletilebilir test
    kataloğu' parçasıdır."""
    __tablename__ = 'custom_tests'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)
    test_id = db.Column(db.String(40), nullable=False)  # örn. 'CUSTOM-a1b2c3d4'
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'test_id': self.test_id,
            'title': self.title,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Evidence(db.Model):
    __tablename__ = 'evidence'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)

    evidence_type = db.Column(db.String(20), default='image')  # image|http_transaction

    # --- image tipi alanları ---
    filename = db.Column(db.String(300))       # kullanıcının orijinal dosya adı (sadece görüntüleme amaçlı)
    stored_filename = db.Column(db.String(100))  # diskteki güvenli, UUID tabanlı ad
    mime_type = db.Column(db.String(100))
    size_bytes = db.Column(db.Integer)

    # --- http_transaction tipi alanları ---
    # HAM metin her zaman saklanır (pentester gerçek kanıta ihtiyaç duyar);
    # redakte edilmiş versiyon AYRICA saklanır ve varsayılan görüntüleme/
    # export bunu kullanır. Ham metni görmek açık bir kullanıcı eylemi
    # gerektirir (bkz. backend/redaction.py).
    http_request = db.Column(db.Text)
    http_response = db.Column(db.Text)
    http_request_redacted = db.Column(db.Text)
    http_response_redacted = db.Column(db.Text)

    # AI Vision analizi (opsiyonel — ANTHROPIC_API_KEY ayarlıysa doldurulur, sadece image tipi için)
    ai_analysis = db.Column(db.Text)                # modelin serbest metin açıklaması
    ai_suggested_test_ids = db.Column(db.Text)       # JSON-encoded list[str]
    ai_confidence = db.Column(db.Float)              # 0-100
    ai_error = db.Column(db.Text)                    # analiz denendi ama başarısız olduysa neden

    # İnsan onayı (roadmap'teki Accept/Reject akışı)
    review_status = db.Column(db.String(20), default='pending')  # pending|accepted|rejected|manual
    linked_session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=True)
    linked_test_id = db.Column(db.String(50), nullable=True)
    linked_finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=True)  # Evidence -> Finding ilişkisi

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, include_raw=False):
        suggested = []
        if self.ai_suggested_test_ids:
            try:
                suggested = json.loads(self.ai_suggested_test_ids)
            except Exception:
                suggested = []
        data = {
            'id': self.id,
            'project_id': self.project_id,
            'evidence_type': self.evidence_type or 'image',
            'filename': self.filename,
            'stored_filename': self.stored_filename,
            'mime_type': self.mime_type,
            'size_bytes': self.size_bytes,
            'http_request_redacted': self.http_request_redacted,
            'http_response_redacted': self.http_response_redacted,
            'ai_analysis': self.ai_analysis,
            'ai_suggested_test_ids': suggested,
            'ai_confidence': self.ai_confidence,
            'ai_error': self.ai_error,
            'review_status': self.review_status,
            'linked_session_id': self.linked_session_id,
            'linked_test_id': self.linked_test_id,
            'linked_finding_id': self.linked_finding_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        # Ham (redakte edilmemiş) metin SADECE acikca istendiyse dahil edilir.
        if include_raw:
            data['http_request'] = self.http_request
            data['http_response'] = self.http_response
        return data


class ReconRun(db.Model):
    __tablename__ = 'recon_runs'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=False)
    target = db.Column(db.String(300))
    base_url = db.Column(db.String(300))
    subdomains = db.Column(db.Text)     # JSON-encoded list[str]
    technologies = db.Column(db.Text)   # JSON-encoded list[str]
    endpoints = db.Column(db.Text)      # JSON-encoded list[str]
    apis = db.Column(db.Text)                # JSON-encoded list[str]
    interesting_paths = db.Column(db.Text)   # JSON-encoded list[{path, status}]
    forms = db.Column(db.Text)               # JSON-encoded list
    cookies_present = db.Column(db.Boolean, default=False)
    suggestions = db.Column(db.Text)         # JSON-encoded {test_id: {level, reasons}} -- Test Planı ve
                                              # checklist öncelik rozetlerinin kaynağı; bu run silinene/
                                              # üzerine yenisi gelene kadar projede kalıcıdır.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        def _load(field, default=None):
            try:
                return json.loads(field) if field else (default if default is not None else [])
            except Exception:
                return default if default is not None else []
        return {
            'id': self.id,
            'project_id': self.project_id,
            'target': self.target,
            'baseUrl': self.base_url,
            'subdomains': _load(self.subdomains),
            'technologies': _load(self.technologies),
            'endpoints': _load(self.endpoints),
            'apis': _load(self.apis),
            'interestingPaths': _load(self.interesting_paths),
            'forms': _load(self.forms),
            'cookiesPresent': bool(self.cookies_present),
            'suggestions': _load(self.suggestions, default={}),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    tester_name = db.Column(db.String(100))
    target_url = db.Column(db.String(500))
    target_description = db.Column(db.String(200))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    status = db.Column(db.String(20), default='active')
    
    results = db.relationship('TestResult', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'tester_name': self.tester_name,
            'target_url': self.target_url,
            'target_description': self.target_description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status,
            'total_tests': len(self.results) if self.results else 0,
            'completed_tests': len([r for r in self.results if r.status != 'pending']) if self.results else 0
        }

class TestResult(db.Model):
    __tablename__ = 'test_results'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=False)
    test_id = db.Column(db.String(50), nullable=False)
    category_id = db.Column(db.String(50))
    
    status = db.Column(db.String(20), default='pending')
    severity = db.Column(db.String(20))
    notes = db.Column(db.Text)
    evidence = db.Column(db.Text)
    finding = db.Column(db.Text)
    # Vulnerability Lifecycle: bir bulgunun remediation durumu. Yalnızca
    # 'finding' doluyken anlamlıdır (gerçek bir zafiyet varken). Akış:
    # open -> fixed -> retesting -> resolved  (veya retesting -> open,
    # yani "reopened" — retest sırasında hâlâ mevcutsa). wont_fix ve
    # accepted_risk, open'dan doğrudan geçilebilecek terminal durumlardır.
    finding_status = db.Column(db.String(20), default='open')

    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)

    # --- Kanban (bkz. backend/app.py /kanban rotalari) ---
    # Mevcut TestResult'a katman olarak eklendi -- ayri bir KanbanCard tablosu
    # YOK, ciftli kaynak-of-truth riskini onlemek icin (bir testin "bitti mi"
    # sorusunun tek cevabi hep TestResult olmali). findings_count/evidence_count
    # to_dict()'te route katmaninda hesaplanir, burada saklanmaz (bayatlamasin diye).
    kanban_status = db.Column(db.String(20), default='todo')  # todo|testing|review|confirmed|done
    assigned_to = db.Column(db.String(100))
    time_spent_minutes = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'test_id': self.test_id,
            'category_id': self.category_id,
            'status': self.status,
            'severity': self.severity,
            'notes': self.notes,
            'evidence': self.evidence,
            'finding': self.finding,
            'finding_status': self.finding_status,
            'kanban_status': self.kanban_status or 'todo',
            'assigned_to': self.assigned_to,
            'time_spent_minutes': self.time_spent_minutes or 0,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress': self.progress,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class AIInteractionLog(db.Model):
    """Her AI cagrisinin kaydi (denetlenebilirlik + Faz 5 metrikleri icin).

    Bu tablo daha once 'AI entagration' commit'inde eklenmisti ama app.py'nin
    gelistirme-branch ile yeniden yazilmasi sirasinda rotalari kaybolmustu.
    AI Report Assistant (ai_report_assistant.py) ve finding_analysis.py'nin
    her cagrisi burada loglanir: hangi projede/bulguda, hangi amacla, hangi
    saglayici/modelle, ne kadar surede basarili/basarisiz oldugu."""
    __tablename__ = 'ai_interaction_logs'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('projects.id'), nullable=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=True)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=True)

    # 'finding_description' | 'finding_remediation' | 'rewrite_professional' |
    # 'executive_summary' | 'finding_analysis' ...
    purpose = db.Column(db.String(50), nullable=False)

    provider = db.Column(db.String(30))
    model = db.Column(db.String(80))

    prompt = db.Column(db.Text)
    response = db.Column(db.Text)

    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    latency_ms = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'finding_id': self.finding_id,
            'session_id': self.session_id,
            'purpose': self.purpose,
            'provider': self.provider,
            'model': self.model,
            'success': self.success,
            'error_message': self.error_message,
            'latency_ms': self.latency_ms,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AIProviderSetting(db.Model):
    """Uygulama arayuzunden yonetilen AI sağlayici ayarlari.

    Tasarim ilkesi: API key ASLA duz metin saklanmaz (bkz. crypto_utils.py'nin
    Fernet ile sifrelemesi) ve to_dict() ASLA ham key donmez -- sadece
    maskelenmis hali (crypto_utils.mask_key). Bu tablo bos/yoksa (hic
    sağlayici eklenmemisse ya da hicbiri aktif degilse) ai/factory.py sessizce
    .env / app.config fallback'ine doner -- geriye donuk uyumluluk bozulmaz.
    'provider' unique'tir: her sağlayicinin tek bir kaydi olur, POST bu
    kayda upsert yapar."""
    __tablename__ = 'ai_provider_settings'

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(30), nullable=False, unique=True)  # gemini|openai|anthropic|ollama
    api_key_encrypted = db.Column(db.Text)  # Fernet ile sifreli; ollama icin bos olabilir
    model = db.Column(db.String(100))
    base_url = db.Column(db.String(300))  # sadece ollama icin anlamli
    is_active = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self, masked_key=''):
        return {
            'id': self.id,
            'provider': self.provider,
            'api_key_masked': masked_key,
            'has_key': bool(self.api_key_encrypted),
            'model': self.model,
            'base_url': self.base_url,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }