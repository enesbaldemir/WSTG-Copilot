from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import json

db = SQLAlchemy()

class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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

    # ---- Faz 5: Deneysel A/B karşılaştırma ----
    # 'ai_assisted' | 'control' | None (çalışmaya dahil değil)
    study_group = db.Column(db.String(20), nullable=True)
    
    results = db.relationship('TestResult', backref='session', lazy=True, cascade='all, delete-orphan')
    notes = db.relationship('Note', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
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
            'study_group': self.study_group,
            'total_tests': len(self.results) if self.results else 0,
            'completed_tests': len([r for r in self.results if r.status != 'pending']) if self.results else 0,
            'total_notes': len(self.notes) if self.notes else 0
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
    
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)
    
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
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress': self.progress,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Note(db.Model):
    """
    Serbest formatlı not defteri kaydı. TestResult'taki alan (her checklist
    maddesinin kendi 'notes/finding' kutusu) ile karışmasın diye ayrı bir
    tablo: burası oturuma (siteye) bağlı, dilenirse belirli bir WSTG test
    maddesine de bağlanabilen, görsel/kanıt ekli genel bir not defteridir.
    test_id NULL ise bu genel bir nottur (belirli bir test maddesiyle
    ilişkilendirilmemiştir).
    """
    __tablename__ = 'notes'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=False)
    test_id = db.Column(db.String(50), nullable=True)
    category_id = db.Column(db.String(50), nullable=True)

    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    severity = db.Column(db.String(20), default='info')
    # JSON-encoded list of {"name": str, "data": "data:image/...;base64,..."}
    images = db.Column(db.Text)

    # ---- Faz 1: CVSS 3.1 + CWE alanları ----
    cvss_vector = db.Column(db.String(120), nullable=True)   # örn. "CVSS:3.1/AV:N/AC:L/..."
    cvss_score = db.Column(db.Float, nullable=True)           # backend'de cvss.calculate() ile hesaplanır
    cvss_rating = db.Column(db.String(20), nullable=True)     # none|low|medium|high|critical
    cwe_id = db.Column(db.String(20), nullable=True)          # örn. "CWE-89"
    cwe_name = db.Column(db.String(200), nullable=True)       # örn. "SQL Injection"

    # ---- Faz 5: Deneysel A/B karşılaştırma (ground-truth etiketleme) ----
    # None = henüz değerlendirilmedi, True = false-positive olarak doğrulandı,
    # False = gerçek/geçerli bulgu olarak doğrulandı. AI'nin false_positive_likelihood
    # TAHMİNİNDEN FARKLI: bu alan pentester'ın kendi nihai kararıdır.
    is_false_positive = db.Column(db.Boolean, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        try:
            images = json.loads(self.images) if self.images else []
        except (TypeError, ValueError):
            images = []
        return {
            'id': self.id,
            'session_id': self.session_id,
            'test_id': self.test_id,
            'category_id': self.category_id,
            'title': self.title,
            'content': self.content,
            'severity': self.severity,
            'images': images,
            'cvss_vector': self.cvss_vector,
            'cvss_score': self.cvss_score,
            'cvss_rating': self.cvss_rating,
            'cwe_id': self.cwe_id,
            'cwe_name': self.cwe_name,
            'is_false_positive': self.is_false_positive,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AIInteractionLog(db.Model):
    """
    Her AI cagrisinin kaydi. Faz 2-4'teki (bulgu analizi, sonraki test
    onerisi, otomatik rapor) her istek burada loglanir. Faz 5'teki
    "AI'li vs AI'siz" deneysel karsilastirmanin ham verisi bu tablodur:
    yanit suresi, basari/hata orani, hangi oturumda hangi amacla
    kac kez cagrildigi gibi metrikler dogrudan buradan hesaplanir.
    """
    __tablename__ = 'ai_interaction_logs'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=True)

    # 'next_test_suggestion' | 'finding_analysis' | 'false_positive_check' |
    # 'report_generation' | 'ping' ...
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
            'session_id': self.session_id,
            'purpose': self.purpose,
            'provider': self.provider,
            'model': self.model,
            'success': self.success,
            'error_message': self.error_message,
            'latency_ms': self.latency_ms,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
