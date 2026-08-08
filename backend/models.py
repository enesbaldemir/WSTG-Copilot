from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

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
    
    results = db.relationship('TestResult', backref='session', lazy=True, cascade='all, delete-orphan')
    
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