# JADE ULTIMATE - Models for Security Platform
# Database models for users, scans, vulnerabilities, and AI analysis

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy import text
import uuid
import enum

from app import db

class UserRole(enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"

class ScanStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertStatus(enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CLOSED = "closed"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime(timezone=True))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime(timezone=True))
    two_factor_secret = db.Column(db.String(32))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    preferences = db.Column(JSONB, default=dict)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == UserRole.ADMIN
    
    def is_analyst(self):
        return self.role in [UserRole.ADMIN, UserRole.ANALYST]
    
    def can_scan(self):
        return self.role in [UserRole.ADMIN, UserRole.ANALYST]
    
    def can_view_reports(self):
        return self.role in [UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER, UserRole.AUDITOR]
    
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role.value,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    scan_type = db.Column(db.String(50), nullable=False)  # network, web, infrastructure, api
    target = db.Column(db.String(500), nullable=False)
    status = db.Column(db.Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    progress = db.Column(db.Integer, default=0)
    
    # Scan configuration
    config = db.Column(JSONB, default=dict)
    scan_options = db.Column(JSONB, default=dict)
    
    # Results and metadata
    results = db.Column(JSONB, default=dict)
    scan_metadata = db.Column(JSONB, default=dict)
    error_message = db.Column(db.Text)
    
    # Timing
    started_at = db.Column(db.DateTime(timezone=True))
    completed_at = db.Column(db.DateTime(timezone=True))
    duration = db.Column(db.Integer)  # seconds
    
    # Metrics
    targets_found = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    critical_vulns = db.Column(db.Integer, default=0)
    high_vulns = db.Column(db.Integer, default=0)
    medium_vulns = db.Column(db.Integer, default=0)
    low_vulns = db.Column(db.Integer, default=0)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def update_vulnerability_counts(self):
        """Update vulnerability counts from related vulnerabilities"""
        vulns = self.vulnerabilities.all()
        self.vulnerabilities_found = len(vulns)
        self.critical_vulns = len([v for v in vulns if v.severity == VulnerabilitySeverity.CRITICAL])
        self.high_vulns = len([v for v in vulns if v.severity == VulnerabilitySeverity.HIGH])
        self.medium_vulns = len([v for v in vulns if v.severity == VulnerabilitySeverity.MEDIUM])
        self.low_vulns = len([v for v in vulns if v.severity == VulnerabilitySeverity.LOW])
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': str(self.scan_id),
            'name': self.name,
            'description': self.description,
            'scan_type': self.scan_type,
            'target': self.target,
            'status': self.status.value,
            'progress': self.progress,
            'config': self.config,
            'results': self.results,
            'metadata': self.scan_metadata,
            'error_message': self.error_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'targets_found': self.targets_found,
            'vulnerabilities_found': self.vulnerabilities_found,
            'critical_vulns': self.critical_vulns,
            'high_vulns': self.high_vulns,
            'medium_vulns': self.medium_vulns,
            'low_vulns': self.low_vulns,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Scan {self.name}>'

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    vuln_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum(VulnerabilitySeverity), nullable=False)
    
    # Classification
    cve_id = db.Column(db.String(20), index=True)
    cwe_id = db.Column(db.String(20), index=True)
    category = db.Column(db.String(100), nullable=False)
    owasp_category = db.Column(db.String(100))
    
    # Target information
    target_host = db.Column(db.String(255))
    target_port = db.Column(db.Integer)
    target_service = db.Column(db.String(100))
    target_path = db.Column(db.String(500))
    
    # Vulnerability details
    proof_of_concept = db.Column(db.Text)
    impact = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    references = db.Column(JSONB, default=list)
    
    # Scoring
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(200))
    risk_score = db.Column(db.Float)
    
    # Status and remediation
    status = db.Column(db.String(50), default='open')
    false_positive = db.Column(db.Boolean, default=False)
    remediated = db.Column(db.Boolean, default=False)
    remediation_date = db.Column(db.DateTime(timezone=True))
    remediation_notes = db.Column(db.Text)
    
    # AI Analysis
    ai_analysis = db.Column(JSONB, default=dict)
    ai_confidence = db.Column(db.Float)
    ai_tags = db.Column(JSONB, default=list)
    
    # Raw data
    raw_output = db.Column(db.Text)
    scanner_data = db.Column(JSONB, default=dict)
    
    # Foreign keys
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    def severity_score(self):
        """Return numeric severity score for sorting"""
        scores = {
            VulnerabilitySeverity.CRITICAL: 5,
            VulnerabilitySeverity.HIGH: 4,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 1
        }
        return scores.get(self.severity, 0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'vuln_id': str(self.vuln_id),
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'category': self.category,
            'owasp_category': self.owasp_category,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'target_service': self.target_service,
            'target_path': self.target_path,
            'proof_of_concept': self.proof_of_concept,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'references': self.references,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'risk_score': self.risk_score,
            'status': self.status,
            'false_positive': self.false_positive,
            'remediated': self.remediated,
            'remediation_date': self.remediation_date.isoformat() if self.remediation_date else None,
            'remediation_notes': self.remediation_notes,
            'ai_analysis': self.ai_analysis,
            'ai_confidence': self.ai_confidence,
            'ai_tags': self.ai_tags,
            'scan_id': self.scan_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.title}>'

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum(VulnerabilitySeverity), nullable=False)
    status = db.Column(db.Enum(AlertStatus), nullable=False, default=AlertStatus.OPEN)
    
    # Alert metadata
    alert_type = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100))
    tags = db.Column(JSONB, default=list)
    
    # Context data
    context = db.Column(JSONB, default=dict)
    evidence = db.Column(JSONB, default=dict)
    affected_assets = db.Column(JSONB, default=list)
    
    # Response tracking
    acknowledged_at = db.Column(db.DateTime(timezone=True))
    resolved_at = db.Column(db.DateTime(timezone=True))
    response_time = db.Column(db.Integer)  # seconds
    resolution_notes = db.Column(db.Text)
    
    # Notification tracking
    notifications_sent = db.Column(JSONB, default=list)
    escalated = db.Column(db.Boolean, default=False)
    escalation_level = db.Column(db.Integer, default=0)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': str(self.alert_id),
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'alert_type': self.alert_type,
            'source': self.source,
            'category': self.category,
            'tags': self.tags,
            'context': self.context,
            'evidence': self.evidence,
            'affected_assets': self.affected_assets,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'response_time': self.response_time,
            'resolution_notes': self.resolution_notes,
            'escalated': self.escalated,
            'escalation_level': self.escalation_level,
            'user_id': self.user_id,
            'scan_id': self.scan_id,
            'vulnerability_id': self.vulnerability_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Alert {self.title}>'

class AIModel(db.Model):
    __tablename__ = 'ai_models'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    provider = db.Column(db.String(50), nullable=False)
    model_type = db.Column(db.String(50), nullable=False)
    version = db.Column(db.String(50))
    
    # Configuration
    api_endpoint = db.Column(db.String(500))
    max_tokens = db.Column(db.Integer, default=4000)
    temperature = db.Column(db.Float, default=0.1)
    top_p = db.Column(db.Float, default=1.0)
    
    # Capabilities
    supports_function_calling = db.Column(db.Boolean, default=False)
    supports_vision = db.Column(db.Boolean, default=False)
    supports_code_generation = db.Column(db.Boolean, default=False)
    
    # Status and metrics
    is_active = db.Column(db.Boolean, default=True)
    total_requests = db.Column(db.Integer, default=0)
    successful_requests = db.Column(db.Integer, default=0)
    failed_requests = db.Column(db.Integer, default=0)
    avg_response_time = db.Column(db.Float, default=0.0)
    
    # Rate limiting
    rate_limit_per_minute = db.Column(db.Integer, default=60)
    rate_limit_per_hour = db.Column(db.Integer, default=3600)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'provider': self.provider,
            'model_type': self.model_type,
            'version': self.version,
            'is_active': self.is_active,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'avg_response_time': self.avg_response_time,
            'supports_function_calling': self.supports_function_calling,
            'supports_vision': self.supports_vision,
            'supports_code_generation': self.supports_code_generation,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<AIModel {self.name}>'

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False, index=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    report_type = db.Column(db.String(50), nullable=False)  # executive, technical, compliance
    format = db.Column(db.String(20), nullable=False, default='html')  # html, pdf, json
    
    # Content
    content = db.Column(JSONB, default=dict)
    executive_summary = db.Column(db.Text)
    findings = db.Column(JSONB, default=list)
    recommendations = db.Column(JSONB, default=list)
    
    # Generation metadata
    template_used = db.Column(db.String(100))
    ai_generated = db.Column(db.Boolean, default=False)
    ai_model_used = db.Column(db.String(100))
    generation_time = db.Column(db.Float)
    
    # File storage
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    file_hash = db.Column(db.String(128))
    
    # Access control
    is_public = db.Column(db.Boolean, default=False)
    access_level = db.Column(db.String(20), default='internal')
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'id': self.id,
            'report_id': str(self.report_id),
            'title': self.title,
            'description': self.description,
            'report_type': self.report_type,
            'format': self.format,
            'content': self.content,
            'executive_summary': self.executive_summary,
            'findings': self.findings,
            'recommendations': self.recommendations,
            'template_used': self.template_used,
            'ai_generated': self.ai_generated,
            'ai_model_used': self.ai_model_used,
            'generation_time': self.generation_time,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'is_public': self.is_public,
            'access_level': self.access_level,
            'user_id': self.user_id,
            'scan_id': self.scan_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Report {self.title}>'

# Index definitions for better performance
db.Index('idx_users_email', User.email)
db.Index('idx_users_username', User.username)
db.Index('idx_scans_user_id', Scan.user_id)
db.Index('idx_scans_status', Scan.status)
db.Index('idx_scans_created_at', Scan.created_at)
db.Index('idx_vulnerabilities_scan_id', Vulnerability.scan_id)
db.Index('idx_vulnerabilities_severity', Vulnerability.severity)
db.Index('idx_vulnerabilities_cve_id', Vulnerability.cve_id)
db.Index('idx_alerts_user_id', Alert.user_id)
db.Index('idx_alerts_status', Alert.status)
db.Index('idx_alerts_severity', Alert.severity)
db.Index('idx_reports_user_id', Report.user_id)
db.Index('idx_reports_scan_id', Report.scan_id)
