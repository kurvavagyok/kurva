# JADE Ultimate - Main Routes
# Web interface routes for the security platform

from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import os
import json
import structlog

from app import app, db, limiter
from models import User, Scan, Vulnerability, Alert, Report, UserRole, ScanStatus
from services.ai_service import AIService
from services.scanner_service import ScannerService
from services.threat_intelligence import ThreatIntelligenceService
from services.report_service import ReportService
from services.email_service import EmailService
from utils.security import requires_role, validate_target
from utils.encryption import encrypt_data, decrypt_data
from api.auth import auth_bp
from api.scans import scans_bp
from api.vulnerabilities import vulnerabilities_bp
from api.reports import reports_bp
from api.dashboard import dashboard_bp

logger = structlog.get_logger()

# Register API blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(scans_bp, url_prefix='/api/scans')
app.register_blueprint(vulnerabilities_bp, url_prefix='/api/vulnerabilities')
app.register_blueprint(reports_bp, url_prefix='/api/reports')
app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')

# Initialize services
ai_service = AIService()
scanner_service = ScannerService()
threat_intel_service = ThreatIntelligenceService()
report_service = ReportService()
email_service = EmailService()

@app.route('/')
def index():
    """Main landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """User login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Account is disabled', 'error')
                return render_template('login.html')
            
            # Check for account lockout
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                flash('Account is temporarily locked', 'error')
                return render_template('login.html')
            
            login_user(user, remember=remember)
            user.last_login = datetime.now(timezone.utc)
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            logger.info("User logged in", user_id=user.id, username=user.username)
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            # Handle failed login
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now(timezone.utc).replace(hour=datetime.now().hour + 1)
                db.session.commit()
            
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logger.info("User logged out", user_id=current_user.id)
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    # Get dashboard statistics
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    active_scans = Scan.query.filter_by(user_id=current_user.id, status=ScanStatus.RUNNING).count()
    total_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user.id
    ).count()
    
    # Get recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.created_at.desc()
    ).limit(10).all()
    
    # Get recent vulnerabilities
    recent_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user.id
    ).order_by(Vulnerability.created_at.desc()).limit(10).all()
    
    # Get active alerts
    active_alerts = Alert.query.filter_by(
        user_id=current_user.id,
        status='open'
    ).order_by(Alert.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         total_scans=total_scans,
                         active_scans=active_scans,
                         total_vulnerabilities=total_vulnerabilities,
                         recent_scans=recent_scans,
                         recent_vulnerabilities=recent_vulnerabilities,
                         active_alerts=active_alerts)

@app.route('/scans')
@login_required
def scans():
    """Scans management page"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    scans_query = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.created_at.desc()
    )
    
    # Filter by status if provided
    status_filter = request.args.get('status')
    if status_filter:
        scans_query = scans_query.filter_by(status=status_filter)
    
    # Filter by scan type if provided
    scan_type_filter = request.args.get('scan_type')
    if scan_type_filter:
        scans_query = scans_query.filter_by(scan_type=scan_type_filter)
    
    scans_pagination = scans_query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('scans.html',
                         scans=scans_pagination.items,
                         pagination=scans_pagination,
                         status_filter=status_filter,
                         scan_type_filter=scan_type_filter)

@app.route('/scans/new', methods=['GET', 'POST'])
@login_required
@requires_role(['admin', 'analyst'])
def new_scan():
    """Create new scan"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        scan_type = request.form.get('scan_type')
        target = request.form.get('target')
        
        # Validate inputs
        if not name or not scan_type or not target:
            flash('Name, scan type, and target are required', 'error')
            return render_template('scans/new.html')
        
        # Validate target
        if not validate_target(target, scan_type):
            flash('Invalid target format for selected scan type', 'error')
            return render_template('scans/new.html')
        
        # Create scan
        scan = Scan(
            name=name,
            description=description,
            scan_type=scan_type,
            target=target,
            user_id=current_user.id,
            status=ScanStatus.PENDING
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Queue scan for processing
        try:
            from tasks import process_scan
            process_scan.delay(scan.id)
            flash('Scan queued successfully', 'success')
        except Exception as e:
            logger.error("Failed to queue scan", error=str(e))
            flash('Failed to queue scan', 'error')
        
        return redirect(url_for('scans'))
    
    return render_template('scans/new.html')

@app.route('/scans/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    """View scan details"""
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    
    # Get vulnerabilities for this scan
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).order_by(
        Vulnerability.severity.desc(),
        Vulnerability.created_at.desc()
    ).all()
    
    return render_template('scans/detail.html',
                         scan=scan,
                         vulnerabilities=vulnerabilities)

@app.route('/vulnerabilities')
@login_required
def vulnerabilities():
    """Vulnerabilities management page"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    vulnerabilities_query = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user.id
    ).order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc())
    
    # Filter by severity if provided
    severity_filter = request.args.get('severity')
    if severity_filter:
        vulnerabilities_query = vulnerabilities_query.filter_by(severity=severity_filter)
    
    # Filter by status if provided
    status_filter = request.args.get('status')
    if status_filter:
        vulnerabilities_query = vulnerabilities_query.filter_by(status=status_filter)
    
    vulnerabilities_pagination = vulnerabilities_query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('vulnerabilities.html',
                         vulnerabilities=vulnerabilities_pagination.items,
                         pagination=vulnerabilities_pagination,
                         severity_filter=severity_filter,
                         status_filter=status_filter)

@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
def vulnerability_detail(vuln_id):
    """View vulnerability details"""
    vulnerability = db.session.query(Vulnerability).join(Scan).filter(
        Vulnerability.id == vuln_id,
        Scan.user_id == current_user.id
    ).first_or_404()
    
    return render_template('vulnerabilities/detail.html',
                         vulnerability=vulnerability)

@app.route('/reports')
@login_required
def reports():
    """Reports management page"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    reports_query = Report.query.filter_by(user_id=current_user.id).order_by(
        Report.created_at.desc()
    )
    
    # Filter by report type if provided
    report_type_filter = request.args.get('report_type')
    if report_type_filter:
        reports_query = reports_query.filter_by(report_type=report_type_filter)
    
    reports_pagination = reports_query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('reports.html',
                         reports=reports_pagination.items,
                         pagination=reports_pagination,
                         report_type_filter=report_type_filter)

@app.route('/reports/generate', methods=['GET', 'POST'])
@login_required
@requires_role(['admin', 'analyst'])
def generate_report():
    """Generate new report"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description', '')
        report_type = request.form.get('report_type')
        scan_id = request.form.get('scan_id')
        
        if not title or not report_type:
            flash('Title and report type are required', 'error')
            return render_template('reports/generate.html')
        
        # Validate scan ownership if scan_id provided
        if scan_id:
            scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
            if not scan:
                flash('Invalid scan selected', 'error')
                return render_template('reports/generate.html')
        
        # Create report
        report = Report(
            title=title,
            description=description,
            report_type=report_type,
            scan_id=scan_id if scan_id else None,
            user_id=current_user.id
        )
        
        db.session.add(report)
        db.session.commit()
        
        # Queue report generation
        try:
            from tasks import generate_report_task
            generate_report_task.delay(report.id)
            flash('Report generation queued successfully', 'success')
        except Exception as e:
            logger.error("Failed to queue report generation", error=str(e))
            flash('Failed to queue report generation', 'error')
        
        return redirect(url_for('reports'))
    
    # Get user's scans for the form
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.created_at.desc()
    ).all()
    
    return render_template('reports/generate.html', user_scans=user_scans)

@app.route('/reports/<int:report_id>')
@login_required
def report_detail(report_id):
    """View report details"""
    report = Report.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    return render_template('reports/detail.html', report=report)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html', user=current_user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    
    if not first_name or not last_name or not email:
        flash('All fields are required', 'error')
        return redirect(url_for('profile'))
    
    # Check if email is already taken by another user
    existing_user = User.query.filter_by(email=email).filter(User.id != current_user.id).first()
    if existing_user:
        flash('Email is already taken', 'error')
        return redirect(url_for('profile'))
    
    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.email = email
    
    db.session.commit()
    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'error')
        return redirect(url_for('profile'))
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('profile'))
    
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long', 'error')
        return redirect(url_for('profile'))
    
    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/admin')
@login_required
@requires_role(['admin'])
def admin():
    """Admin dashboard"""
    # Get system statistics
    total_users = User.query.count()
    total_scans = Scan.query.count()
    total_vulnerabilities = Vulnerability.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    
    # Get recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_scans=total_scans,
                         total_vulnerabilities=total_vulnerabilities,
                         active_users=active_users,
                         recent_users=recent_users,
                         recent_scans=recent_scans)

@app.route('/admin/users')
@login_required
@requires_role(['admin'])
def admin_users():
    """Admin users management"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    users_query = User.query.order_by(User.created_at.desc())
    
    # Filter by role if provided
    role_filter = request.args.get('role')
    if role_filter:
        users_query = users_query.filter_by(role=role_filter)
    
    # Filter by status if provided
    status_filter = request.args.get('status')
    if status_filter == 'active':
        users_query = users_query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        users_query = users_query.filter_by(is_active=False)
    
    users_pagination = users_query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/users.html',
                         users=users_pagination.items,
                         pagination=users_pagination,
                         role_filter=role_filter,
                         status_filter=status_filter)

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@requires_role(['admin'])
def toggle_user_status(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot deactivate your own account', 'error')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}', 'success')
    
    return redirect(url_for('admin_users'))

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit exceeded handler"""
    return render_template('errors/429.html'), 429

@app.errorhandler(401)
def unauthorized_handler(e):
    """Unauthorized access handler"""
    return render_template('errors/401.html'), 401

# JADE ULTIMATE - Routes
# Import all route modules to register them with the Flask app

from api import auth, scans, vulnerabilities, reports, dashboard

# Routes are automatically registered when modules are imported
# Each API module registers its routes with the Flask app instance
