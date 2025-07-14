# JADE ULTIMATE - State-of-the-Art AI Security Platform 2025
# Enhanced Enterprise Security Platform with Advanced AI Integration
# Created by Kollár Sándor - Digital Fingerprint Embedded

import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from redis import Redis
import structlog

# --- INDESTRUCTIBLE DIGITAL FINGERPRINT ---
DIGITAL_FINGERPRINT = "Jade made by Kollár Sándor"
CREATOR_SIGNATURE = "SmFkZSBtYWRlIGJ5IEtvbGzDoXIgU8OhbmRvcg=="
CREATOR_HASH = "a7b4c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5"

# Configure structured logging
logging.basicConfig(level=logging.DEBUG)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
mail = Mail()
jwt = JWTManager()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "jade-ultimate-secret-key-2025")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configuration
app.config.update(
    # Database
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "postgresql://postgres:password@localhost:5432/jade_security"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_size": 20,
        "max_overflow": 30,
        "pool_timeout": 30,
    },
    
    # JWT
    JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY", "jwt-secret-key-2025"),
    JWT_ACCESS_TOKEN_EXPIRES=1800,  # 30 minutes
    JWT_REFRESH_TOKEN_EXPIRES=604800,  # 7 days
    
    # Mail
    MAIL_SERVER=os.environ.get("SMTP_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.environ.get("SMTP_PORT", 587)),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get("SMTP_USERNAME", ""),
    MAIL_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
    MAIL_DEFAULT_SENDER=os.environ.get("EMAIL_FROM", "noreply@jade-security.com"),
    
    # Security
    WTF_CSRF_ENABLED=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
    
    # Rate limiting
    RATELIMIT_STORAGE_URL=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    RATELIMIT_DEFAULT="100 per minute",
    
    # File uploads
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
    UPLOAD_FOLDER='uploads',
    ALLOWED_EXTENSIONS={'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'json', 'xml'},
)

# Initialize extensions with app
db.init_app(app)
login_manager.init_app(app)
mail.init_app(app)
jwt.init_app(app)

# CORS configuration
CORS(app, origins=["*"], supports_credentials=True)

# Rate limiting
try:
    redis_client = Redis.from_url(app.config['RATELIMIT_STORAGE_URL'])
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        storage_uri=app.config['RATELIMIT_STORAGE_URL'],
        default_limits=["1000 per day", "100 per hour"]
    )
except Exception as e:
    logging.warning(f"Could not initialize rate limiter: {e}")
    limiter = None

# Login manager configuration
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Create tables and initialize app
with app.app_context():
    # Import models to ensure they're registered
    import models
    
    # Create all tables
    db.create_all()
    
    # Log startup
    logger = structlog.get_logger()
    logger.info("jade_startup", 
                creator=DIGITAL_FINGERPRINT, 
                version="ULTIMATE-2025",
                database_url=app.config['SQLALCHEMY_DATABASE_URI'][:50] + "...")

# Global request middleware
@app.before_request
def before_request():
    """Add security headers and logging to all requests"""
    from flask import request, g
    import time
    
    g.start_time = time.time()
    g.creator = CREATOR_SIGNATURE
    
    # Log request
    logger = structlog.get_logger()
    logger.info("request_start",
                method=request.method,
                path=request.path,
                user_agent=request.headers.get('User-Agent', ''),
                ip=request.remote_addr)

@app.after_request
def after_request(response):
    """Add security headers and log response"""
    from flask import g
    import time
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src 'self' data: https:; font-src 'self' https: data:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Creator'] = CREATOR_SIGNATURE
    
    # Log response
    if hasattr(g, 'start_time'):
        process_time = time.time() - g.start_time
        response.headers['X-Process-Time'] = str(process_time)
        
        logger = structlog.get_logger()
        logger.info("request_end",
                    status_code=response.status_code,
                    process_time=process_time,
                    response_size=len(response.get_data()))
    
    return response

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    from flask import render_template
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    from flask import render_template
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    from flask import render_template
    return render_template('errors/403.html'), 403

# Health check endpoint
@app.route('/health')
def health_check():
    import time
    return {
        "status": "healthy",
        "version": "1.0.0",
        "creator": DIGITAL_FINGERPRINT,
        "timestamp": time.time(),
        "database": "connected" if db.engine else "disconnected"
    }

# Root endpoint
@app.route('/api')
def api_root():
    return {
        "message": "JADE Ultimate Security Platform API",
        "version": "1.0.0",
        "creator": DIGITAL_FINGERPRINT,
        "endpoints": {
            "auth": "/api/auth",
            "scans": "/api/scans",
            "vulnerabilities": "/api/vulnerabilities",
            "reports": "/api/reports",
            "dashboard": "/api/dashboard",
            "health": "/health"
        }
    }
