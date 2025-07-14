# JADE Ultimate Security Platform - Configuration
# Enhanced with 2025 state-of-the-art settings

import os
from typing import List, Optional, Dict, Any
import secrets

class Config:
    # Application settings
    APP_NAME = "JADE Ultimate Security Platform"
    VERSION = "1.0.0"
    DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
    
    # Security settings
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
    SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_urlsafe(32))
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_urlsafe(32))
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_urlsafe(32))
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
    
    # Database settings
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:password@localhost:5432/jade_security")
    DATABASE_POOL_SIZE = 20
    DATABASE_MAX_OVERFLOW = 30
    DATABASE_POOL_TIMEOUT = 30
    DATABASE_POOL_RECYCLE = 3600
    
    # Redis settings
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
    
    # Security headers and CORS
    ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")
    
    # AI/LLM API Keys
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    TOGETHER_AI_API_KEY = os.environ.get("TOGETHER_AI_API_KEY", "")
    PERPLEXITY_API_KEY = os.environ.get("PERPLEXITY_API_KEY", "")
    HUGGINGFACE_TOKEN = os.environ.get("HUGGINGFACE_TOKEN", "")
    
    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
    
    # Email settings
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    EMAIL_FROM = os.environ.get("EMAIL_FROM", "noreply@jade-security.com")
    
    # Cloud storage
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
    S3_BUCKET = os.environ.get("S3_BUCKET")
    
    # Monitoring and logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    SENTRY_DSN = os.environ.get("SENTRY_DSN")
    
    # Scan settings
    MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "10"))
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "3600"))  # 1 hour
    MAX_SCAN_TARGETS = int(os.environ.get("MAX_SCAN_TARGETS", "1000"))
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
    
    # AI Model settings
    DEFAULT_LLM_MODEL = os.environ.get("DEFAULT_LLM_MODEL", "gpt-4o")
    LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "4000"))
    LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.1"))
    
    # Vulnerability scoring
    CVSS_CRITICAL_THRESHOLD = 9.0
    CVSS_HIGH_THRESHOLD = 7.0
    CVSS_MEDIUM_THRESHOLD = 4.0
    CVSS_LOW_THRESHOLD = 0.1
    
    # Compliance settings
    COMPLIANCE_STANDARDS = ["ISO27001", "GDPR", "SOC2", "NIST", "PCI-DSS"]
    AUDIT_LOG_RETENTION_DAYS = 2555  # 7 years
    
    # Feature flags
    ENABLE_AI_ANALYSIS = os.environ.get("ENABLE_AI_ANALYSIS", "true").lower() == "true"
    ENABLE_THREAT_INTELLIGENCE = os.environ.get("ENABLE_THREAT_INTELLIGENCE", "true").lower() == "true"
    ENABLE_EMAIL_NOTIFICATIONS = os.environ.get("ENABLE_EMAIL_NOTIFICATIONS", "true").lower() == "true"
    ENABLE_REAL_TIME_MONITORING = os.environ.get("ENABLE_REAL_TIME_MONITORING", "true").lower() == "true"
    
    # File upload settings
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    ALLOWED_FILE_EXTENSIONS = {'.txt', '.csv', '.json', '.xml', '.pdf', '.docx', '.xlsx'}
    UPLOAD_FOLDER = 'uploads'
    
    # Session configuration
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'jade:'
    SESSION_REDIS = None  # Will be set in app initialization
    
    # Celery configuration
    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    
    # Timezone
    TIMEZONE = os.environ.get("TIMEZONE", "UTC")
    
    @staticmethod
    def get_ai_models():
        """Get available AI models configuration"""
        return {
            'openai': {
                'gpt-4o': {
                    'max_tokens': 4000,
                    'temperature': 0.1,
                    'supports_function_calling': True,
                    'supports_vision': True
                },
                'gpt-4o-mini': {
                    'max_tokens': 16000,
                    'temperature': 0.1,
                    'supports_function_calling': True,
                    'supports_vision': True
                }
            },
            'anthropic': {
                'claude-sonnet-4-20250514': {
                    'max_tokens': 8000,
                    'temperature': 0.1,
                    'supports_function_calling': True,
                    'supports_vision': True
                }
            },
            'google': {
                'gemini-2.5-flash': {
                    'max_tokens': 8000,
                    'temperature': 0.1,
                    'supports_function_calling': True,
                    'supports_vision': True
                },
                'gemini-2.5-pro': {
                    'max_tokens': 32000,
                    'temperature': 0.1,
                    'supports_function_calling': True,
                    'supports_vision': True
                }
            }
        }
    
    @staticmethod
    def get_scanner_tools():
        """Get available security scanner tools"""
        return {
            'nmap': {
                'name': 'Nmap',
                'type': 'network',
                'description': 'Network discovery and security auditing',
                'supported_options': ['tcp_scan', 'udp_scan', 'service_detection', 'os_detection', 'script_scan']
            },
            'nikto': {
                'name': 'Nikto',
                'type': 'web',
                'description': 'Web server scanner',
                'supported_options': ['ssl_scan', 'cgi_scan', 'plugin_scan']
            },
            'sqlmap': {
                'name': 'SQLMap',
                'type': 'web',
                'description': 'SQL injection testing',
                'supported_options': ['database_fingerprint', 'data_extraction', 'file_system_access']
            },
            'dirb': {
                'name': 'DirB',
                'type': 'web',
                'description': 'Directory and file brute forcer',
                'supported_options': ['recursive_scan', 'extension_scan', 'custom_wordlist']
            },
            'sslyze': {
                'name': 'SSLyze',
                'type': 'ssl',
                'description': 'SSL/TLS configuration analyzer',
                'supported_options': ['certificate_info', 'cipher_suites', 'vulnerabilities']
            }
        }
    
    @staticmethod
    def get_threat_intelligence_sources():
        """Get threat intelligence sources configuration"""
        return {
            'virustotal': {
                'name': 'VirusTotal',
                'type': 'malware',
                'description': 'Malware and URL analysis',
                'rate_limit': 4,  # requests per minute
                'supported_lookups': ['file_hash', 'url', 'ip', 'domain']
            },
            'shodan': {
                'name': 'Shodan',
                'type': 'network',
                'description': 'Internet-connected device search',
                'rate_limit': 100,  # requests per month
                'supported_lookups': ['ip', 'domain', 'port', 'service']
            },
            'censys': {
                'name': 'Censys',
                'type': 'network',
                'description': 'Internet-wide scanning data',
                'rate_limit': 1000,  # requests per month
                'supported_lookups': ['ip', 'certificate', 'domain']
            },
            'otx': {
                'name': 'AlienVault OTX',
                'type': 'threat',
                'description': 'Open threat intelligence',
                'rate_limit': 10000,  # requests per hour
                'supported_lookups': ['ip', 'domain', 'url', 'file_hash']
            }
        }

# Environment-specific configurations
class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    
class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = "sqlite:///test.db"

# Configuration selector
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
