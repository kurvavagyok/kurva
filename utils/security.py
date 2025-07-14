# JADE Ultimate - Security Utilities
# Security validation and authorization utilities

import re
import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Optional, Any
from functools import wraps
from flask import request, abort, current_app
from flask_login import current_user
import structlog

from models import UserRole

logger = structlog.get_logger()

def validate_target(target: str, scan_type: str) -> bool:
    """
    Validate scan target based on scan type
    """
    try:
        if scan_type == 'network':
            return validate_ip_or_hostname(target)
        elif scan_type == 'web':
            return validate_url_or_hostname(target)
        elif scan_type == 'ssl':
            return validate_hostname_port(target)
        elif scan_type == 'infrastructure':
            return validate_ip_or_hostname(target)
        else:
            return False
    except Exception as e:
        logger.error("Target validation failed", target=target, scan_type=scan_type, error=str(e))
        return False

def validate_ip_or_hostname(target: str) -> bool:
    """
    Validate IP address or hostname
    """
    try:
        # Try to parse as IP address
        ipaddress.ip_address(target)
        
        # Check if it's a private IP (optional restriction)
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_private:
            logger.warning("Private IP address detected", target=target)
            # Allow private IPs for internal scanning
        
        return True
    except ValueError:
        # Not an IP, try as hostname
        return validate_hostname(target)

def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname format
    """
    if not hostname or len(hostname) > 253:
        return False
    
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    
    # Check each label
    allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    labels = hostname.split(".")
    
    if len(labels) < 2:
        return False
    
    for label in labels:
        if not allowed.match(label):
            return False
    
    return True

def validate_url_or_hostname(target: str) -> bool:
    """
    Validate URL or hostname for web scanning
    """
    # If it starts with http/https, validate as URL
    if target.startswith(('http://', 'https://')):
        return validate_url(target)
    else:
        # Validate as hostname
        return validate_hostname(target)

def validate_url(url: str) -> bool:
    """
    Validate URL format
    """
    try:
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Only allow http and https
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Validate hostname part
        return validate_hostname(parsed.netloc.split(':')[0])
    except Exception:
        return False

def validate_hostname_port(target: str) -> bool:
    """
    Validate hostname:port format
    """
    try:
        if ':' in target:
            hostname, port_str = target.rsplit(':', 1)
            port = int(port_str)
            
            # Validate port range
            if not (1 <= port <= 65535):
                return False
            
            return validate_hostname(hostname)
        else:
            return validate_hostname(target)
    except ValueError:
        return False

def sanitize_command(command: str) -> str:
    """
    Sanitize command for safe execution
    """
    # Remove dangerous characters
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r']
    
    for char in dangerous_chars:
        command = command.replace(char, '')
    
    return command.strip()

def validate_file_upload(filename: str, allowed_extensions: set) -> bool:
    """
    Validate uploaded file
    """
    if not filename:
        return False
    
    # Check for path traversal
    if '..' in filename or filename.startswith('/'):
        return False
    
    # Check extension
    if '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    return f'.{extension}' in allowed_extensions

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage
    """
    # Remove path separators and dangerous characters
    sanitized = re.sub(r'[^\w\-_\.]', '', filename)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        sanitized = name[:250] + ('.' + ext if ext else '')
    
    return sanitized

def validate_json_input(data: dict, required_fields: List[str]) -> tuple[bool, Optional[str]]:
    """
    Validate JSON input data
    """
    if not isinstance(data, dict):
        return False, "Invalid JSON format"
    
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
        
        if data[field] is None or (isinstance(data[field], str) and not data[field].strip()):
            return False, f"Field '{field}' cannot be empty"
    
    return True, None

def requires_role(roles: List[str]):
    """
    Decorator to require specific user roles
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            user_role = current_user.role.value if hasattr(current_user.role, 'value') else current_user.role
            
            if user_role not in roles:
                logger.warning("Unauthorized access attempt", 
                              user_id=current_user.id,
                              required_roles=roles,
                              user_role=user_role,
                              endpoint=request.endpoint)
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def requires_permission(permission: str):
    """
    Decorator to require specific permission
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not has_permission(current_user, permission):
                logger.warning("Permission denied", 
                              user_id=current_user.id,
                              permission=permission,
                              endpoint=request.endpoint)
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def has_permission(user, permission: str) -> bool:
    """
    Check if user has specific permission
    """
    role_permissions = {
        'admin': [
            'scan.create', 'scan.read', 'scan.update', 'scan.delete',
            'vulnerability.read', 'vulnerability.update',
            'report.create', 'report.read', 'report.delete',
            'user.create', 'user.read', 'user.update', 'user.delete',
            'system.admin'
        ],
        'analyst': [
            'scan.create', 'scan.read', 'scan.update',
            'vulnerability.read', 'vulnerability.update',
            'report.create', 'report.read'
        ],
        'viewer': [
            'scan.read',
            'vulnerability.read',
            'report.read'
        ],
        'auditor': [
            'scan.read',
            'vulnerability.read',
            'report.read',
            'audit.read'
        ]
    }
    
    user_role = user.role.value if hasattr(user.role, 'value') else user.role
    permissions = role_permissions.get(user_role, [])
    
    return permission in permissions

def validate_scan_config(config: dict, scan_type: str) -> tuple[bool, Optional[str]]:
    """
    Validate scan configuration
    """
    if not isinstance(config, dict):
        return False, "Configuration must be a dictionary"
    
    if scan_type == 'network':
        # Validate network scan options
        valid_options = ['tcp_scan', 'udp_scan', 'service_detection', 'os_detection', 'script_scan', 'timing']
        for key in config.keys():
            if key not in valid_options:
                return False, f"Invalid network scan option: {key}"
        
        # Validate timing option
        if 'timing' in config:
            valid_timing = ['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane']
            if config['timing'] not in valid_timing:
                return False, f"Invalid timing option: {config['timing']}"
    
    elif scan_type == 'web':
        # Validate web scan options
        valid_options = ['ssl_scan', 'directory_scan', 'vulnerability_scan', 'crawl_depth']
        for key in config.keys():
            if key not in valid_options:
                return False, f"Invalid web scan option: {key}"
        
        # Validate crawl depth
        if 'crawl_depth' in config:
            try:
                depth = int(config['crawl_depth'])
                if not (1 <= depth <= 5):
                    return False, "Crawl depth must be between 1 and 5"
            except ValueError:
                return False, "Crawl depth must be a number"
    
    return True, None

def validate_ip_range(ip_range: str) -> bool:
    """
    Validate IP range or CIDR notation
    """
    try:
        # Try CIDR notation
        network = ipaddress.ip_network(ip_range, strict=False)
        
        # Limit network size for security
        if network.num_addresses > 65536:  # /16 maximum
            return False
        
        return True
    except ValueError:
        # Try range notation (e.g., 192.168.1.1-192.168.1.100)
        if '-' in ip_range:
            try:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                # Ensure same IP version
                if start.version != end.version:
                    return False
                
                # Ensure logical order
                if start > end:
                    return False
                
                # Limit range size
                if int(end) - int(start) > 65536:
                    return False
                
                return True
            except ValueError:
                return False
        
        return False

def check_rate_limit(user_id: int, action: str, limit: int, window: int) -> bool:
    """
    Check if user has exceeded rate limit for action
    """
    try:
        import time
        from collections import defaultdict
        
        # Simple in-memory rate limiting (use Redis in production)
        if not hasattr(current_app, 'rate_limit_store'):
            current_app.rate_limit_store = defaultdict(list)
        
        key = f"{user_id}:{action}"
        now = time.time()
        
        # Clean old entries
        current_app.rate_limit_store[key] = [
            timestamp for timestamp in current_app.rate_limit_store[key]
            if now - timestamp < window
        ]
        
        # Check limit
        if len(current_app.rate_limit_store[key]) >= limit:
            return False
        
        # Add current request
        current_app.rate_limit_store[key].append(now)
        return True
    except Exception as e:
        logger.error("Rate limit check failed", error=str(e))
        return True  # Allow request if rate limiting fails

def validate_password_strength(password: str) -> tuple[bool, List[str]]:
    """
    Validate password strength
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check for common passwords
    common_passwords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey'
    ]
    
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    return len(errors) == 0, errors

def validate_email(email: str) -> bool:
    """
    Validate email format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username: str) -> tuple[bool, Optional[str]]:
    """
    Validate username format
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 50:
        return False, "Username must be less than 50 characters long"
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, hyphens, and underscores"
    
    return True, None

def escape_html(text: str) -> str:
    """
    Escape HTML characters to prevent XSS
    """
    if not text:
        return ""
    
    escape_chars = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    for char, escaped in escape_chars.items():
        text = text.replace(char, escaped)
    
    return text

def validate_csv_upload(file_content: str) -> tuple[bool, Optional[str]]:
    """
    Validate CSV file content
    """
    try:
        import csv
        import io
        
        # Check file size (limit to 10MB)
        if len(file_content.encode('utf-8')) > 10 * 1024 * 1024:
            return False, "File size exceeds 10MB limit"
        
        # Try to parse CSV
        csv_reader = csv.reader(io.StringIO(file_content))
        rows = list(csv_reader)
        
        if not rows:
            return False, "CSV file is empty"
        
        # Check maximum rows (limit to 10000)
        if len(rows) > 10000:
            return False, "CSV file contains too many rows (maximum 10000)"
        
        # Check for valid headers
        headers = rows[0] if rows else []
        if not headers:
            return False, "CSV file must have headers"
        
        return True, None
    except Exception as e:
        return False, f"Invalid CSV format: {str(e)}"

def check_sql_injection(input_string: str) -> bool:
    """
    Basic SQL injection detection
    """
    if not input_string:
        return False
    
    # Common SQL injection patterns
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)",
        r"('|(\\')|(;)|(\-\-)|(/\*)|(\*/)|(\bOR\b)|(\bAND\b))",
        r"(\b(INFORMATION_SCHEMA|SYS|MASTER|MSDB|TEMPDB)\b)"
    ]
    
    input_upper = input_string.upper()
    
    for pattern in sql_patterns:
        if re.search(pattern, input_upper):
            return True
    
    return False

def validate_api_key_format(api_key: str) -> bool:
    """
    Validate API key format
    """
    if not api_key:
        return False
    
    # API key should be a valid JWT token or secure token
    if len(api_key) < 32:
        return False
    
    # Check if it's a JWT token
    if api_key.count('.') == 2:
        try:
            import jwt
            # Don't verify signature here, just check format
            jwt.decode(api_key, options={"verify_signature": False})
            return True
        except jwt.InvalidTokenError:
            return False
    
    # Check if it's a secure token (base64 URL safe)
    try:
        import base64
        base64.urlsafe_b64decode(api_key + '==')
        return True
    except Exception:
        return False

