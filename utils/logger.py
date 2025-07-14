# JADE Ultimate - Logging Utilities
# Comprehensive logging configuration and utilities

import os
import sys
import logging
import structlog
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import json
import traceback

from config import Config

def setup_logging():
    """
    Setup structured logging for JADE Ultimate
    """
    # Create logs directory if it doesn't exist
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging level
    log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    
    # Configure standard logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_dir / 'jade_ultimate.log')
        ]
    )
    
    # Configure structlog
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
            add_custom_fields,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Create security audit logger
    security_logger = logging.getLogger('security_audit')
    security_handler = logging.FileHandler(log_dir / 'security_audit.log')
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
    ))
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.INFO)
    
    # Create error logger
    error_logger = logging.getLogger('error')
    error_handler = logging.FileHandler(log_dir / 'errors.log')
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s - ERROR - %(name)s - %(levelname)s - %(message)s'
    ))
    error_logger.addHandler(error_handler)
    error_logger.setLevel(logging.ERROR)
    
    # Create access logger
    access_logger = logging.getLogger('access')
    access_handler = logging.FileHandler(log_dir / 'access.log')
    access_handler.setFormatter(logging.Formatter(
        '%(asctime)s - ACCESS - %(message)s'
    ))
    access_logger.addHandler(access_handler)
    access_logger.setLevel(logging.INFO)

def add_custom_fields(logger, method_name, event_dict):
    """
    Add custom fields to log entries
    """
    event_dict['application'] = 'jade_ultimate'
    event_dict['version'] = '1.0.0'
    event_dict['creator'] = 'Kollár Sándor'
    
    # Add request ID if available
    from flask import has_request_context, g
    if has_request_context():
        event_dict['request_id'] = getattr(g, 'request_id', 'unknown')
    
    return event_dict

class SecurityAuditLogger:
    """
    Specialized logger for security audit events
    """
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
    
    def log_authentication_attempt(self, username: str, ip_address: str, success: bool, failure_reason: Optional[str] = None):
        """
        Log authentication attempt
        """
        event = {
            'event_type': 'authentication_attempt',
            'username': username,
            'ip_address': ip_address,
            'success': success,
            'failure_reason': failure_reason,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if success:
            self.logger.info(f"Authentication successful for user {username} from {ip_address}")
        else:
            self.logger.warning(f"Authentication failed for user {username} from {ip_address}: {failure_reason}")
    
    def log_authorization_failure(self, user_id: int, resource: str, action: str, ip_address: str):
        """
        Log authorization failure
        """
        event = {
            'event_type': 'authorization_failure',
            'user_id': user_id,
            'resource': resource,
            'action': action,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.warning(f"Authorization failed for user {user_id} accessing {resource} from {ip_address}")
    
    def log_privilege_escalation(self, user_id: int, old_role: str, new_role: str, admin_user_id: int):
        """
        Log privilege escalation
        """
        event = {
            'event_type': 'privilege_escalation',
            'user_id': user_id,
            'old_role': old_role,
            'new_role': new_role,
            'admin_user_id': admin_user_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"Privilege escalation: User {user_id} role changed from {old_role} to {new_role} by admin {admin_user_id}")
    
    def log_data_access(self, user_id: int, resource_type: str, resource_id: int, action: str):
        """
        Log sensitive data access
        """
        event = {
            'event_type': 'data_access',
            'user_id': user_id,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'action': action,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"Data access: User {user_id} {action} {resource_type} {resource_id}")
    
    def log_security_event(self, event_type: str, user_id: Optional[int], description: str, severity: str = 'info'):
        """
        Log general security event
        """
        event = {
            'event_type': event_type,
            'user_id': user_id,
            'description': description,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if severity == 'critical':
            self.logger.critical(f"SECURITY EVENT: {event_type} - {description}")
        elif severity == 'error':
            self.logger.error(f"SECURITY EVENT: {event_type} - {description}")
        elif severity == 'warning':
            self.logger.warning(f"SECURITY EVENT: {event_type} - {description}")
        else:
            self.logger.info(f"SECURITY EVENT: {event_type} - {description}")

class AccessLogger:
    """
    Specialized logger for access events
    """
    
    def __init__(self):
        self.logger = logging.getLogger('access')
    
    def log_request(self, method: str, path: str, ip_address: str, user_id: Optional[int], 
                   status_code: int, response_time: float, user_agent: str):
        """
        Log HTTP request
        """
        log_entry = {
            'method': method,
            'path': path,
            'ip_address': ip_address,
            'user_id': user_id,
            'status_code': status_code,
            'response_time': response_time,
            'user_agent': user_agent,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(json.dumps(log_entry))
    
    def log_api_request(self, endpoint: str, method: str, ip_address: str, api_key: Optional[str],
                       status_code: int, response_time: float):
        """
        Log API request
        """
        log_entry = {
            'type': 'api_request',
            'endpoint': endpoint,
            'method': method,
            'ip_address': ip_address,
            'api_key': api_key[:10] + '...' if api_key else None,
            'status_code': status_code,
            'response_time': response_time,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(json.dumps(log_entry))

class ErrorLogger:
    """
    Specialized logger for error events
    """
    
    def __init__(self):
        self.logger = logging.getLogger('error')
    
    def log_exception(self, exception: Exception, context: Dict[str, Any] = None):
        """
        Log exception with context
        """
        error_info = {
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'traceback': traceback.format_exc(),
            'context': context or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.error(json.dumps(error_info))
    
    def log_validation_error(self, field: str, value: Any, error_message: str, user_id: Optional[int] = None):
        """
        Log validation error
        """
        error_info = {
            'error_type': 'validation_error',
            'field': field,
            'value': str(value)[:100],  # Truncate long values
            'error_message': error_message,
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.error(json.dumps(error_info))
    
    def log_database_error(self, operation: str, table: str, error: Exception, query: Optional[str] = None):
        """
        Log database error
        """
        error_info = {
            'error_type': 'database_error',
            'operation': operation,
            'table': table,
            'error_message': str(error),
            'query': query[:500] if query else None,  # Truncate long queries
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.error(json.dumps(error_info))

class PerformanceLogger:
    """
    Logger for performance monitoring
    """
    
    def __init__(self):
        self.logger = logging.getLogger('performance')
        
        # Create performance log file
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        handler = logging.FileHandler(log_dir / 'performance.log')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - PERFORMANCE - %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_scan_performance(self, scan_id: int, scan_type: str, duration: float, 
                           targets_scanned: int, vulnerabilities_found: int):
        """
        Log scan performance metrics
        """
        perf_data = {
            'metric_type': 'scan_performance',
            'scan_id': scan_id,
            'scan_type': scan_type,
            'duration': duration,
            'targets_scanned': targets_scanned,
            'vulnerabilities_found': vulnerabilities_found,
            'scan_rate': targets_scanned / duration if duration > 0 else 0,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(json.dumps(perf_data))
    
    def log_ai_performance(self, model_name: str, operation: str, duration: float, 
                          tokens_used: int, success: bool):
        """
        Log AI model performance
        """
        perf_data = {
            'metric_type': 'ai_performance',
            'model_name': model_name,
            'operation': operation,
            'duration': duration,
            'tokens_used': tokens_used,
            'success': success,
            'tokens_per_second': tokens_used / duration if duration > 0 else 0,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(json.dumps(perf_data))
    
    def log_database_performance(self, operation: str, table: str, duration: float, rows_affected: int):
        """
        Log database performance
        """
        perf_data = {
            'metric_type': 'database_performance',
            'operation': operation,
            'table': table,
            'duration': duration,
            'rows_affected': rows_affected,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(json.dumps(perf_data))

class LogManager:
    """
    Central log manager for JADE Ultimate
    """
    
    def __init__(self):
        self.security_logger = SecurityAuditLogger()
        self.access_logger = AccessLogger()
        self.error_logger = ErrorLogger()
        self.performance_logger = PerformanceLogger()
        self.main_logger = structlog.get_logger()
    
    def get_security_logger(self) -> SecurityAuditLogger:
        """Get security audit logger"""
        return self.security_logger
    
    def get_access_logger(self) -> AccessLogger:
        """Get access logger"""
        return self.access_logger
    
    def get_error_logger(self) -> ErrorLogger:
        """Get error logger"""
        return self.error_logger
    
    def get_performance_logger(self) -> PerformanceLogger:
        """Get performance logger"""
        return self.performance_logger
    
    def get_main_logger(self):
        """Get main structured logger"""
        return self.main_logger

# Global log manager instance
log_manager = LogManager()

# Convenience functions
def get_security_logger() -> SecurityAuditLogger:
    """Get security audit logger"""
    return log_manager.get_security_logger()

def get_access_logger() -> AccessLogger:
    """Get access logger"""
    return log_manager.get_access_logger()

def get_error_logger() -> ErrorLogger:
    """Get error logger"""
    return log_manager.get_error_logger()

def get_performance_logger() -> PerformanceLogger:
    """Get performance logger"""
    return log_manager.get_performance_logger()

def get_logger(name: str = None):
    """Get structured logger"""
    if name:
        return structlog.get_logger(name)
    return log_manager.get_main_logger()
