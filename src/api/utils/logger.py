"""
Centralized Logging System for CloudSentinel
Provides structured, configurable logging for backend services and Celery tasks.
"""

import os
import sys
import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union
from contextlib import contextmanager
import traceback
import functools

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

class SecurityFilter(logging.Filter):
    """Filter to sanitize sensitive information from logs"""
    
    SENSITIVE_KEYS = {
        'password', 'secret', 'token', 'key', 'auth', 'credential',
        'api_key', 'access_key', 'secret_key', 'private_key',
        'client_secret', 'webhook_secret', 'encryption_key'
    }
    
    def filter(self, record):
        """Filter out sensitive information from log records"""
        if hasattr(record, 'msg') and isinstance(record.msg, (dict, str)):
            record.msg = self._sanitize_data(record.msg)
        
        if hasattr(record, 'args') and record.args:
            record.args = tuple(self._sanitize_data(arg) for arg in record.args)
        
        return True
    
    def _sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize sensitive data"""
        if isinstance(data, dict):
            return {
                key: "***REDACTED***" if self._is_sensitive_key(key) else self._sanitize_data(value)
                for key, value in data.items()
            }
        elif isinstance(data, (list, tuple)):
            return type(data)(self._sanitize_data(item) for item in data)
        elif isinstance(data, str):
            return self._sanitize_string(data)
        return data
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key contains sensitive information"""
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS)
    
    def _sanitize_string(self, text: str) -> str:
        """Sanitize sensitive patterns in strings"""
        # Basic pattern matching for common secrets
        import re
        
        # AWS keys pattern
        text = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', text)
        text = re.sub(r'[A-Za-z0-9/+=]{40}', '***REDACTED***', text)
        
        # JWT tokens
        text = re.sub(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', '***JWT_REDACTED***', text)
        
        return text

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = os.uname().nodename if hasattr(os, 'uname') else 'unknown'
    
    def format(self, record):
        """Format log record as JSON"""
        log_entry = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process': record.process,
            'thread': record.thread,
            'hostname': self.hostname,
            'service': 'cloudsentinel'
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'exc_info', 'exc_text',
                          'stack_info', 'getMessage'):
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)

class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[91m',  # Bright Red
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        """Format log record with colors"""
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset_color = self.COLORS['RESET']
        
        # Color the level name
        record.levelname = f"{log_color}{record.levelname}{reset_color}"
        
        return super().format(record)

class CloudSentinelLogger:
    """Main logger class for CloudSentinel"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._load_config()
        self._loggers: Dict[str, logging.Logger] = {}
        self._setup_root_logger()
        
        if STRUCTLOG_AVAILABLE and self.config.get('enable_structured_logging', True):
            self._setup_structlog()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load logging configuration from environment variables"""
        return {
            'level': os.getenv('LOG_LEVEL', 'INFO').upper(),
            'format': os.getenv('LOG_FORMAT', 'json').lower(),
            'file_path': os.getenv('LOG_FILE_PATH'),
            'max_file_size': os.getenv('LOG_MAX_FILE_SIZE', '10MB'),
            'backup_count': int(os.getenv('LOG_BACKUP_COUNT', '5')),
            'rotation': os.getenv('LOG_ROTATION', 'size').lower(),
            'enable_structured_logging': os.getenv('ENABLE_STRUCTURED_LOGGING', 'true').lower() == 'true',
            'enable_request_logging': os.getenv('ENABLE_REQUEST_LOGGING', 'true').lower() == 'true',
            'enable_console': os.getenv('ENABLE_CONSOLE_LOGGING', 'true').lower() == 'true',
        }
    
    def _setup_root_logger(self):
        """Setup the root logger configuration"""
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config['level']))
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Security filter
        security_filter = SecurityFilter()
        
        # Console handler
        if self.config['enable_console']:
            console_handler = logging.StreamHandler(sys.stdout)
            
            if self.config['format'] == 'json':
                console_handler.setFormatter(JSONFormatter())
            else:
                console_formatter = ColoredFormatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]'
                )
                console_handler.setFormatter(console_formatter)
            
            console_handler.addFilter(security_filter)
            root_logger.addHandler(console_handler)
        
        # File handler
        if self.config['file_path']:
            self._setup_file_handler(root_logger, security_filter)
    
    def _setup_file_handler(self, logger: logging.Logger, security_filter: SecurityFilter):
        """Setup file handler with rotation"""
        file_path = Path(self.config['file_path'])
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        if self.config['rotation'] == 'size':
            # Size-based rotation
            max_bytes = self._parse_size(self.config['max_file_size'])
            file_handler = logging.handlers.RotatingFileHandler(
                file_path,
                maxBytes=max_bytes,
                backupCount=self.config['backup_count'],
                encoding='utf-8'
            )
        elif self.config['rotation'] == 'daily':
            # Time-based rotation (daily)
            file_handler = logging.handlers.TimedRotatingFileHandler(
                file_path,
                when='midnight',
                interval=1,
                backupCount=self.config['backup_count'],
                encoding='utf-8'
            )
        elif self.config['rotation'] == 'weekly':
            # Time-based rotation (weekly)
            file_handler = logging.handlers.TimedRotatingFileHandler(
                file_path,
                when='W0',  # Monday
                interval=1,
                backupCount=self.config['backup_count'],
                encoding='utf-8'
            )
        else:
            # No rotation
            file_handler = logging.FileHandler(file_path, encoding='utf-8')
        
        # Set formatter
        if self.config['format'] == 'json':
            file_handler.setFormatter(JSONFormatter())
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]'
            )
            file_handler.setFormatter(file_formatter)
        
        file_handler.addFilter(security_filter)
        logger.addHandler(file_handler)
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string (e.g., '10MB') to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def _setup_structlog(self):
        """Setup structlog for structured logging"""
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]
        
        if self.config['format'] == 'json':
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.processors.KeyValueRenderer())
        
        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance with the specified name"""
        if name not in self._loggers:
            logger = logging.getLogger(name)
            self._loggers[name] = logger
        
        return self._loggers[name]
    
    def get_structured_logger(self, name: str):
        """Get a structured logger instance (requires structlog)"""
        if not STRUCTLOG_AVAILABLE:
            return self.get_logger(name)
        
        return structlog.get_logger(name)

class RequestLoggingMiddleware:
    """Middleware for logging HTTP requests"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def __call__(self, request, call_next):
        """Log request and response information"""
        start_time = datetime.utcnow()
        
        # Log request
        self.logger.info("HTTP Request", extra={
            'method': request.method,
            'url': str(request.url),
            'headers': dict(request.headers),
            'client_ip': request.client.host if request.client else None,
            'user_agent': request.headers.get('user-agent'),
            'request_id': getattr(request.state, 'request_id', None)
        })
        
        # Process request
        response = call_next(request)
        
        # Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Log response
        self.logger.info("HTTP Response", extra={
            'status_code': response.status_code,
            'duration_seconds': duration,
            'request_id': getattr(request.state, 'request_id', None)
        })
        
        return response

class AuditLogger:
    """Logger specifically for audit events"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_user_action(self, user_id: str, action: str, resource: str, 
                       success: bool, details: Optional[Dict[str, Any]] = None):
        """Log user actions for audit purposes"""
        self.logger.info("User Action", extra={
            'event_type': 'user_action',
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'success': success,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def log_security_event(self, event_type: str, severity: str, 
                          details: Dict[str, Any]):
        """Log security-related events"""
        self.logger.warning("Security Event", extra={
            'event_type': 'security_event',
            'security_event_type': event_type,
            'severity': severity,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def log_scan_event(self, scan_id: str, provider: str, action: str,
                      status: str, details: Optional[Dict[str, Any]] = None):
        """Log scan-related events"""
        self.logger.info("Scan Event", extra={
            'event_type': 'scan_event',
            'scan_id': scan_id,
            'provider': provider,
            'action': action,
            'status': status,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        })

class PerformanceLogger:
    """Logger for performance monitoring"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    @contextmanager
    def time_operation(self, operation_name: str, **context):
        """Context manager to time operations"""
        start_time = datetime.utcnow()
        try:
            yield
            success = True
            error = None
        except Exception as e:
            success = False
            error = str(e)
            raise
        finally:
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.logger.info("Operation Performance", extra={
                'event_type': 'performance',
                'operation': operation_name,
                'duration_seconds': duration,
                'success': success,
                'error': error,
                **context
            })
    
    def log_slow_query(self, query: str, duration: float, parameters: Optional[Dict] = None):
        """Log slow database queries"""
        self.logger.warning("Slow Query", extra={
            'event_type': 'slow_query',
            'query': query,
            'duration_seconds': duration,
            'parameters': parameters or {}
        })

def log_function_call(logger: Optional[logging.Logger] = None):
    """Decorator to log function calls"""
    def decorator(func):
        nonlocal logger
        if logger is None:
            logger = logging.getLogger(func.__module__)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger.debug(f"Calling {func.__name__}", extra={
                'function': func.__name__,
                'module': func.__module__,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            })
            
            try:
                result = func(*args, **kwargs)
                logger.debug(f"Completed {func.__name__}", extra={
                    'function': func.__name__,
                    'success': True
                })
                return result
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {str(e)}", extra={
                    'function': func.__name__,
                    'success': False,
                    'error': str(e)
                })
                raise
        
        return wrapper
    return decorator

# Global logger instance
_global_logger_instance = None

def setup_logging(config: Optional[Dict[str, Any]] = None) -> CloudSentinelLogger:
    """Setup global logging configuration"""
    global _global_logger_instance
    _global_logger_instance = CloudSentinelLogger(config)
    return _global_logger_instance

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    if _global_logger_instance is None:
        setup_logging()
    return _global_logger_instance.get_logger(name)

def get_structured_logger(name: str):
    """Get a structured logger instance"""
    if _global_logger_instance is None:
        setup_logging()
    return _global_logger_instance.get_structured_logger(name)

def get_audit_logger(name: str = 'cloudsentinel.audit') -> AuditLogger:
    """Get an audit logger instance"""
    logger = get_logger(name)
    return AuditLogger(logger)

def get_performance_logger(name: str = 'cloudsentinel.performance') -> PerformanceLogger:
    """Get a performance logger instance"""
    logger = get_logger(name)
    return PerformanceLogger(logger)

# Convenience functions for common logging patterns
def log_scan_start(scan_id: str, provider: str, **context):
    """Log scan start event"""
    logger = get_logger('cloudsentinel.scanner')
    logger.info(f"Starting scan {scan_id} for {provider}", extra={
        'scan_id': scan_id,
        'provider': provider,
        'event': 'scan_start',
        **context
    })

def log_scan_complete(scan_id: str, provider: str, findings_count: int, **context):
    """Log scan completion event"""
    logger = get_logger('cloudsentinel.scanner')
    logger.info(f"Completed scan {scan_id} for {provider} with {findings_count} findings", extra={
        'scan_id': scan_id,
        'provider': provider,
        'findings_count': findings_count,
        'event': 'scan_complete',
        **context
    })

def log_alert_created(alert_id: str, severity: str, **context):
    """Log alert creation event"""
    logger = get_logger('cloudsentinel.alerts')
    logger.info(f"Created {severity} alert {alert_id}", extra={
        'alert_id': alert_id,
        'severity': severity,
        'event': 'alert_created',
        **context
    })

def log_notification_sent(channel: str, recipient: str, success: bool, **context):
    """Log notification sending event"""
    logger = get_logger('cloudsentinel.notifications')
    level = logging.INFO if success else logging.ERROR
    logger.log(level, f"Notification sent via {channel} to {recipient}: {'success' if success else 'failed'}", extra={
        'channel': channel,
        'recipient': recipient,
        'success': success,
        'event': 'notification_sent',
        **context
    })

# Initialize logging on module import
setup_logging()
