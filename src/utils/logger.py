"""
Structured Logging Module

Provides structured JSON logging with support for multiple outputs,
log rotation, and context enrichment.
"""

import logging
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum
from logging.handlers import RotatingFileHandler
import traceback

try:
    from pythonjsonlogger import jsonlogger
    HAS_JSON_LOGGER = True
except ImportError:
    HAS_JSON_LOGGER = False


class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class LoggerConfig:
    """Configuration for structured logging"""
    
    def __init__(self,
                 level: LogLevel = LogLevel.INFO,
                 format_json: bool = True,
                 log_to_file: bool = True,
                 log_file_path: str = "logs/ddos_system.log",
                 log_file_max_bytes: int = 10485760,
                 log_file_backup_count: int = 5,
                 log_to_console: bool = True,
                 include_context: bool = True,
                 include_timestamp: bool = True,
                 timezone: str = "UTC",
                 service_name: str = "ddos-protection"):
        
        self.level = level
        self.format_json = format_json
        self.log_to_file = log_to_file
        self.log_file_path = Path(log_file_path)
        self.log_file_max_bytes = log_file_max_bytes
        self.log_file_backup_count = log_file_backup_count
        self.log_to_console = log_to_console
        self.include_context = include_context
        self.include_timestamp = include_timestamp
        self.timezone = timezone
        self.service_name = service_name

        if self.log_to_file:
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)


_INTERNAL_LOG_KEYS = frozenset({
    'name', 'msg', 'args', 'created', 'levelname', 'levelno',
    'pathname', 'filename', 'module', 'exc_info', 'exc_text',
    'stack_info', 'lineno', 'funcName', 'thread', 'threadName',
    'processName', 'process', 'message', 'asctime', 'msecs',
    'relativeCreated', 'extra', 'context',
})


class JsonFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Formats log records as JSON objects for easy ingestion by log aggregators.
    """

    def __init__(self, include_context: bool = True, service_name: str = "ddos-protection"):
        super().__init__()
        self.include_context = include_context
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        if self.include_context:
            # Extract context from extra dict
            extra = getattr(record, 'extra', None) or {}
            if 'context' in extra:
                log_entry["context"] = extra['context']
            elif extra:
                log_entry["context"] = extra

        return json.dumps(log_entry, default=str)


class ColoredConsoleFormatter(logging.Formatter):
    """Colored console formatter for human-readable logs during development."""

    COLORS = {
        'DEBUG':    '\033[36m',   # Cyan
        'INFO':     '\033[32m',   # Green
        'WARNING':  '\033[33m',   # Yellow
        'ERROR':    '\033[31m',   # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET':    '\033[0m',
    }

    def format(self, record: logging.LogRecord) -> str:
        log_time = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']

        message = record.getMessage()
        
        # Truncate logger name for cleaner output
        logger_name = record.name
        if len(logger_name) > 20:
            logger_name = logger_name[-20:]
        
        log_line = f"{log_time} {color}{record.levelname:<8}{reset} {logger_name:<20} {message}"

        if record.exc_info:
            log_line += "\n" + self.formatException(record.exc_info)

        return log_line


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds context to all log messages."""

    def __init__(self, logger: logging.Logger, extra: Dict[str, Any] = None):
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log record to add context"""
        # Work on copies — never mutate the caller's dict
        caller_extra = dict(kwargs.get('extra') or {})
        
        # Merge existing context
        caller_context = dict(caller_extra.get('context') or {})
        caller_context.update(self.extra)
        caller_extra['context'] = caller_context

        kwargs['extra'] = caller_extra
        return msg, kwargs


def setup_logging(config: Optional[LoggerConfig] = None) -> logging.Logger:
    """
    Setup the logging system with the given configuration.

    Args:
        config: Logger configuration (uses defaults if None)

    Returns:
        Root logger instance
    """
    if config is None:
        config = LoggerConfig()

    root_logger = logging.getLogger()
    root_logger.setLevel(config.level.value)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatters
    if config.format_json:
        if HAS_JSON_LOGGER:
            json_formatter = jsonlogger.JsonFormatter(
                fmt='%(asctime)s %(levelname)s %(name)s %(message)s',
                rename_fields={
                    'asctime': 'timestamp',
                    'levelname': 'level',
                    'name': 'logger',
                }
            )
            console_formatter = json_formatter
            file_formatter = json_formatter
        else:
            json_formatter = JsonFormatter(
                include_context=config.include_context,
                service_name=config.service_name,
            )
            console_formatter = json_formatter
            file_formatter = json_formatter
    else:
        console_formatter = ColoredConsoleFormatter()
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    # Add console handler
    if config.log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(config.level.value)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # Add file handler
    if config.log_to_file:
        file_handler = RotatingFileHandler(
            config.log_file_path,
            maxBytes=config.log_file_max_bytes,
            backupCount=config.log_file_backup_count,
        )
        file_handler.setLevel(config.level.value)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger('kafka').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)

    app_logger = get_logger('ddos_system')
    app_logger.info(
        f"Logging initialized - Level: {config.level.name}, "
        f"JSON format: {config.format_json}, "
        f"Service: {config.service_name}"
    )

    return app_logger


def get_logger(
    name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Union[logging.Logger, ContextAdapter]:
    """
    Get a logger instance with optional context.

    Args:
        name: Logger name (usually __name__)
        context: Optional context dict added to all log messages

    Returns:
        Logger or ContextAdapter instance
    """
    logger = logging.getLogger(name)
    if context:
        return ContextAdapter(logger, context)
    return logger


class PerformanceLogger:
    """Context manager for logging performance metrics."""

    def __init__(self, logger: logging.Logger, operation: str, **context):
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        self.logger.debug(f"Starting {self.operation}", extra={'context': self.context})
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.context['duration_seconds'] = round(duration, 3)
        self.context['success'] = exc_type is None

        if exc_type:
            self.logger.error(
                f"Failed {self.operation}: {exc_val}",
                extra={'context': self.context},
                exc_info=True,
            )
        else:
            self.logger.info(
                f"Completed {self.operation} in {duration:.3f}s",
                extra={'context': self.context},
            )


class RequestLogger:
    """Logger for HTTP requests with timing and status tracking."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_request(self, method: str, url: str, status_code: int = None,
                    duration_ms: float = None, **extra):
        """Log an HTTP request"""
        log_data = {
            'method': method, 
            'url': url,
            'status_code': status_code, 
            'duration_ms': duration_ms, 
            **extra
        }
        
        if status_code and status_code >= 400:
            self.logger.warning("HTTP request failed", extra={'context': log_data})
        else:
            self.logger.debug("HTTP request completed", extra={'context': log_data})

    def log_api_call(self, service: str, endpoint: str, **kwargs):
        """Log an API call"""
        log_data = {'service': service, 'endpoint': endpoint, **kwargs}
        self.logger.debug(f"API call to {service}", extra={'context': log_data})


def get_performance_logger(name: str, operation: str) -> PerformanceLogger:
    """Get a performance logger for timing operations"""
    return PerformanceLogger(get_logger(name), operation)