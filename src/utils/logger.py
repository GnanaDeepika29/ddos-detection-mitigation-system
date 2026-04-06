"""
Structured Logging Module

Provides structured JSON logging with support for multiple outputs,
log rotation, and context enrichment.
"""

import json
import logging
import sys
import time
import traceback
from datetime import datetime
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, Union

try:
    from pythonjsonlogger import jsonlogger  # type: ignore
    HAS_JSON_LOGGER = True
except ImportError:
    HAS_JSON_LOGGER = False


class LogLevel(Enum):
    DEBUG    = logging.DEBUG
    INFO     = logging.INFO
    WARNING  = logging.WARNING
    ERROR    = logging.ERROR
    CRITICAL = logging.CRITICAL


class LoggerConfig:
    """Configuration for structured logging."""

    def __init__(
        self,
        level: LogLevel = LogLevel.INFO,
        format_json: bool = True,
        log_to_file: bool = True,
        log_file_path: str = "logs/ddos_system.log",
        log_file_max_bytes: int = 10_485_760,
        log_file_backup_count: int = 5,
        log_to_console: bool = True,
        include_context: bool = True,
        include_timestamp: bool = True,
        timezone: str = "UTC",
        service_name: str = "ddos-protection",
    ) -> None:
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

        # Directory is created lazily in setup_logging(), not here, so
        # constructing a LoggerConfig never raises on permission errors.


_INTERNAL_LOG_KEYS = frozenset({
    'name', 'msg', 'args', 'created', 'levelname', 'levelno',
    'pathname', 'filename', 'module', 'exc_info', 'exc_text',
    'stack_info', 'lineno', 'funcName', 'thread', 'threadName',
    'processName', 'process', 'message', 'asctime', 'msecs',
    'relativeCreated', 'extra', 'context',
})


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def __init__(
        self,
        include_context: bool = True,
        service_name: str = "ddos-protection",
    ) -> None:
        super().__init__()
        self.include_context = include_context
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # FIX BUG-16: exc_info can be (None, None, None).  Accessing
        # exc_info[0].__name__ when exc_info[0] is None raises AttributeError.
        # Guard with an explicit None check before building the exception dict.
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        if self.include_context:
            extra = getattr(record, 'extra', None) or {}
            if 'context' in extra:
                log_entry["context"] = extra['context']
            elif extra:
                log_entry["context"] = extra

        return json.dumps(log_entry, default=str)


class ColoredConsoleFormatter(logging.Formatter):
    """Colored console formatter for human-readable dev logs."""

    COLORS = {
        'DEBUG':    '\033[36m',
        'INFO':     '\033[32m',
        'WARNING':  '\033[33m',
        'ERROR':    '\033[31m',
        'CRITICAL': '\033[35m',
        'RESET':    '\033[0m',
    }

    def format(self, record: logging.LogRecord) -> str:
        log_time = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        name = record.name[-20:] if len(record.name) > 20 else record.name
        line = f"{log_time} {color}{record.levelname:<8}{reset} {name:<20} {record.getMessage()}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that injects context into all log messages."""

    def __init__(
        self, logger: logging.Logger, extra: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """
        Merge adapter-level context with per-call context.

        FIX BUG-13: The original code called caller_context.update(self.extra)
        AFTER building caller_context from the call-site extra.  This meant
        adapter defaults overwrote per-call values for the same key — the
        wrong precedence.  Fixed: adapter defaults are set first, then
        per-call context overwrites them.
        """
        caller_extra = dict(kwargs.get('extra') or {})

        # Start with adapter defaults, then let per-call context override.
        merged_context: Dict[str, Any] = {}
        merged_context.update(self.extra)                                   # FIX BUG-13
        merged_context.update(caller_extra.get('context') or {})            # FIX BUG-13

        caller_extra['context'] = merged_context
        kwargs['extra'] = caller_extra
        return msg, kwargs


def setup_logging(config: Optional[LoggerConfig] = None) -> logging.Logger:
    """
    Configure the root logger from a LoggerConfig.

    Returns the application-level logger.
    """
    if config is None:
        config = LoggerConfig()

    # Create log directory lazily here (not in LoggerConfig.__init__).
    if config.log_to_file:
        config.log_file_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(config.level.value)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Build formatters — use distinct instances to avoid shared-state surprises.
    if config.format_json:
        if HAS_JSON_LOGGER:
            def _make_json_fmt() -> logging.Formatter:
                return jsonlogger.JsonFormatter(  # type: ignore
                    fmt='%(asctime)s %(levelname)s %(name)s %(message)s',
                    rename_fields={'asctime': 'timestamp', 'levelname': 'level', 'name': 'logger'},
                )
            console_formatter: logging.Formatter = _make_json_fmt()
            file_formatter: logging.Formatter = _make_json_fmt()
        else:
            console_formatter = JsonFormatter(
                include_context=config.include_context, service_name=config.service_name
            )
            file_formatter = JsonFormatter(
                include_context=config.include_context, service_name=config.service_name
            )
    else:
        console_formatter = ColoredConsoleFormatter()
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    if config.log_to_console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(config.level.value)
        ch.setFormatter(console_formatter)
        root_logger.addHandler(ch)

    if config.log_to_file:
        fh = RotatingFileHandler(
            config.log_file_path,
            maxBytes=config.log_file_max_bytes,
            backupCount=config.log_file_backup_count,
        )
        fh.setLevel(config.level.value)
        fh.setFormatter(file_formatter)
        root_logger.addHandler(fh)

    # Suppress noisy third-party loggers
    for noisy in ('kafka', 'urllib3', 'requests', 'aiohttp'):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    app_logger = get_logger('ddos_system')
    app_logger.info(
        f"Logging initialised — level={config.level.name}, "
        f"json={config.format_json}, service={config.service_name}"
    )
    return app_logger


def get_logger(
    name: str,
    context: Optional[Dict[str, Any]] = None,
) -> Union[logging.Logger, ContextAdapter]:
    """
    Get a logger (with optional per-adapter context).

    Args:
        name:    Logger name (typically __name__).
        context: Optional dict added to every log record from this adapter.
    """
    base_logger = logging.getLogger(name)
    if context:
        return ContextAdapter(base_logger, context)
    return base_logger


class PerformanceLogger:
    """Context manager for timing and logging operations."""

    def __init__(
        self, logger: logging.Logger, operation: str, **context: Any
    ) -> None:
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time: Optional[float] = None

    def __enter__(self) -> "PerformanceLogger":
        self.start_time = time.time()
        self.logger.debug(f"Starting {self.operation}", extra={'context': self.context})
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        duration = time.time() - (self.start_time or time.time())
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
    """HTTP request logger with timing and status tracking."""

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def log_request(
        self,
        method: str,
        url: str,
        status_code: Optional[int] = None,
        duration_ms: Optional[float] = None,
        **extra: Any,
    ) -> None:
        log_data = {
            'method': method, 'url': url,
            'status_code': status_code, 'duration_ms': duration_ms,
            **extra,
        }
        if status_code and status_code >= 400:
            self.logger.warning("HTTP request failed", extra={'context': log_data})
        else:
            self.logger.debug("HTTP request completed", extra={'context': log_data})

    def log_api_call(self, service: str, endpoint: str, **kwargs: Any) -> None:
        log_data = {'service': service, 'endpoint': endpoint, **kwargs}
        self.logger.debug(f"API call to {service}", extra={'context': log_data})


def get_performance_logger(name: str, operation: str) -> PerformanceLogger:
    return PerformanceLogger(get_logger(name), operation)