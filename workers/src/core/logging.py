"""
Structured logging configuration for EASM workers.

Supports JSON format for production (machine-parseable) and
human-readable format for development.
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs logs in JSON format for easy parsing by log aggregators.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "service": "worker",
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields from record
        extra_keys = set(record.__dict__.keys()) - {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "taskName", "message",
        }
        for key in extra_keys:
            value = getattr(record, key)
            if value is not None:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class HumanReadableFormatter(logging.Formatter):
    """
    Human-readable formatter for development with colors.
    """

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        base_msg = f"{timestamp} | {color}{record.levelname:8}{self.RESET} | {record.name} | {record.getMessage()}"

        # Add extra context if present
        extra_keys = set(record.__dict__.keys()) - {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "taskName", "message",
        }

        extra_parts = []
        for key in sorted(extra_keys):
            value = getattr(record, key)
            if value is not None:
                extra_parts.append(f"{key}={value}")

        if extra_parts:
            base_msg += f" | {' '.join(extra_parts)}"

        if record.exc_info:
            base_msg += f"\n{self.formatException(record.exc_info)}"

        return base_msg


class ContextLogger(logging.LoggerAdapter):
    """
    Logger adapter that adds context to all log messages.

    Usage:
        logger = get_logger(__name__, scan_id="abc123", target="example.com")
        logger.info("Starting scan")
    """

    def process(self, msg: str, kwargs: Dict) -> tuple:
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(name: str, **context) -> ContextLogger:
    """
    Get a logger with optional context fields.

    Args:
        name: Logger name (usually __name__)
        **context: Additional context fields to include in all logs

    Returns:
        ContextLogger with the specified context
    """
    logger = logging.getLogger(name)
    return ContextLogger(logger, context)


def setup_logging() -> None:
    """
    Configure the logging system for workers.

    Uses JSON format in production, human-readable format in development.
    """
    environment = os.getenv("ENVIRONMENT", "development")

    log_level = logging.INFO
    if environment == "development":
        log_level = logging.DEBUG

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    if root_logger.handlers:
        root_logger.handlers = []

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    if environment == "production":
        formatter = StructuredFormatter()
    else:
        formatter = HumanReadableFormatter()

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)
    logging.getLogger("kombu").setLevel(logging.WARNING)

    logger = get_logger("src.core.logging")
    logger.info(
        "Worker logging configured",
        extra={
            "level": logging.getLevelName(log_level),
            "format": "json" if environment == "production" else "human",
        }
    )
