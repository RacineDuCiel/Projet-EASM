"""
Structured logging configuration for the EASM Platform backend.

Supports JSON format for production (machine-parseable) and
human-readable format for development.
"""
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.core.config import settings


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs logs in JSON format for easy parsing by log aggregators
    (ELK, Datadog, CloudWatch, etc.)
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
    Human-readable formatter for development.

    Includes colors for different log levels.
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
        # Add color based on level
        color = self.COLORS.get(record.levelname, "")

        # Build the base message
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

        # Add exception if present
        if record.exc_info:
            base_msg += f"\n{self.formatException(record.exc_info)}"

        return base_msg


class ContextLogger(logging.LoggerAdapter):
    """
    Logger adapter that adds context to all log messages.

    Usage:
        logger = get_logger(__name__, scan_id="abc123", target="example.com")
        logger.info("Starting scan")  # Will include scan_id and target
    """

    def process(self, msg: str, kwargs: Dict) -> tuple:
        # Merge adapter context with call-time extra
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

    Example:
        logger = get_logger(__name__, scan_id="123", phase="discovery")
        logger.info("Starting phase")
    """
    logger = logging.getLogger(name)
    return ContextLogger(logger, context)


def setup_logging() -> None:
    """
    Configure the logging system.

    Uses JSON format in production, human-readable format in development.
    """
    # Determine the logging level
    log_level = logging.INFO
    if settings.ENVIRONMENT == "development":
        log_level = logging.DEBUG

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplication
    if root_logger.handlers:
        root_logger.handlers = []

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Choose formatter based on environment
    if settings.ENVIRONMENT == "production":
        formatter = StructuredFormatter()
    else:
        formatter = HumanReadableFormatter()

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Log startup
    logger = get_logger("src.core.logging")
    logger.info(
        f"Logging configured",
        extra={
            "level": logging.getLevelName(log_level),
            "format": "json" if settings.ENVIRONMENT == "production" else "human",
        }
    )
