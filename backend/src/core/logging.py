import logging
import sys
from typing import Any
from src.core.config import settings

class InterceptHandler(logging.Handler):
    """
    Intercept standard logging messages and route them to the configured handler.
    Useful if we were using loguru, but here we stick to standard logging 
    with a custom formatter for consistency.
    """
    def emit(self, record: logging.LogRecord) -> None:
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())

def setup_logging() -> None:
    """
    Configure the logging system.
    """
    # Define the format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Determine the logging level
    log_level = logging.INFO
    if settings.ENVIRONMENT == "development":
        log_level = logging.DEBUG

    # Create a root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplication
    if root_logger.handlers:
        root_logger.handlers = []

    # Create a console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Create a formatter
    formatter = logging.Formatter(log_format)
    console_handler.setFormatter(formatter)

    # Add the handler to the root logger
    root_logger.addHandler(console_handler)

    # Set levels for third-party libraries to avoid noise
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # Log that logging is set up
    logging.getLogger("src.core.logging").info(f"Logging configured. Level: {logging.getLevelName(log_level)}")
