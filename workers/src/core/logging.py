import logging
import sys
import os

def setup_logging() -> None:
    """
    Configure the logging system for workers.
    """
    # Define the format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Determine the logging level
    environment = os.getenv("ENVIRONMENT", "development")
    log_level = logging.INFO
    if environment == "development":
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
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)

    # Log that logging is set up
    logging.getLogger("src.core.logging").info(f"Worker logging configured. Level: {logging.getLevelName(log_level)}")
