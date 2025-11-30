import requests
import logging
from src.celery_app import BACKEND_URL

logger = logging.getLogger(__name__)
HTTP_TIMEOUT = 30

def log_event(scan_id, message, severity="info"):
    """
    Helper to send scan events to the backend.
    """
    try:
        requests.post(
            f"{BACKEND_URL}/scans/{scan_id}/events",
            json={
                "message": message,
                "severity": severity
            },
            timeout=HTTP_TIMEOUT
        )
    except Exception as e:
        logger.error(f"Failed to log event: {e}")
