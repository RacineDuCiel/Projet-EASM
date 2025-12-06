"""
Worker utility functions with connection pooling for HTTP calls.
"""
import logging
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from src.celery_app import BACKEND_URL

logger = logging.getLogger(__name__)
HTTP_TIMEOUT = 30


# Singleton session with connection pooling  
_session: Optional[requests.Session] = None


def get_session() -> requests.Session:
    """
    Returns a singleton requests.Session with connection pooling and retry logic.
    This significantly reduces connection overhead for multiple backend API calls.
    """
    global _session
    if _session is None:
        _session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        # Configure connection pooling
        adapter = HTTPAdapter(
            pool_connections=10,   # Number of connection pools
            pool_maxsize=10,       # Connections per pool
            max_retries=retry_strategy
        )
        
        _session.mount("http://", adapter)
        _session.mount("https://", adapter)
        
        logger.debug("Created new HTTP session with connection pooling")
    
    return _session


def log_event(scan_id: str, message: str, severity: str = "info") -> None:
    """
    Helper to send scan events to the backend.
    Uses connection-pooled session for reduced overhead.
    """
    try:
        session = get_session()
        session.post(
            f"{BACKEND_URL}/scans/{scan_id}/events",
            json={
                "message": message,
                "severity": severity
            },
            timeout=HTTP_TIMEOUT
        )
    except Exception as e:
        logger.error(f"Failed to log event: {e}")


def post_to_backend(endpoint: str, json_data: dict, timeout: int = HTTP_TIMEOUT) -> requests.Response:
    """
    Helper to POST data to backend with connection pooling.
    
    Args:
        endpoint: API endpoint path (e.g., "/scans/{id}/assets")
        json_data: JSON payload to send
        timeout: Request timeout in seconds
        
    Returns:
        Response object
    """
    session = get_session()
    return session.post(
        f"{BACKEND_URL}{endpoint}",
        json=json_data,
        timeout=timeout
    )
