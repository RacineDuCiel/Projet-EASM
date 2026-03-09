"""
Shared utilities and constants for EASM scanning tools.
"""
import os
import shutil
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

DEFAULT_SCAN_PORTS = os.getenv("SCAN_PORTS", "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090")
DEFAULT_NAABU_RATE_LIMIT = os.getenv("NAABU_RATE_LIMIT", "1000")
MAX_THREADPOOL_WORKERS = int(os.getenv("MAX_THREADPOOL_WORKERS", "4"))

DEFAULT_NUCLEI_TIMEOUT_TOTAL = int(os.getenv("NUCLEI_TIMEOUT_TOTAL", "600"))
DEFAULT_NUCLEI_RATE_LIMIT = os.getenv("NUCLEI_RATE_LIMIT", "150")
DEFAULT_NUCLEI_TIMEOUT = os.getenv("NUCLEI_TIMEOUT", "5")
DEFAULT_NUCLEI_RETRIES = os.getenv("NUCLEI_RETRIES", "1")
DEFAULT_NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "info,low,medium,high,critical")


# =============================================================================
# Utility Functions
# =============================================================================

def _parse_response_time(time_str) -> Optional[int]:
    """Parse httpx response time string to milliseconds as int.

    Handles various formats:
    - '78.38318ms' -> 78 (value in ms, truncate decimals)
    - '0.07838318s' -> 78 (value in seconds, multiply by 1000)
    - '50' -> 50000 (raw number < 100, assume seconds, multiply by 1000)
    - '500' -> 500 (raw number >= 100, assume milliseconds)
    - 50.5 (float) -> 50500 (assume seconds if < 100)
    - 500 (int) -> 500 (assume milliseconds)
    """
    if time_str is None:
        return None
    if isinstance(time_str, (int, float)):
        if time_str < 100:
            return int(time_str * 1000)
        return int(time_str)
    if not isinstance(time_str, str):
        return None
    time_str = time_str.strip()
    if not time_str:
        return None
    try:
        suffix = None
        lower_str = time_str.lower()
        if lower_str.endswith('ms'):
            suffix = 'ms'
        elif lower_str.endswith('s'):
            suffix = 's'
        cleaned = re.sub(r'[^\d.]', '', time_str)
        if not cleaned:
            logger.warning(f"Could not parse response time '{time_str}': no numeric value found")
            return None
        value = float(cleaned)
        if suffix == 's':
            return int(value * 1000)
        if suffix == 'ms':
            return int(value)
        if value < 100:
            return int(value * 1000)
        return int(value)
    except (ValueError, TypeError) as e:
        logger.warning(f"Could not parse response time '{time_str}': {e}")
        return None


def check_tool(tool_name: str) -> bool:
    """Check if a tool is installed and available in PATH."""
    return shutil.which(tool_name) is not None


def normalize_severity(severity: str) -> str:
    """Normalizes Nuclei severity to match backend Enum."""
    if not severity:
        return "info"

    severity = severity.lower()
    mapping = {
        "informational": "info",
        "unknown": "info",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical"
    }
    return mapping.get(severity, "info")
