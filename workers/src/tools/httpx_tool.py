"""
HTTP probing tools: httpx for technology detection, security headers, and favicon hashing.
"""
import subprocess
import json
import hashlib
import base64
import logging
import requests
from typing import Dict, Any

from .common import check_tool, _parse_response_time

logger = logging.getLogger(__name__)


def run_httpx(target: str, port: int = None) -> Dict[str, Any]:
    """
    Runs httpx for technology detection on a target.

    Args:
        target: Domain or IP to scan
        port: Optional specific port

    Returns:
        Dictionary with detected technologies and metadata
    """
    if not check_tool("httpx"):
        logger.error("httpx not found in PATH")
        return {"technologies": [], "error": "httpx not installed"}

    # Build target URL
    if port:
        if port == 443:
            url = f"https://{target}:{port}"
        else:
            url = f"http://{target}:{port}"
    else:
        url = target

    logger.info(f"Running httpx tech detection on {url}...")

    try:
        cmd = [
            "httpx",
            "-u", url,
            "-tech-detect",
            "-json",
            "-silent",
            "-timeout", "15",
            "-no-color",
            "-follow-redirects"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if not result.stdout.strip():
            logger.warning(f"httpx returned no output for {url}")
            return {"technologies": [], "target": url}

        # Parse JSON output (httpx outputs one JSON per line)
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                # Extract technology info
                tech_result = {
                    "target": url,
                    "technologies": data.get("tech", []),
                    "web_server": data.get("webserver"),
                    "status_code": data.get("status_code"),
                    "content_length": data.get("content_length"),
                    "response_time_ms": _parse_response_time(data.get("time")),
                    "tls": data.get("tls", {}),
                    "waf": data.get("waf"),
                    "cdn": data.get("cdn"),
                    "title": data.get("title"),
                }

                logger.info(f"httpx detected {len(tech_result['technologies'])} technologies on {url}")
                return tech_result

            except json.JSONDecodeError:
                continue

        return {"technologies": [], "target": url}

    except subprocess.TimeoutExpired:
        logger.error(f"httpx timed out on {url}")
        return {"technologies": [], "error": "timeout", "target": url}
    except Exception as e:
        logger.error(f"httpx failed on {url}: {e}")
        return {"technologies": [], "error": str(e), "target": url}


def run_httpx_security_headers(target: str, port: int = None) -> Dict[str, Any]:
    """
    Run httpx with security headers analysis.

    Returns:
        Dictionary with security headers data
    """
    if not check_tool("httpx"):
        logger.error("httpx not found in PATH")
        return {}

    # Build URL
    if port:
        if port == 443:
            url = f"https://{target}:{port}"
        else:
            url = f"http://{target}:{port}"
    else:
        url = f"https://{target}"

    logger.info(f"Running httpx security headers analysis on {url}")

    try:
        cmd = [
            "httpx",
            "-u", url,
            "-json",
            "-silent",
            "-include-response-header",
            "-timeout", "15",
            "-no-color",
            "-follow-redirects"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                headers = data.get("header", {})

                # Normalize header keys to lowercase
                headers_lower = {k.lower(): v for k, v in headers.items()}

                # Calculate missing headers and score
                security_headers_check = {
                    "content-security-policy": 20,
                    "strict-transport-security": 20,
                    "x-frame-options": 15,
                    "x-content-type-options": 15,
                    "x-xss-protection": 10,
                    "referrer-policy": 10,
                    "permissions-policy": 10,
                }

                missing = []
                score = 100

                for header, points in security_headers_check.items():
                    if header not in headers_lower:
                        missing.append(header)
                        score -= points

                # Determine grade
                if score >= 90:
                    grade = "A+"
                elif score >= 80:
                    grade = "A"
                elif score >= 70:
                    grade = "B"
                elif score >= 60:
                    grade = "C"
                elif score >= 50:
                    grade = "D"
                else:
                    grade = "F"

                result_data = {
                    "url": url,
                    "content_security_policy": headers_lower.get("content-security-policy"),
                    "strict_transport_security": headers_lower.get("strict-transport-security"),
                    "x_frame_options": headers_lower.get("x-frame-options"),
                    "x_content_type_options": headers_lower.get("x-content-type-options"),
                    "x_xss_protection": headers_lower.get("x-xss-protection"),
                    "referrer_policy": headers_lower.get("referrer-policy"),
                    "permissions_policy": headers_lower.get("permissions-policy"),
                    "missing_headers": json.dumps(missing),
                    "score": max(0, score),
                    "grade": grade,
                }

                logger.info(f"Security headers for {url}: score={score}, grade={grade}")
                return result_data

            except json.JSONDecodeError:
                continue

        return {}

    except subprocess.TimeoutExpired:
        logger.error(f"httpx security headers timed out for {url}")
        return {}
    except Exception as e:
        logger.error(f"httpx security headers failed for {url}: {e}")
        return {}


def calculate_favicon_hash(target: str, port: int = None) -> Dict[str, Any]:
    """
    Calculate favicon hash for fingerprinting (Shodan-compatible).

    Returns:
        Dictionary with favicon hashes
    """
    # Build URL
    if port:
        if port == 443:
            base_url = f"https://{target}:{port}"
        else:
            base_url = f"http://{target}:{port}"
    else:
        base_url = f"https://{target}"

    favicon_url = f"{base_url}/favicon.ico"
    logger.info(f"Calculating favicon hash for {favicon_url}")

    try:
        response = requests.get(favicon_url, timeout=10, allow_redirects=True)
        response.raise_for_status()

        favicon_data = response.content

        if not favicon_data or len(favicon_data) < 10:
            logger.warning(f"No valid favicon found at {favicon_url}")
            return {}

        # Calculate hashes
        md5_hash = hashlib.md5(favicon_data).hexdigest()
        sha256_hash = hashlib.sha256(favicon_data).hexdigest()

        # Calculate Shodan-compatible MurmurHash3
        try:
            import mmh3
            favicon_b64 = base64.encodebytes(favicon_data)
            mmh3_hash = str(mmh3.hash(favicon_b64))
        except ImportError:
            logger.warning("mmh3 not installed, skipping MurmurHash3")
            mmh3_hash = None

        result = {
            "mmh3_hash": mmh3_hash,
            "md5_hash": md5_hash,
            "sha256_hash": sha256_hash,
            "favicon_url": favicon_url,
            "favicon_size": len(favicon_data),
        }

        logger.info(f"Favicon hash: mmh3={mmh3_hash}, md5={md5_hash[:8]}...")
        return result

    except requests.exceptions.RequestException as e:
        logger.debug(f"No favicon at {favicon_url}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Favicon hash calculation failed for {target}: {e}")
        return {}
