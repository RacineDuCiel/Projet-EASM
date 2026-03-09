"""
Historical URL tools: waybackurls and gau (GetAllUrls).
"""
import subprocess
import logging
from typing import List, Dict, Any

from .common import check_tool

logger = logging.getLogger(__name__)


def run_waybackurls(domain: str, timeout: int = 120) -> List[Dict[str, Any]]:
    """
    Fetch historical URLs from Wayback Machine.

    Returns:
        List of historical URL records
    """
    if not check_tool("waybackurls"):
        logger.error("waybackurls not found in PATH")
        return []

    logger.info(f"Running waybackurls for {domain}")

    try:
        cmd = ["waybackurls", domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        urls = []
        seen = set()

        for line in result.stdout.splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)

            urls.append({
                "url": url,
                "source": "wayback",
                "archived_date": None,  # waybackurls doesn't provide dates
            })

        logger.info(f"waybackurls found {len(urls)} URLs for {domain}")
        return urls[:2000]  # Limit to prevent memory issues

    except subprocess.TimeoutExpired:
        logger.error(f"waybackurls timed out for {domain}")
        return []
    except Exception as e:
        logger.error(f"waybackurls failed for {domain}: {e}")
        return []


def run_gau(domain: str, timeout: int = 180) -> List[Dict[str, Any]]:
    """
    Run gau (GetAllUrls) to aggregate URLs from multiple sources.

    Returns:
        List of discovered URL records
    """
    if not check_tool("gau"):
        logger.error("gau not found in PATH")
        return []

    logger.info(f"Running gau for {domain}")

    try:
        cmd = [
            "gau",
            "--subs",           # Include subdomains
            "--threads", "5",
            "--timeout", "60",
            "--blacklist", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
            domain
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        urls = []
        seen = set()

        for line in result.stdout.splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)

            urls.append({
                "url": url,
                "source": "gau",
            })

        logger.info(f"gau found {len(urls)} URLs for {domain}")
        return urls[:3000]  # Limit results

    except subprocess.TimeoutExpired:
        logger.error(f"gau timed out for {domain}")
        return []
    except Exception as e:
        logger.error(f"gau failed for {domain}: {e}")
        return []
