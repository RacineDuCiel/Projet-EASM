"""
Web crawling tools: katana for endpoint discovery.
"""
import subprocess
import json
import logging
from typing import List, Dict, Any

from .common import check_tool

logger = logging.getLogger(__name__)


def run_katana(target: str, depth: int = 2, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run katana for web crawling and endpoint discovery.

    Args:
        target: Target URL (include scheme)
        depth: Crawl depth
        timeout: Maximum runtime in seconds

    Returns:
        List of discovered endpoints
    """
    if not check_tool("katana"):
        logger.error("katana not found in PATH")
        return []

    # Ensure target has scheme
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    logger.info(f"Running katana on {target} (depth={depth})")

    try:
        cmd = [
            "katana",
            "-u", target,
            "-json",
            "-silent",
            "-depth", str(depth),
            "-jc",          # JavaScript crawling
            "-kf", "all",   # Known files
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf",  # Exclude static files
            "-timeout", str(min(timeout, 600))
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        endpoints = []
        seen_urls = set()

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get("request", {}).get("endpoint") or data.get("endpoint")

                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)

                endpoint = {
                    "url": url,
                    "method": data.get("request", {}).get("method", "GET"),
                    "status_code": data.get("response", {}).get("status_code"),
                    "content_type": data.get("response", {}).get("headers", {}).get("content-type"),
                    "content_length": data.get("response", {}).get("body_size"),
                    "source": "katana",
                    "is_js_file": url.endswith(".js"),
                    "is_api_endpoint": any(x in url for x in ["/api/", "/v1/", "/v2/", "/graphql", ".json"])
                }
                endpoints.append(endpoint)

            except json.JSONDecodeError:
                continue

        logger.info(f"katana found {len(endpoints)} endpoints on {target}")
        return endpoints[:1000]  # Limit results

    except subprocess.TimeoutExpired:
        logger.error(f"katana timed out on {target}")
        return []
    except Exception as e:
        logger.error(f"katana failed on {target}: {e}")
        return []
