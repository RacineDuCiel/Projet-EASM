import subprocess
import json
import os
import shutil
import logging
import socket
import hashlib
import base64
import requests
import time
from typing import List, Dict, Any, Generator, Optional
from datetime import datetime

from src.validation import validate_input, InputType, ValidationError
from src.result import (
    ToolResult, ResultStatus, ErrorCategory,
    success_result, error_result, timeout_result,
    tool_missing_result, invalid_input_result, not_found_result,
    SubdomainResult, PortScanResult, TechnologyResult,
    VulnerabilityFinding, DNSRecordResult, CertificateResult
)

import re

logger = logging.getLogger(__name__)


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

def run_subfinder(domain: str, timeout: int = 120) -> ToolResult[SubdomainResult]:
    """
    Runs subfinder to discover subdomains.
    Returns a ToolResult with SubdomainResult containing unique subdomains found.
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("subfinder"):
        return tool_missing_result("subfinder")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Subfinder on {domain}...")

    try:
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Subfinder found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="subfinder",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Subfinder timed out on {domain}")
        return timeout_result(
            f"Subfinder timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="subfinder", count=0, duration_ms=duration_ms)
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"Subfinder failed on {domain}: {e.stderr}")
        return error_result(
            f"Subfinder failed: {e.stderr}",
            ErrorCategory.SYSTEM,
            "SUBFINDER_ERROR",
            str(e)
        )

    except Exception as e:
        logger.error(f"Unexpected error running Subfinder on {domain}: {e}")
        return error_result(
            f"Unexpected error: {str(e)}",
            ErrorCategory.CRITICAL,
            "UNEXPECTED_ERROR",
            str(e)
        )


def run_amass(domain: str, timeout: int = 300, passive_only: bool = True) -> ToolResult[SubdomainResult]:
    """
    Runs Amass for subdomain enumeration.
    More comprehensive than Subfinder but slower.

    Args:
        domain: Target domain
        timeout: Maximum execution time in seconds
        passive_only: If True, only use passive sources (faster, no DNS bruteforce)

    Returns:
        ToolResult with SubdomainResult containing unique subdomains found
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("amass"):
        logger.warning("Amass not found in PATH, skipping")
        return tool_missing_result("amass")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Amass on {domain} (passive={passive_only})...")

    try:
        cmd = ["amass", "enum", "-d", domain, "-silent"]
        if passive_only:
            cmd.append("-passive")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Amass found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="amass",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Amass timed out on {domain} after {timeout}s")
        return timeout_result(
            f"Amass timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="amass", count=0, duration_ms=duration_ms)
        )

    except Exception as e:
        logger.error(f"Amass failed on {domain}: {e}")
        return error_result(
            f"Amass failed: {str(e)}",
            ErrorCategory.SYSTEM,
            "AMASS_ERROR",
            str(e)
        )


def run_findomain(domain: str, timeout: int = 120) -> ToolResult[SubdomainResult]:
    """
    Runs Findomain for fast subdomain enumeration.
    Very fast tool that aggregates multiple sources.

    Args:
        domain: Target domain
        timeout: Maximum execution time in seconds

    Returns:
        ToolResult with SubdomainResult containing unique subdomains found
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("findomain"):
        logger.warning("Findomain not found in PATH, skipping")
        return tool_missing_result("findomain")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Findomain on {domain}...")

    try:
        cmd = ["findomain", "-t", domain, "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Findomain found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="findomain",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Findomain timed out on {domain}")
        return timeout_result(
            f"Findomain timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="findomain", count=0, duration_ms=duration_ms)
        )

    except Exception as e:
        logger.error(f"Findomain failed on {domain}: {e}")
        return error_result(
            f"Findomain failed: {str(e)}",
            ErrorCategory.SYSTEM,
            "FINDOMAIN_ERROR",
            str(e)
        )


def run_assetfinder(domain: str, timeout: int = 60) -> ToolResult[SubdomainResult]:
    """
    Runs assetfinder for subdomain enumeration.
    Fast and lightweight tool.

    Args:
        domain: Target domain
        timeout: Maximum execution time in seconds

    Returns:
        ToolResult with SubdomainResult containing unique subdomains found
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("assetfinder"):
        logger.warning("Assetfinder not found in PATH, skipping")
        return tool_missing_result("assetfinder")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Assetfinder on {domain}...")

    try:
        cmd = ["assetfinder", "--subs-only", domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        subdomains = [s for s in subdomains if s.endswith(f".{domain}") or s == domain]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Assetfinder found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="assetfinder",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Assetfinder timed out on {domain}")
        return timeout_result(
            f"Assetfinder timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="assetfinder", count=0, duration_ms=duration_ms)
        )

    except Exception as e:
        logger.error(f"Assetfinder failed on {domain}: {e}")
        return error_result(
            f"Assetfinder failed: {str(e)}",
            ErrorCategory.SYSTEM,
            "ASSETFINDER_ERROR",
            str(e)
        )


def aggregate_subdomain_discovery(
    domain: str,
    use_amass: bool = False,
    use_findomain: bool = True,
    use_assetfinder: bool = True,
    parallel: bool = True
) -> Dict[str, Any]:
    """
    Aggregate results from multiple subdomain enumeration tools.
    Runs tools in parallel for faster results.

    Args:
        domain: Target domain
        use_amass: Include Amass (slower but more comprehensive)
        use_findomain: Include Findomain
        use_assetfinder: Include Assetfinder
        parallel: Run tools in parallel

    Returns:
        Dictionary with aggregated results and per-tool breakdown
    """
    import concurrent.futures

    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        logger.error(f"Invalid domain for aggregation: {domain}")
        return {
            "domain": domain,
            "subdomains": [],
            "sources": {},
            "total_unique": 0,
            "error": validation.error_message
        }

    domain = validation.sanitized_value
    logger.info(f"Starting aggregated subdomain discovery for {domain}")

    results = {
        "domain": domain,
        "subdomains": set(),
        "sources": {},
        "total_unique": 0,
    }

    def run_tool_wrapper(tool_info):
        name, func = tool_info
        try:
            result = func(domain)
            if isinstance(result, ToolResult):
                if result.is_success:
                    return name, result.data.subdomains, None
                else:
                    return name, [], result.error.message if result.error else "Unknown error"
            else:
                return name, result, None
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return name, [], str(e)

    tools_to_run = [("subfinder", run_subfinder)]

    if use_findomain:
        tools_to_run.append(("findomain", run_findomain))
    if use_assetfinder:
        tools_to_run.append(("assetfinder", run_assetfinder))
    if use_amass:
        tools_to_run.append(("amass", lambda d: run_amass(d, passive_only=True)))

    if parallel and len(tools_to_run) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(run_tool_wrapper, t) for t in tools_to_run]
            for future in concurrent.futures.as_completed(futures):
                name, subs, error = future.result()
                if error:
                    results["sources"][name] = {"count": 0, "error": error}
                else:
                    results["sources"][name] = {"count": len(subs)}
                    results["subdomains"].update(subs)
    else:
        for tool_info in tools_to_run:
            name, subs, error = run_tool_wrapper(tool_info)
            if error:
                results["sources"][name] = {"count": 0, "error": error}
            else:
                results["sources"][name] = {"count": len(subs)}
                results["subdomains"].update(subs)

    results["subdomains"] = list(results["subdomains"])
    results["total_unique"] = len(results["subdomains"])

    logger.info(
        f"Aggregated discovery for {domain}: {results['total_unique']} unique subdomains "
        f"from {len(results['sources'])} sources"
    )

    return results

DEFAULT_SCAN_PORTS = os.getenv("SCAN_PORTS", "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090")
DEFAULT_NAABU_RATE_LIMIT = os.getenv("NAABU_RATE_LIMIT", "1000")
MAX_THREADPOOL_WORKERS = int(os.getenv("MAX_THREADPOOL_WORKERS", "4"))


def run_naabu(host: str, ports: str = None, rate_limit: str = None) -> ToolResult[PortScanResult]:
    """
    Runs naabu to scan ports on a host.
    Returns a ToolResult with PortScanResult containing open ports metadata.

    Args:
        host: Target hostname or IP
        ports: Comma-separated ports or ranges (e.g., "80,443,8000-8010")
        rate_limit: Scan rate limit
    """
    if not check_tool("naabu"):
        return tool_missing_result("naabu")

    validation = validate_input(host, InputType.DOMAIN)
    if not validation.is_valid:
        validation = validate_input(host, InputType.IP)
        if not validation.is_valid:
            return invalid_input_result(
                validation.error_message or "Invalid host",
                host
            )

    host = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Naabu on {host}...")

    try:
        ip_address = socket.gethostbyname(host)
        logger.info(f"Resolved {host} to {ip_address}")
    except socket.gaierror as e:
        logger.error(f"Failed to resolve hostname {host}: {e}")
        return error_result(
            f"Failed to resolve hostname: {str(e)}",
            ErrorCategory.BUSINESS,
            "DNS_RESOLUTION_FAILED",
            str(e)
        )

    try:
        ports = ports or DEFAULT_SCAN_PORTS
        rate_limit = rate_limit or DEFAULT_NAABU_RATE_LIMIT

        cmd = ["naabu", "-host", ip_address, "-json", "-p", ports, "-rate", rate_limit, "-silent"]
        logger.debug(f"Executing Naabu command: [REDACTED]")

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        duration_ms = int((time.time() - start_time) * 1000)

        open_ports = []
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                open_ports.append({
                    "port": data.get("port"),
                    "protocol": data.get("protocol", "tcp"),
                    "service_name": "unknown"
                })
            except json.JSONDecodeError:
                pass

        if not open_ports:
             logger.warning(f"Naabu completed but found NO open ports on {host} ({ip_address})")
             return not_found_result(
                 "No open ports found",
                 PortScanResult(host=host, ports=[], count=0, duration_ms=duration_ms)
             )

        logger.info(f"Naabu found {len(open_ports)} open ports on {host} ({ip_address})")

        return success_result(
            PortScanResult(
                host=host,
                ports=open_ports,
                count=len(open_ports),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Naabu timed out on {host}")
        return timeout_result(
            "Naabu timed out after 300s",
            PortScanResult(host=host, ports=[], count=0, duration_ms=duration_ms)
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"Naabu failed on {host}: {e.stderr}")
        return error_result(
            f"Naabu failed: {e.stderr}",
            ErrorCategory.SYSTEM,
            "NAABU_ERROR",
            str(e)
        )

    except Exception as e:
        logger.error(f"Unexpected error running Naabu on {host}: {e}")
        return error_result(
            f"Unexpected error: {str(e)}",
            ErrorCategory.CRITICAL,
            "UNEXPECTED_ERROR",
            str(e)
        )

DEFAULT_NUCLEI_TIMEOUT_TOTAL = int(os.getenv("NUCLEI_TIMEOUT_TOTAL", "600"))
DEFAULT_NUCLEI_RATE_LIMIT = os.getenv("NUCLEI_RATE_LIMIT", "150")
DEFAULT_NUCLEI_TIMEOUT = os.getenv("NUCLEI_TIMEOUT", "5")
DEFAULT_NUCLEI_RETRIES = os.getenv("NUCLEI_RETRIES", "1")
DEFAULT_NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "info,low,medium,high,critical")


def run_nuclei(
    target: str,
    tags: str = None,
    severity: str = None,
    rate_limit: str = None,
    timeout: str = None,
    retries: str = None,
    timeout_total: int = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Runs Nuclei to scan for vulnerabilities.
    Unified function replacing run_nuclei and run_nuclei_with_tags.
    Yields findings (vulnerabilities) as they are found.

    Args:
        target: Target URL or hostname
        tags: Comma-separated Nuclei template tags (if None, runs all templates)
        severity: Severity filter
        rate_limit: Request rate limit
        timeout: Per-request timeout
        retries: Number of retries
        timeout_total: Global timeout for entire scan (default: 600s)
    """
    if not check_tool("nuclei"):
        logger.error("Nuclei not found in PATH")
        return

    validation = validate_input(target, InputType.URL)
    if not validation.is_valid:
        validation = validate_input(target, InputType.DOMAIN)
        if not validation.is_valid:
            logger.error(f"Invalid target for Nuclei: {target}")
            return

    target = validation.sanitized_value
    NUCLEI_TIMEOUT_TOTAL = timeout_total or DEFAULT_NUCLEI_TIMEOUT_TOTAL

    logger.info(f"Running Nuclei on {target} (max {NUCLEI_TIMEOUT_TOTAL}s)...")

    severity = severity or DEFAULT_NUCLEI_SEVERITY
    rate_limit = rate_limit or DEFAULT_NUCLEI_RATE_LIMIT
    timeout = timeout or DEFAULT_NUCLEI_TIMEOUT
    retries = retries or DEFAULT_NUCLEI_RETRIES

    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-silent",
        "-severity", severity,
        "-rate-limit", rate_limit,
        "-timeout", timeout,
        "-retries", retries
    ]

    if tags:
        cmd.extend(["-tags", tags])

    logger.debug(f"Executing Nuclei command: [REDACTED]")

    process = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        import threading
        import queue

        findings_queue: queue.Queue = queue.Queue()
        reader_error: List[Exception] = []

        def read_output():
            """Thread function to read Nuclei output."""
            try:
                if process.stdout:
                    for line in process.stdout:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            finding = {
                                "title": data.get("info", {}).get("name"),
                                "severity": normalize_severity(data.get("info", {}).get("severity")),
                                "description": data.get("info", {}).get("description"),
                                "status": "open",
                                "matched": data.get("matched-at", ""),
                                "template_id": data.get("template-id", ""),
                                "tags": data.get("info", {}).get("tags", []),
                            }
                            findings_queue.put(finding)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                reader_error.append(e)
            finally:
                findings_queue.put(None)

        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()

        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            remaining_timeout = max(0.1, NUCLEI_TIMEOUT_TOTAL - elapsed)

            if elapsed >= NUCLEI_TIMEOUT_TOTAL:
                logger.error(f"Nuclei global timeout ({NUCLEI_TIMEOUT_TOTAL}s) reached on {target}")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                break

            try:
                finding = findings_queue.get(timeout=min(1.0, remaining_timeout))
                if finding is None:
                    break
                yield finding
            except queue.Empty:
                if process.poll() is not None:
                    while True:
                        try:
                            finding = findings_queue.get_nowait()
                            if finding is None:
                                break
                            yield finding
                        except queue.Empty:
                            break
                    break

        reader_thread.join(timeout=5)

        if reader_error:
            logger.error(f"Nuclei reader error on {target}: {reader_error[0]}")

        stderr = process.stderr.read() if process.stderr else ""
        if process.returncode and process.returncode != 0 and stderr:
            logger.error(f"Nuclei process error on {target}: {stderr}")

    except Exception as e:
        logger.error(f"Nuclei failed on {target}: {e}")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def run_nuclei_with_tags(
    target: str,
    tags: str = None,
    severity: str = None,
    rate_limit: str = None,
    timeout: str = None,
    retries: str = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Enhanced Nuclei function with tag-based filtering and configurable parameters.
    Now delegates to unified run_nuclei function.

    Args:
        target: Target URL
        tags: Comma-separated Nuclei template tags (if None, runs all templates)
        severity: Severity filter
        rate_limit: Request rate limit
        timeout: Per-request timeout
        retries: Number of retries
    """
    tags_info = f"tags={tags}" if tags else "all templates"
    logger.info(f"Running Nuclei on {target} ({tags_info})...")

    yield from run_nuclei(
        target=target,
        tags=tags,
        severity=severity,
        rate_limit=rate_limit,
        timeout=timeout,
        retries=retries
    )


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


def run_nuclei_with_tags(
    target: str,
    tags: str = None,
    severity: str = None,
    rate_limit: str = None,
    timeout: str = None,
    retries: str = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Enhanced Nuclei function with tag-based filtering and configurable parameters.

    Args:
        target: Target URL
        tags: Comma-separated Nuclei template tags (if None, runs all templates)
        severity: Severity filter
        rate_limit: Request rate limit
        timeout: Per-request timeout
        retries: Number of retries
    """
    if not check_tool("nuclei"):
        logger.error("Nuclei not found in PATH")
        return

    # Global timeout for entire Nuclei scan
    NUCLEI_TIMEOUT_TOTAL = int(os.getenv("NUCLEI_TIMEOUT_TOTAL", "600"))

    # Use provided params or fall back to env vars
    severity = severity or os.getenv("NUCLEI_SEVERITY", "info,low,medium,high,critical")
    rate_limit = rate_limit or os.getenv("NUCLEI_RATE_LIMIT", "150")
    timeout = timeout or os.getenv("NUCLEI_TIMEOUT", "5")
    retries = retries or os.getenv("NUCLEI_RETRIES", "1")

    tags_info = f"tags={tags}" if tags else "all templates"
    logger.info(f"Running Nuclei on {target} ({tags_info}, max {NUCLEI_TIMEOUT_TOTAL}s)...")

    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-silent",
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-retries", str(retries)
    ]

    # Add tags filter if specified
    if tags:
        cmd.extend(["-tags", tags])

    logger.debug(f"Executing Nuclei command: {' '.join(cmd)}")

    process = None
    try:
        # Use Popen to stream output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        import threading
        import queue
        import time

        # Queue to collect findings from reader thread
        findings_queue: queue.Queue = queue.Queue()
        reader_error: List[Exception] = []

        def read_output():
            """Thread function to read Nuclei output."""
            try:
                if process.stdout:
                    for line in process.stdout:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            finding = {
                                "title": data.get("info", {}).get("name"),
                                "severity": normalize_severity(data.get("info", {}).get("severity")),
                                "description": data.get("info", {}).get("description"),
                                "status": "open",
                                "matched": data.get("matched-at", ""),
                                "template_id": data.get("template-id", ""),
                                "tags": data.get("info", {}).get("tags", []),
                            }
                            findings_queue.put(finding)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                reader_error.append(e)
            finally:
                findings_queue.put(None)  # Signal end of output

        # Start reader thread
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()

        # Yield findings with timeout protection
        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            remaining_timeout = max(0.1, NUCLEI_TIMEOUT_TOTAL - elapsed)

            if elapsed >= NUCLEI_TIMEOUT_TOTAL:
                logger.error(f"Nuclei global timeout ({NUCLEI_TIMEOUT_TOTAL}s) reached on {target}")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                break

            try:
                finding = findings_queue.get(timeout=min(1.0, remaining_timeout))
                if finding is None:  # End signal
                    break
                yield finding
            except queue.Empty:
                # Check if process is still running
                if process.poll() is not None:
                    # Process finished, drain remaining queue
                    while True:
                        try:
                            finding = findings_queue.get_nowait()
                            if finding is None:
                                break
                            yield finding
                        except queue.Empty:
                            break
                    break

        # Wait for reader thread to complete
        reader_thread.join(timeout=5)

        # Check for errors
        if reader_error:
            logger.error(f"Nuclei reader error on {target}: {reader_error[0]}")

        stderr = process.stderr.read() if process.stderr else ""
        if process.returncode and process.returncode != 0 and stderr:
            logger.error(f"Nuclei process error on {target}: {stderr}")

    except Exception as e:
        logger.error(f"Nuclei failed on {target}: {e}")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


# ============================================================================
# PASSIVE RECONNAISSANCE TOOLS
# ============================================================================

def run_dnsx(domain: str, record_types: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run dnsx for DNS record enumeration.

    Args:
        domain: Target domain
        record_types: List of record types (default: a, aaaa, mx, txt, ns, soa, cname)

    Returns:
        Dictionary with record_type -> list of record data
    """
    if not check_tool("dnsx"):
        logger.error("dnsx not found in PATH")
        return {}

    record_types = record_types or ["a", "aaaa", "mx", "txt", "ns", "soa", "cname"]

    logger.info(f"Running dnsx on {domain} for records: {record_types}")

    try:
        cmd = ["dnsx", "-d", domain, "-json", "-silent", "-resp"]
        for rt in record_types:
            cmd.append(f"-{rt}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        records: Dict[str, List[Dict[str, Any]]] = {}

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                # Process each record type
                for rtype in record_types:
                    rtype_upper = rtype.upper()
                    if rtype in data or rtype_upper in data:
                        values = data.get(rtype) or data.get(rtype_upper, [])
                        if not isinstance(values, list):
                            values = [values]

                        if rtype_upper not in records:
                            records[rtype_upper] = []

                        for val in values:
                            record_entry = {
                                "record_type": rtype_upper,
                                "record_value": val if isinstance(val, str) else str(val),
                                "ttl": data.get("ttl"),
                            }
                            # Add priority for MX records
                            if rtype_upper == "MX" and isinstance(val, dict):
                                record_entry["priority"] = val.get("preference")
                                record_entry["record_value"] = val.get("host", str(val))

                            records[rtype_upper].append(record_entry)

            except json.JSONDecodeError:
                continue

        total_records = sum(len(v) for v in records.values())
        logger.info(f"dnsx found {total_records} records for {domain}")
        return records

    except subprocess.TimeoutExpired:
        logger.error(f"dnsx timed out on {domain}")
        return {}
    except Exception as e:
        logger.error(f"dnsx failed on {domain}: {e}")
        return {}


def run_whois(domain: str) -> Dict[str, Any]:
    """
    Run WHOIS lookup using python-whois.

    Returns:
        Dictionary with WHOIS data
    """
    logger.info(f"Running WHOIS lookup for {domain}")

    try:
        import whois
        w = whois.whois(domain)

        # Handle dates that might be lists
        def parse_date(d):
            if isinstance(d, list):
                d = d[0] if d else None
            if isinstance(d, datetime):
                return d.isoformat()
            return str(d) if d else None

        # Handle name servers
        name_servers = w.name_servers
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        elif name_servers:
            name_servers = list(set(ns.lower() for ns in name_servers if ns))

        result = {
            "registrar": w.registrar,
            "creation_date": parse_date(w.creation_date),
            "expiration_date": parse_date(w.expiration_date),
            "updated_date": parse_date(w.updated_date),
            "name_servers": json.dumps(name_servers) if name_servers else None,
            "registrant_org": getattr(w, 'org', None),
            "registrant_country": getattr(w, 'country', None),
            "registrant_email": getattr(w, 'emails', [None])[0] if isinstance(getattr(w, 'emails', None), list) else getattr(w, 'emails', None),
            "dnssec": getattr(w, 'dnssec', None),
            "raw_data": w.text[:10000] if hasattr(w, 'text') else None  # Limit raw data size
        }

        logger.info(f"WHOIS lookup successful for {domain}: registrar={result.get('registrar')}")
        return result

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return {}


def query_crtsh(domain: str, timeout: int = 30) -> List[Dict[str, Any]]:
    """
    Query crt.sh for Certificate Transparency logs.
    Free API, no key required.

    Returns:
        List of certificate records
    """
    logger.info(f"Querying crt.sh for {domain}")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        certs_raw = response.json()

        # Deduplicate by serial number
        seen_serials = set()
        certs = []

        for cert in certs_raw:
            serial = cert.get("serial_number")
            if serial in seen_serials:
                continue
            seen_serials.add(serial)

            # Parse SANs (Subject Alternative Names)
            name_value = cert.get("name_value", "")
            sans = [n.strip() for n in name_value.split("\n") if n.strip()] if name_value else []

            certs.append({
                "serial_number": serial,
                "issuer_cn": cert.get("issuer_name"),
                "issuer_org": None,  # Not available from crt.sh
                "subject_cn": cert.get("common_name"),
                "subject_alt_names": json.dumps(sans),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "is_wildcard": "*" in cert.get("common_name", ""),
                "source": "crt.sh"
            })

        logger.info(f"crt.sh found {len(certs)} unique certificates for {domain}")
        return certs[:500]  # Limit to prevent memory issues

    except requests.exceptions.Timeout:
        logger.error(f"crt.sh query timed out for {domain}")
        return []
    except Exception as e:
        logger.error(f"crt.sh query failed for {domain}: {e}")
        return []


def lookup_asn(ip: str) -> Dict[str, Any]:
    """
    Look up ASN information for an IP address.
    Uses BGPView API (free, no key required).

    Returns:
        Dictionary with ASN data
    """
    logger.info(f"Looking up ASN for {ip}")

    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json().get("data", {})
        prefixes = data.get("prefixes", [])

        if prefixes:
            prefix = prefixes[0]
            asn = prefix.get("asn", {})
            result = {
                "ip_address": ip,
                "asn_number": asn.get("asn"),
                "asn_name": asn.get("name"),
                "asn_description": asn.get("description"),
                "asn_country": asn.get("country_code"),
                "bgp_prefix": prefix.get("prefix"),
                "rir": data.get("rir_allocation", {}).get("rir_name")
            }
            logger.info(f"ASN lookup for {ip}: AS{result.get('asn_number')} - {result.get('asn_name')}")
            return result

        logger.warning(f"No ASN data found for {ip}")
        return {"ip_address": ip}

    except Exception as e:
        logger.error(f"ASN lookup failed for {ip}: {e}")
        return {"ip_address": ip}


def run_reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup (PTR record).

    Returns:
        Hostname or None
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        logger.info(f"Reverse DNS: {ip} -> {hostname}")
        return hostname
    except socket.herror:
        logger.debug(f"No PTR record for {ip}")
        return None
    except Exception as e:
        logger.error(f"Reverse DNS failed for {ip}: {e}")
        return None


def run_tlsx(target: str, port: int = 443) -> Dict[str, Any]:
    """
    Run tlsx for SSL/TLS certificate analysis.

    Returns:
        Dictionary with certificate details
    """
    if not check_tool("tlsx"):
        logger.error("tlsx not found in PATH")
        return {}

    logger.info(f"Running tlsx on {target}:{port}")

    try:
        cmd = [
            "tlsx",
            "-u", f"{target}:{port}",
            "-json",
            "-silent",
            "-san",
            "-cn",
            "-so",      # Subject organization
            "-tv",      # TLS version
            "-cipher",
            "-hash", "sha256",
            "-expired",
            "-self-signed",
            "-wildcard-cert"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                # Parse SANs
                sans = data.get("san", [])
                if isinstance(sans, str):
                    sans = [sans]

                cert_result = {
                    "serial_number": data.get("serial"),
                    "issuer_cn": data.get("issuer_cn"),
                    "issuer_org": data.get("issuer_org"),
                    "subject_cn": data.get("subject_cn"),
                    "subject_alt_names": json.dumps(sans),
                    "not_before": data.get("not_before"),
                    "not_after": data.get("not_after"),
                    "signature_algorithm": data.get("signature_alg"),
                    "key_algorithm": data.get("pubkey_algorithm"),
                    "key_size": data.get("pubkey_bits"),
                    "is_self_signed": data.get("self_signed", False),
                    "is_expired": data.get("expired", False),
                    "is_wildcard": data.get("wildcard_cert", False),
                    "fingerprint_sha256": data.get("fingerprint_hash", {}).get("sha256"),
                    "tls_version": data.get("tls_version"),
                    "source": "tlsx"
                }

                logger.info(f"tlsx: {target}:{port} - CN={cert_result.get('subject_cn')}, expires={cert_result.get('not_after')}")
                return cert_result

            except json.JSONDecodeError:
                continue

        logger.warning(f"tlsx returned no data for {target}:{port}")
        return {}

    except subprocess.TimeoutExpired:
        logger.error(f"tlsx timed out on {target}:{port}")
        return {}
    except Exception as e:
        logger.error(f"tlsx failed on {target}:{port}: {e}")
        return {}


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


# ============================================================================
# EXTERNAL API INTEGRATIONS
# ============================================================================

def query_shodan(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Query Shodan API for IP intelligence.

    Args:
        ip: Target IP address
        api_key: Shodan API key

    Returns:
        Dictionary with Shodan data
    """
    if not api_key:
        logger.warning("Shodan API key not configured")
        return {}

    logger.info(f"Querying Shodan for {ip}")

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": api_key}

        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 404:
            logger.info(f"No Shodan data for {ip}")
            return {"ip_address": ip}

        response.raise_for_status()
        data = response.json()

        result = {
            "ip_address": ip,
            "open_ports": json.dumps(data.get("ports", [])),
            "hostnames": json.dumps(data.get("hostnames", [])),
            "domains": json.dumps(data.get("domains", [])),
            "os": data.get("os"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "city": data.get("city"),
            "region": data.get("region_code"),
            "country": data.get("country_name"),
            "latitude": str(data.get("latitude")) if data.get("latitude") else None,
            "longitude": str(data.get("longitude")) if data.get("longitude") else None,
            "last_update": data.get("last_update"),
            "vulns": json.dumps(data.get("vulns", [])),
            "tags": json.dumps(data.get("tags", [])),
            "raw_data": json.dumps(data)[:50000],  # Limit size
        }

        logger.info(f"Shodan: {ip} has {len(data.get('ports', []))} open ports")
        return result

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logger.error("Shodan API key is invalid")
        else:
            logger.error(f"Shodan API error for {ip}: {e}")
        return {"ip_address": ip}
    except Exception as e:
        logger.error(f"Shodan query failed for {ip}: {e}")
        return {"ip_address": ip}


def query_securitytrails(domain: str, api_key: str) -> Dict[str, Any]:
    """
    Query SecurityTrails API for DNS history and subdomains.

    Returns:
        Dictionary with DNS history and subdomain data
    """
    if not api_key:
        logger.warning("SecurityTrails API key not configured")
        return {}

    logger.info(f"Querying SecurityTrails for {domain}")

    headers = {"APIKEY": api_key}

    try:
        result = {"domain": domain, "subdomains": [], "dns_history": []}

        # Get subdomains
        subs_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        subs_resp = requests.get(subs_url, headers=headers, timeout=30)
        subs_resp.raise_for_status()

        subdomains_data = subs_resp.json().get("subdomains", [])
        result["subdomains"] = [f"{sub}.{domain}" for sub in subdomains_data]

        # Get DNS history (A records)
        hist_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        hist_resp = requests.get(hist_url, headers=headers, timeout=30)
        hist_resp.raise_for_status()

        result["dns_history"] = hist_resp.json().get("records", [])

        logger.info(f"SecurityTrails: {domain} has {len(result['subdomains'])} subdomains")
        return result

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logger.error("SecurityTrails API key is invalid")
        else:
            logger.error(f"SecurityTrails API error for {domain}: {e}")
        return {}
    except Exception as e:
        logger.error(f"SecurityTrails query failed for {domain}: {e}")
        return {}


def query_censys(target: str, api_id: str, api_secret: str) -> Dict[str, Any]:
    """
    Query Censys API for certificate and host data.

    Returns:
        Dictionary with Censys data
    """
    if not api_id or not api_secret:
        logger.warning("Censys API credentials not configured")
        return {}

    logger.info(f"Querying Censys for {target}")

    try:
        # Try to resolve to IP if it's a hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            ip = target

        # Query Censys hosts endpoint
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        auth = (api_id, api_secret)

        response = requests.get(url, auth=auth, timeout=30)

        if response.status_code == 404:
            logger.info(f"No Censys data for {target}")
            return {}

        response.raise_for_status()
        data = response.json().get("result", {})

        result = {
            "ip": ip,
            "services": json.dumps(data.get("services", [])),
            "location": json.dumps(data.get("location", {})),
            "autonomous_system": json.dumps(data.get("autonomous_system", {})),
            "operating_system": json.dumps(data.get("operating_system", {})),
            "last_updated": data.get("last_updated_at"),
        }

        logger.info(f"Censys: {target} has {len(data.get('services', []))} services")
        return result

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logger.error("Censys API credentials are invalid")
        else:
            logger.error(f"Censys API error for {target}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Censys query failed for {target}: {e}")
        return {}


def query_hackertarget(domain: str, api_key: str = None) -> Dict[str, Any]:
    """
    Query HackerTarget API for reconnaissance data.
    Free tier available, optional API key for higher limits.

    Returns:
        Dictionary with reconnaissance data
    """
    logger.info(f"Querying HackerTarget for {domain}")

    base_url = "https://api.hackertarget.com"
    params = {"apikey": api_key} if api_key else {}

    results = {}

    try:
        # DNS lookup
        dns_resp = requests.get(f"{base_url}/dnslookup/", params={"q": domain, **params}, timeout=15)
        if dns_resp.status_code == 200 and "error" not in dns_resp.text.lower():
            results["dns_lookup"] = dns_resp.text

        # HTTP headers
        headers_resp = requests.get(f"{base_url}/httpheaders/", params={"q": domain, **params}, timeout=15)
        if headers_resp.status_code == 200 and "error" not in headers_resp.text.lower():
            results["http_headers"] = headers_resp.text

        # Reverse DNS
        try:
            ip = socket.gethostbyname(domain)
            rdns_resp = requests.get(f"{base_url}/reversedns/", params={"q": ip, **params}, timeout=15)
            if rdns_resp.status_code == 200 and "error" not in rdns_resp.text.lower():
                results["reverse_dns"] = rdns_resp.text
        except socket.gaierror:
            pass

        logger.info(f"HackerTarget: collected {len(results)} data types for {domain}")
        return results

    except Exception as e:
        logger.error(f"HackerTarget query failed for {domain}: {e}")
        return {}
