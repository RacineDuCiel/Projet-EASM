"""
Scan tasks for port scanning, technology detection, and vulnerability detection.
Implements real-time vulnerability streaming and technology-based template prioritization.
"""
import logging
from typing import List, Dict, Any, Set
from src.celery_app import app
from src import tools
from src.tech_mapping import build_nuclei_tags_argument, get_technology_summary
from src.utils import log_event, post_to_backend, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


@app.task(
    name='src.tasks.port_scan_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def port_scan_task(asset: Dict[str, Any], scan_id: str, scan_config: Dict = None) -> Dict[str, Any]:
    """
    Step 1: Port scanning with Naabu
    Uses configured ports based on scan depth.
    If specific_port is set, skip Naabu and use that port directly.
    """
    domain = asset["value"]
    scan_config = scan_config or {}
    ports = scan_config.get("ports")
    specific_port = scan_config.get("specific_port")

    logger.info(f"Running port scan on {domain}...")
    log_event(scan_id, f"Starting port scan on {domain}...")

    try:
        # If specific port is provided, skip Naabu discovery
        if specific_port:
            logger.info(f"Using specific port {specific_port} for {domain} (skipping Naabu)")
            log_event(scan_id, f"Using specified port {specific_port} on {domain}")
            open_ports = [{
                "port": specific_port,
                "protocol": "tcp",
                "service_name": "http"  # Assume HTTP for now
            }]
        else:
            # Run Naabu for port discovery
            open_ports = tools.run_naabu(domain, ports=ports)

        asset["services"] = open_ports

        log_event(scan_id, f"Port scan finished on {domain}. Found {len(open_ports)} ports.")

        if open_ports:
            try:
                resp = post_to_backend(f"/scans/{scan_id}/assets", [asset])
                resp.raise_for_status()
                logger.info(f"Sent {len(open_ports)} services to backend for {domain}")
            except Exception as e:
                logger.error(f"Error sending services for {domain}: {e}", exc_info=True)
                raise

        return asset
    except Exception as e:
        logger.error(f"Port scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Port scan failed on {domain}: {str(e)}", "error")
        asset["services"] = []
        return asset


@app.task(
    name='src.tasks.tech_detect_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 60},
    retry_backoff=True
)
def tech_detect_task(asset: Dict[str, Any], scan_id: str, scan_config: Dict = None) -> Dict[str, Any]:
    """
    Step 2: Technology detection using httpx.
    Runs after port scan, before vulnerability scan.
    Detects technologies to prioritize Nuclei templates.
    """
    domain = asset["value"]
    services = asset.get("services", [])

    logger.info(f"Running tech detection on {domain} for {len(services)} services")
    log_event(scan_id, f"Starting technology detection on {domain}...")

    detected_technologies: List[str] = []
    tech_by_port: Dict[int, Dict] = {}

    try:
        if services:
            for service in services:
                port = service.get("port")
                if not port:
                    continue

                # Run httpx on this port
                tech_info = tools.run_httpx(domain, port)

                if tech_info.get("technologies"):
                    tech_by_port[port] = tech_info
                    detected_technologies.extend(tech_info.get("technologies", []))

                    # Report to backend
                    _report_tech_detection(domain, port, tech_info, scan_id)
        else:
            # No ports discovered, try default HTTP/HTTPS
            for port in [80, 443]:
                tech_info = tools.run_httpx(domain, port)
                if tech_info.get("technologies"):
                    tech_by_port[port] = tech_info
                    detected_technologies.extend(tech_info.get("technologies", []))
                    _report_tech_detection(domain, port, tech_info, scan_id)

        # Deduplicate technologies
        unique_techs = list(set(detected_technologies))
        asset["detected_technologies"] = unique_techs
        asset["tech_by_port"] = tech_by_port

        tech_count = len(unique_techs)
        if tech_count > 0:
            summary = get_technology_summary(unique_techs)
            log_event(scan_id, f"Tech detection on {domain}: {summary}")
        else:
            log_event(scan_id, f"Tech detection on {domain}: no technologies detected")

        logger.info(f"Tech detection completed for {domain}: {tech_count} unique technologies")
        return asset

    except Exception as e:
        logger.error(f"Tech detection failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Tech detection failed on {domain}: {str(e)}", "error")
        asset["detected_technologies"] = []
        asset["tech_by_port"] = {}
        return asset


def _report_tech_detection(domain: str, port: int, tech_info: Dict, scan_id: str) -> None:
    """Report tech detection results to backend."""
    try:
        tls_info = tech_info.get("tls", {})
        tls_version = tls_info.get("version") if isinstance(tls_info, dict) else None

        payload = {
            "asset_value": domain,
            "port": port,
            "technologies": tech_info.get("technologies", []),
            "web_server": tech_info.get("web_server"),
            "waf_detected": tech_info.get("waf"),
            "tls_version": tls_version,
            "response_time_ms": int(float(tech_info.get("response_time", 0)) * 1000) if tech_info.get("response_time") else None
        }

        resp = post_to_backend(f"/scans/{scan_id}/tech-detect", payload)
        resp.raise_for_status()
        logger.debug(f"Reported tech detection for {domain}:{port}")

    except Exception as e:
        logger.error(f"Failed to report tech detection for {domain}:{port}: {e}")


@app.task(
    name='src.tasks.vuln_scan_prioritized_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def vuln_scan_prioritized_task(asset: Dict[str, Any], scan_id: str, scan_config: Dict = None) -> Dict[str, Any]:
    """
    Phase 4: Prioritized vulnerability scanning with Nuclei.
    Uses detected technologies to run targeted templates first.
    Controlled by run_prioritized_templates flag.
    """
    scan_config = scan_config or {}

    # Check if prioritized scanning is enabled
    if not scan_config.get("run_prioritized_templates", True):
        logger.info(f"Prioritized vuln scan skipped (disabled in profile)")
        asset["seen_titles"] = []
        asset["vuln_count_prioritized"] = 0
        return asset

    domain = asset["value"]
    services = asset.get("services", [])
    detected_techs = asset.get("detected_technologies", [])

    logger.info(f"Starting prioritized vuln scan for {domain}")
    log_event(scan_id, f"Starting vulnerability scan on {domain}...")

    try:
        targets = _build_target_urls(domain, services)
        vuln_count = 0
        seen_titles: Set[str] = set()

        # Build tags based on detected technologies
        nuclei_tags = None
        if detected_techs:
            nuclei_tags = build_nuclei_tags_argument(
                detected_techs,
                include_critical=True
            )
            tech_summary = ", ".join(detected_techs[:5])
            if len(detected_techs) > 5:
                tech_summary += f" (+{len(detected_techs) - 5} more)"
            log_event(scan_id, f"Running targeted templates for: {tech_summary}")
        else:
            log_event(scan_id, f"No technologies detected, running critical/generic templates")
            # Even without tech detection, run critical generic tags
            nuclei_tags = build_nuclei_tags_argument([], include_critical=True)

        # Get config parameters
        rate_limit = str(scan_config.get("nuclei_rate_limit", 150))
        timeout = str(scan_config.get("nuclei_timeout", 5))
        retries = str(scan_config.get("nuclei_retries", 1))

        # Run Nuclei with technology-specific tags
        for target_url in targets:
            for finding in tools.run_nuclei_with_tags(
                target_url,
                tags=nuclei_tags,
                rate_limit=rate_limit,
                timeout=timeout,
                retries=retries
            ):
                if finding["title"] in seen_titles:
                    continue

                seen_titles.add(finding["title"])
                vuln_count += 1
                _stream_vulnerability(domain, finding, scan_id)

        log_event(scan_id, f"Prioritized scan on {domain}: found {vuln_count} vulnerabilities")
        logger.info(f"Prioritized vuln scan completed for {domain}: {vuln_count} vulnerabilities")

        # Store seen titles for deduplication in full scan
        asset["seen_titles"] = list(seen_titles)
        asset["vuln_count_prioritized"] = vuln_count
        return asset

    except Exception as e:
        logger.error(f"Prioritized vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Vuln scan failed on {domain}: {str(e)}", "error")
        asset["seen_titles"] = []
        asset["vuln_count_prioritized"] = 0
        return asset


@app.task(
    name='src.tasks.vuln_scan_full_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 300},
    retry_backoff=True
)
def vuln_scan_full_task(asset: Dict[str, Any], scan_id: str, scan_config: Dict = None) -> Dict[str, Any]:
    """
    Phase 5: Full vulnerability scanning (deep_analysis phase).
    Runs all Nuclei templates without tag filtering.
    Skips vulnerabilities already found in prioritized scan.
    Controlled by run_full_templates flag.
    """
    scan_config = scan_config or {}

    if not scan_config.get("run_full_templates", False):
        logger.info(f"Full vuln scan skipped (not enabled in profile)")
        return asset

    domain = asset["value"]
    services = asset.get("services", [])
    seen_titles = set(asset.get("seen_titles", []))  # Skip already found vulns

    logger.info(f"Starting FULL vuln scan for {domain} (deep mode)")
    log_event(scan_id, f"Starting comprehensive scan on {domain} (deep mode)...")

    try:
        targets = _build_target_urls(domain, services)
        vuln_count = 0

        # Get config parameters (use more conservative settings for full scan)
        rate_limit = str(scan_config.get("nuclei_rate_limit", 100))
        timeout = str(scan_config.get("nuclei_timeout", 10))
        retries = str(scan_config.get("nuclei_retries", 3))

        # Run Nuclei WITHOUT tag filtering for comprehensive coverage
        for target_url in targets:
            for finding in tools.run_nuclei_with_tags(
                target_url,
                tags=None,  # No tag filtering - run all templates
                rate_limit=rate_limit,
                timeout=timeout,
                retries=retries
            ):
                if finding["title"] in seen_titles:
                    continue

                seen_titles.add(finding["title"])
                vuln_count += 1
                _stream_vulnerability(domain, finding, scan_id)

        log_event(scan_id, f"Full scan on {domain}: found {vuln_count} additional vulnerabilities")
        logger.info(f"Full vuln scan completed for {domain}: {vuln_count} additional vulnerabilities")

        asset["vuln_count_full"] = vuln_count
        return asset

    except Exception as e:
        logger.error(f"Full vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Full scan failed on {domain}: {str(e)}", "error")
        asset["vuln_count_full"] = 0
        return asset


# Legacy task for backward compatibility
@app.task(
    name='src.tasks.vuln_scan_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def vuln_scan_task(asset: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """
    Legacy vulnerability scanning task.
    Kept for backward compatibility with existing scans.
    """
    domain = asset["value"]
    services = asset.get("services", [])

    logger.info(f"Starting vulnerability scan for {domain} with {len(services)} services")
    log_event(scan_id, f"Starting vulnerability scan on {domain}...")

    try:
        targets = _build_target_urls(domain, services)
        vuln_count = 0
        seen_titles: Set[str] = set()

        for target_url in targets:
            for finding in tools.run_nuclei(target_url):
                if finding["title"] in seen_titles:
                    continue

                seen_titles.add(finding["title"])
                vuln_count += 1
                _stream_vulnerability(domain, finding, scan_id)

        logger.info(f"Vulnerability scan completed for {domain}: {vuln_count} unique vulnerabilities")
        log_event(scan_id, f"Vuln scan finished on {domain}. Found {vuln_count} vulnerabilities.")

        asset["vulnerabilities"] = []
        return asset

    except Exception as e:
        logger.error(f"Vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Vuln scan failed on {domain}: {str(e)}", "error")
        asset["vulnerabilities"] = []
        return asset


def _stream_vulnerability(domain: str, finding: Dict, scan_id: str) -> None:
    """
    Send vulnerability to backend via streaming endpoint.
    Enables real-time display in Dashboard.
    """
    try:
        # Parse port from matched URL if available
        port = None
        matched = finding.get("matched", "")
        if ":" in matched:
            try:
                # Extract port from URL like https://domain:8443/path
                port_str = matched.split(":")[-1].split("/")[0]
                port = int(port_str)
            except (ValueError, IndexError):
                pass

        payload = {
            "asset_value": domain,
            "asset_type": "subdomain",
            "title": finding["title"],
            "severity": finding["severity"],
            "description": finding.get("description", ""),
            "port": port,
            "service_name": finding.get("service_name")
        }

        resp = post_to_backend(f"/scans/{scan_id}/vulnerabilities", payload)
        resp.raise_for_status()
        logger.info(f"Streamed vulnerability: {finding['title']} ({finding['severity']}) on {domain}")

    except Exception as e:
        logger.error(f"Failed to stream vulnerability {finding.get('title', 'Unknown')}: {e}")


def _build_target_urls(domain: str, services: List[Dict]) -> List[str]:
    """Build list of target URLs from domain and discovered services."""
    targets: Set[str] = set()

    if services:
        for service in services:
            port = service.get("port")
            if not port:
                continue

            service_name = service.get("service_name", "").lower()

            if port == 443 or service_name in ["https", "ssl", "tls"]:
                targets.add(f"https://{domain}:{port}")
            elif port == 80:
                targets.add(f"http://{domain}:{port}")
            else:
                # For unknown ports, try both protocols
                targets.add(f"http://{domain}:{port}")
                targets.add(f"https://{domain}:{port}")
    else:
        logger.warning(f"No ports discovered for {domain}, using default HTTP/HTTPS")
        targets.add(f"http://{domain}")
        targets.add(f"https://{domain}")

    return list(targets)
