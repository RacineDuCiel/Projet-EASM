"""
Passive Reconnaissance tasks for EASM.
Implements depth-based passive scanning (fast/deep) with optional API integrations.

Fast mode: DNS records, WHOIS, Certificate Transparency, ASN lookup, reverse DNS
Deep mode: + tlsx, katana, waybackurls, gau, security headers, favicon hash, + API integrations
"""
import logging
import socket
from typing import Dict, Any, List
from celery import chain, group, chord
from src.celery_app import app
from src import tools
from src.utils import log_event, post_to_backend

logger = logging.getLogger(__name__)


@app.task(name='src.tasks.passive_recon_orchestrator', queue='discovery')
def passive_recon_orchestrator(target: str, scan_id: str, scan_config: Dict[str, Any] = None):
    """
    Orchestrate passive reconnaissance based on scan depth.

    Args:
        target: Domain to scan
        scan_id: Scan UUID
        scan_config: Configuration including:
            - scan_depth: "fast" or "deep" (controls which tools run)
            - api_keys: Dict of available API keys
            - enable_web_archive: Whether to query web archive (deep mode)
            - enable_crawling: Whether to crawl the target (deep mode)
    """
    scan_config = scan_config or {}
    scan_depth = scan_config.get("scan_depth", "fast")
    api_keys = scan_config.get("api_keys", {})

    logger.info(f"Starting passive recon for {target} (depth: {scan_depth})")
    log_event(scan_id, f"Starting passive reconnaissance ({scan_depth} mode)")

    # FAST MODE - Essential tasks (always run in parallel)
    essential_tasks = [
        dns_records_task.s(target, scan_id),
        whois_lookup_task.s(target, scan_id),
        cert_transparency_task.s(target, scan_id),
        asn_lookup_task.s(target, scan_id),
        reverse_dns_task.s(target, scan_id),
    ]

    # Add HackerTarget (free API, always available)
    essential_tasks.append(hackertarget_task.s(target, scan_id, api_keys.get("hackertarget_key")))

    # DEEP MODE - Extended tasks
    extended_tasks = []
    if scan_depth == "deep":
        extended_tasks = [
            tlsx_task.s(target, scan_id),
            security_headers_task.s(target, scan_id),
            favicon_hash_task.s(target, scan_id),
        ]

        # Crawling and URL discovery (if enabled)
        if scan_config.get("enable_crawling", True):
            extended_tasks.append(katana_task.s(target, scan_id))

        if scan_config.get("enable_web_archive", True):
            extended_tasks.append(waybackurls_task.s(target, scan_id))
            extended_tasks.append(gau_task.s(target, scan_id))

        # Add paid API integrations if keys are configured
        if api_keys.get("shodan_key"):
            extended_tasks.append(shodan_task.s(target, scan_id, api_keys["shodan_key"]))

        if api_keys.get("securitytrails_key"):
            extended_tasks.append(securitytrails_task.s(target, scan_id, api_keys["securitytrails_key"]))

        if api_keys.get("censys_id") and api_keys.get("censys_secret"):
            extended_tasks.append(censys_task.s(target, scan_id, api_keys["censys_id"], api_keys["censys_secret"]))

    # Build workflow based on depth
    if scan_depth == "deep" and extended_tasks:
        # Run essential first, then extended, then finalize
        all_tasks = essential_tasks + extended_tasks
        workflow = chord(group(all_tasks), finalize_passive_recon.s(target, scan_id))
    else:
        # Fast mode: just essential tasks
        workflow = chord(group(essential_tasks), finalize_passive_recon.s(target, scan_id))

    workflow.apply_async()
    return {"status": "started", "depth": scan_depth, "target": target}


# ============================================================================
# ESSENTIAL TASKS (FAST MODE)
# ============================================================================

@app.task(
    name='src.tasks.dns_records_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 30},
    retry_backoff=True
)
def dns_records_task(target: str, scan_id: str) -> Dict[str, Any]:
    """DNS record enumeration using dnsx."""
    log_event(scan_id, f"Collecting DNS records for {target}")

    try:
        records = tools.run_dnsx(target)

        if records:
            # Flatten records for API
            flat_records = []
            for record_type, record_list in records.items():
                flat_records.extend(record_list)

            post_to_backend(f"/scans/{scan_id}/passive-intel/dns", {
                "asset_value": target,
                "records": flat_records
            })

            total = sum(len(v) for v in records.values())
            log_event(scan_id, f"DNS: Found {total} records for {target}")

        return {"dns_records": records, "target": target}

    except Exception as e:
        logger.error(f"DNS records task failed for {target}: {e}")
        log_event(scan_id, f"DNS records collection failed: {str(e)}", "warning")
        return {"dns_records": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.whois_lookup_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 30},
    retry_backoff=True
)
def whois_lookup_task(target: str, scan_id: str) -> Dict[str, Any]:
    """WHOIS lookup for domain registration info."""
    log_event(scan_id, f"Looking up WHOIS for {target}")

    try:
        whois_data = tools.run_whois(target)

        if whois_data and whois_data.get("registrar"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/whois", {
                "asset_value": target,
                "whois_data": whois_data
            })
            log_event(scan_id, f"WHOIS: Registrar={whois_data.get('registrar', 'N/A')}")

        return {"whois": whois_data, "target": target}

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {target}: {e}")
        log_event(scan_id, f"WHOIS lookup failed: {str(e)}", "warning")
        return {"whois": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.cert_transparency_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 60},
    retry_backoff=True
)
def cert_transparency_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Query Certificate Transparency logs via crt.sh."""
    log_event(scan_id, f"Querying CT logs for {target}")

    try:
        certs = tools.query_crtsh(target)

        if certs:
            post_to_backend(f"/scans/{scan_id}/passive-intel/certificates", {
                "asset_value": target,
                "certificates": certs
            })
            log_event(scan_id, f"CT Logs: Found {len(certs)} certificates")

        return {"certificates": certs, "target": target}

    except Exception as e:
        logger.error(f"CT lookup failed for {target}: {e}")
        log_event(scan_id, f"CT lookup failed: {str(e)}", "warning")
        return {"certificates": [], "target": target, "error": str(e)}


@app.task(
    name='src.tasks.asn_lookup_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 30},
    retry_backoff=True
)
def asn_lookup_task(target: str, scan_id: str) -> Dict[str, Any]:
    """ASN lookup for IP intelligence."""
    log_event(scan_id, f"Looking up ASN for {target}")

    try:
        # Resolve to IP first
        ip = socket.gethostbyname(target)
        asn_data = tools.lookup_asn(ip)

        if asn_data and asn_data.get("asn_number"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/asn", {
                "asset_value": target,
                "asn_data": asn_data
            })
            log_event(scan_id, f"ASN: {asn_data.get('asn_name', 'N/A')} (AS{asn_data.get('asn_number', 'N/A')})")

        return {"asn": asn_data, "target": target, "ip": ip}

    except socket.gaierror as e:
        logger.warning(f"Could not resolve {target} for ASN lookup: {e}")
        log_event(scan_id, f"ASN lookup skipped: could not resolve {target}", "warning")
        return {"asn": {}, "target": target, "error": "DNS resolution failed"}
    except Exception as e:
        logger.error(f"ASN lookup failed for {target}: {e}")
        return {"asn": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.reverse_dns_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 15},
    retry_backoff=True
)
def reverse_dns_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Reverse DNS (PTR) lookup."""
    log_event(scan_id, f"Performing reverse DNS for {target}")

    try:
        ip = socket.gethostbyname(target)
        hostname = tools.run_reverse_dns(ip)

        if hostname:
            post_to_backend(f"/scans/{scan_id}/passive-intel/reverse-dns", {
                "asset_value": target,
                "ip_address": ip,
                "ptr_hostname": hostname
            })
            log_event(scan_id, f"Reverse DNS: {ip} -> {hostname}")

        return {"reverse_dns": {"ip": ip, "hostname": hostname}, "target": target}

    except socket.gaierror:
        return {"reverse_dns": {}, "target": target, "error": "DNS resolution failed"}
    except Exception as e:
        logger.error(f"Reverse DNS failed for {target}: {e}")
        return {"reverse_dns": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.hackertarget_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 30},
    retry_backoff=True
)
def hackertarget_task(target: str, scan_id: str, api_key: str = None) -> Dict[str, Any]:
    """Query HackerTarget API (free)."""
    log_event(scan_id, f"Querying HackerTarget for {target}")

    try:
        ht_data = tools.query_hackertarget(target, api_key)

        if ht_data:
            post_to_backend(f"/scans/{scan_id}/passive-intel/hackertarget", {
                "asset_value": target,
                "hackertarget_data": ht_data
            })
            log_event(scan_id, f"HackerTarget: Collected {len(ht_data)} data types")

        return {"hackertarget": ht_data, "target": target}

    except Exception as e:
        logger.error(f"HackerTarget query failed for {target}: {e}")
        return {"hackertarget": {}, "target": target, "error": str(e)}


# ============================================================================
# EXTENDED TASKS (DEEP MODE)
# ============================================================================

@app.task(
    name='src.tasks.tlsx_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 30},
    retry_backoff=True
)
def tlsx_task(target: str, scan_id: str) -> Dict[str, Any]:
    """TLS/SSL certificate analysis using tlsx."""
    log_event(scan_id, f"Analyzing TLS certificates for {target}")

    try:
        cert_data = tools.run_tlsx(target, port=443)

        if cert_data and cert_data.get("subject_cn"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/tls-cert", {
                "asset_value": target,
                "certificate": cert_data
            })
            log_event(scan_id, f"TLS: CN={cert_data.get('subject_cn')}, expires {cert_data.get('not_after', 'N/A')}")

        return {"tls_cert": cert_data, "target": target}

    except Exception as e:
        logger.error(f"tlsx failed for {target}: {e}")
        return {"tls_cert": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.katana_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 60},
    retry_backoff=True
)
def katana_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Web crawling for endpoint discovery using katana."""
    log_event(scan_id, f"Crawling {target} for endpoints")

    try:
        endpoints = tools.run_katana(target, depth=2, timeout=300)

        if endpoints:
            post_to_backend(f"/scans/{scan_id}/passive-intel/endpoints", {
                "asset_value": target,
                "endpoints": endpoints[:500]  # Limit to prevent overload
            })

            js_count = sum(1 for e in endpoints if e.get("is_js_file"))
            api_count = sum(1 for e in endpoints if e.get("is_api_endpoint"))
            log_event(scan_id, f"Katana: Found {len(endpoints)} endpoints ({js_count} JS, {api_count} API)")

        return {"endpoints": endpoints, "target": target}

    except Exception as e:
        logger.error(f"Katana failed for {target}: {e}")
        return {"endpoints": [], "target": target, "error": str(e)}


@app.task(
    name='src.tasks.waybackurls_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 60},
    retry_backoff=True
)
def waybackurls_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Fetch historical URLs from Web Archive."""
    log_event(scan_id, f"Fetching Web Archive URLs for {target}")

    try:
        urls = tools.run_waybackurls(target)

        if urls:
            post_to_backend(f"/scans/{scan_id}/passive-intel/historical-urls", {
                "asset_value": target,
                "urls": urls,
                "source": "wayback"
            })
            log_event(scan_id, f"Wayback: Found {len(urls)} historical URLs")

        return {"historical_urls": urls, "target": target, "source": "wayback"}

    except Exception as e:
        logger.error(f"Waybackurls failed for {target}: {e}")
        return {"historical_urls": [], "target": target, "error": str(e)}


@app.task(
    name='src.tasks.gau_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 60},
    retry_backoff=True
)
def gau_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Aggregate URLs from multiple sources using gau."""
    log_event(scan_id, f"Running GAU URL aggregation for {target}")

    try:
        urls = tools.run_gau(target)

        if urls:
            post_to_backend(f"/scans/{scan_id}/passive-intel/historical-urls", {
                "asset_value": target,
                "urls": urls,
                "source": "gau"
            })
            log_event(scan_id, f"GAU: Found {len(urls)} URLs")

        return {"gau_urls": urls, "target": target}

    except Exception as e:
        logger.error(f"GAU failed for {target}: {e}")
        return {"gau_urls": [], "target": target, "error": str(e)}


@app.task(
    name='src.tasks.security_headers_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 30},
    retry_backoff=True
)
def security_headers_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Analyze security headers."""
    log_event(scan_id, f"Analyzing security headers for {target}")

    try:
        headers_data = tools.run_httpx_security_headers(target)

        if headers_data and headers_data.get("score") is not None:
            post_to_backend(f"/scans/{scan_id}/passive-intel/security-headers", {
                "asset_value": target,
                "headers": headers_data
            })
            log_event(scan_id, f"Security Headers: Score {headers_data.get('score')}/100 (Grade: {headers_data.get('grade')})")

        return {"security_headers": headers_data, "target": target}

    except Exception as e:
        logger.error(f"Security headers analysis failed for {target}: {e}")
        return {"security_headers": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.favicon_hash_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 15},
    retry_backoff=True
)
def favicon_hash_task(target: str, scan_id: str) -> Dict[str, Any]:
    """Calculate favicon hash for fingerprinting."""
    log_event(scan_id, f"Calculating favicon hash for {target}")

    try:
        favicon_data = tools.calculate_favicon_hash(target)

        if favicon_data and favicon_data.get("mmh3_hash"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/favicon", {
                "asset_value": target,
                "favicon_hash": favicon_data
            })
            log_event(scan_id, f"Favicon: MMH3 hash={favicon_data.get('mmh3_hash')}")

        return {"favicon": favicon_data, "target": target}

    except Exception as e:
        logger.error(f"Favicon hash failed for {target}: {e}")
        return {"favicon": {}, "target": target, "error": str(e)}


# ============================================================================
# API INTEGRATION TASKS
# ============================================================================

@app.task(
    name='src.tasks.shodan_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 60},
    retry_backoff=True
)
def shodan_task(target: str, scan_id: str, api_key: str) -> Dict[str, Any]:
    """Query Shodan API for infrastructure intel."""
    log_event(scan_id, f"Querying Shodan for {target}")

    try:
        ip = socket.gethostbyname(target)
        shodan_data = tools.query_shodan(ip, api_key)

        if shodan_data and shodan_data.get("open_ports"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/shodan", {
                "asset_value": target,
                "shodan_data": shodan_data
            })

            import json
            ports = json.loads(shodan_data.get("open_ports", "[]"))
            log_event(scan_id, f"Shodan: Found {len(ports)} open ports")

        return {"shodan": shodan_data, "target": target}

    except socket.gaierror:
        log_event(scan_id, f"Shodan skipped: could not resolve {target}", "warning")
        return {"shodan": {}, "target": target, "error": "DNS resolution failed"}
    except Exception as e:
        logger.error(f"Shodan query failed for {target}: {e}")
        return {"shodan": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.securitytrails_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 60},
    retry_backoff=True
)
def securitytrails_task(target: str, scan_id: str, api_key: str) -> Dict[str, Any]:
    """Query SecurityTrails for DNS history and subdomains."""
    log_event(scan_id, f"Querying SecurityTrails for {target}")

    try:
        st_data = tools.query_securitytrails(target, api_key)

        if st_data and st_data.get("subdomains"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/securitytrails", {
                "asset_value": target,
                "securitytrails_data": st_data
            })

            subs = st_data.get("subdomains", [])
            log_event(scan_id, f"SecurityTrails: Found {len(subs)} subdomains")

            # Also add discovered subdomains as assets
            if subs:
                assets = [{"value": sub, "asset_type": "subdomain", "is_active": True} for sub in subs[:100]]
                post_to_backend(f"/scans/{scan_id}/assets", assets)

        return {"securitytrails": st_data, "target": target}

    except Exception as e:
        logger.error(f"SecurityTrails query failed for {target}: {e}")
        return {"securitytrails": {}, "target": target, "error": str(e)}


@app.task(
    name='src.tasks.censys_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 1, 'countdown': 60},
    retry_backoff=True
)
def censys_task(target: str, scan_id: str, api_id: str, api_secret: str) -> Dict[str, Any]:
    """Query Censys for certificate and host data."""
    log_event(scan_id, f"Querying Censys for {target}")

    try:
        censys_data = tools.query_censys(target, api_id, api_secret)

        if censys_data and censys_data.get("services"):
            post_to_backend(f"/scans/{scan_id}/passive-intel/censys", {
                "asset_value": target,
                "censys_data": censys_data
            })
            log_event(scan_id, f"Censys: Data collected")

        return {"censys": censys_data, "target": target}

    except Exception as e:
        logger.error(f"Censys query failed for {target}: {e}")
        return {"censys": {}, "target": target, "error": str(e)}


# ============================================================================
# FINALIZATION
# ============================================================================

@app.task(name='src.tasks.finalize_passive_recon', queue='discovery')
def finalize_passive_recon(results: list, target: str, scan_id: str) -> Dict[str, Any]:
    """Finalize passive reconnaissance and aggregate summary."""
    logger.info(f"Passive reconnaissance completed for {target}")

    # Count collected data
    summary = {
        "target": target,
        "dns_records_collected": False,
        "whois_collected": False,
        "certificates_collected": False,
        "asn_collected": False,
        "endpoints_found": 0,
        "historical_urls_found": 0,
        "security_headers_score": None,
        "api_sources_used": [],
    }

    for result in (results or []):
        if not isinstance(result, dict):
            continue

        if result.get("dns_records"):
            summary["dns_records_collected"] = True
        if result.get("whois") and result["whois"].get("registrar"):
            summary["whois_collected"] = True
        if result.get("certificates"):
            summary["certificates_collected"] = True
        if result.get("asn") and result["asn"].get("asn_number"):
            summary["asn_collected"] = True
        if result.get("endpoints"):
            summary["endpoints_found"] += len(result["endpoints"])
        if result.get("historical_urls"):
            summary["historical_urls_found"] += len(result["historical_urls"])
        if result.get("gau_urls"):
            summary["historical_urls_found"] += len(result["gau_urls"])
        if result.get("security_headers") and result["security_headers"].get("score") is not None:
            summary["security_headers_score"] = result["security_headers"]["score"]
        if result.get("shodan") and result["shodan"].get("open_ports"):
            summary["api_sources_used"].append("shodan")
        if result.get("securitytrails") and result["securitytrails"].get("subdomains"):
            summary["api_sources_used"].append("securitytrails")
        if result.get("censys") and result["censys"].get("services"):
            summary["api_sources_used"].append("censys")

    log_event(scan_id, f"Passive recon completed for {target}: {summary['endpoints_found']} endpoints, {summary['historical_urls_found']} URLs")

    return {"status": "completed", "target": target, "summary": summary}
