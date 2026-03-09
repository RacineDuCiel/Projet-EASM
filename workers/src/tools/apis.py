"""
External API integrations: Shodan, SecurityTrails, Censys, HackerTarget.
"""
import json
import socket
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)


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
