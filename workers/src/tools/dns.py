"""
DNS enumeration tools: dnsx, whois, reverse DNS, ASN lookup.
"""
import subprocess
import json
import socket
import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

from .common import check_tool


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
