"""
TLS/SSL analysis tools: tlsx and crt.sh certificate transparency.
"""
import subprocess
import json
import logging
import requests
from typing import List, Dict, Any

from .common import check_tool

logger = logging.getLogger(__name__)


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
