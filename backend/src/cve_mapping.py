"""
CVE Mapping Module Stub for Backend.

This module provides minimal CVE-related functionality for the backend.
The full implementation is in workers/src/cve_mapping.py.
"""
from typing import List, Dict, Any, Optional


# Known Exploited Vulnerabilities from CISA KEV catalog
# Subset of critical CVEs known to be actively exploited
KEV_CVES = {
    # 2024 Critical CVEs actively exploited
    "CVE-2024-21887",  # Ivanti Connect Secure RCE
    "CVE-2024-21893",  # Ivanti Connect Secure SSRF
    "CVE-2024-1709",   # ScreenConnect Auth Bypass
    "CVE-2024-1708",   # ScreenConnect Path Traversal
    "CVE-2024-27198",  # TeamCity Auth Bypass
    "CVE-2024-27199",  # TeamCity Path Traversal
    "CVE-2024-3400",   # PAN-OS Command Injection
    "CVE-2024-23897",  # Jenkins Arbitrary File Read

    # 2023 Critical CVEs
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2023-46805",  # Ivanti Policy Secure Auth Bypass
    "CVE-2023-46747",  # F5 BIG-IP RCE
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2023-42793",  # TeamCity RCE
    "CVE-2023-38831",  # WinRAR Code Execution
    "CVE-2023-35078",  # Ivanti EPMM Auth Bypass
    "CVE-2023-34362",  # MOVEit SQL Injection
    "CVE-2023-28771",  # Zyxel Command Injection
    "CVE-2023-27997",  # FortiGate RCE
    "CVE-2023-27350",  # PaperCut RCE
    "CVE-2023-26360",  # Adobe ColdFusion
    "CVE-2023-22515",  # Confluence RCE
    "CVE-2023-20198",  # Cisco IOS XE Web UI
    "CVE-2023-20273",  # Cisco IOS XE
    "CVE-2023-0669",   # GoAnywhere RCE
    "CVE-2023-4863",   # WebP Heap Buffer Overflow

    # 2022 Critical CVEs
    "CVE-2022-47966",  # Zoho ManageEngine RCE
    "CVE-2022-42475",  # FortiOS Heap Overflow
    "CVE-2022-41082",  # Exchange ProxyNotShell RCE
    "CVE-2022-41040",  # Exchange ProxyNotShell SSRF
    "CVE-2022-30190",  # Follina
    "CVE-2022-26134",  # Confluence RCE
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2022-22963",  # Spring Cloud Function RCE
    "CVE-2022-22954",  # VMware Workspace ONE RCE
    "CVE-2022-1388",   # F5 BIG-IP Auth Bypass

    # 2021 Critical CVEs (still actively exploited)
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-44832",  # Log4j RCE
    "CVE-2021-45046",  # Log4j RCE
    "CVE-2021-45105",  # Log4j DoS
    "CVE-2021-40444",  # MSHTML RCE
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2021-34473",  # ProxyShell Exchange
    "CVE-2021-31207",  # ProxyShell Exchange
    "CVE-2021-26858",  # ProxyLogon Exchange
    "CVE-2021-26857",  # ProxyLogon Exchange
    "CVE-2021-26855",  # ProxyLogon Exchange
    "CVE-2021-21972",  # VMware vCenter RCE
    "CVE-2021-21985",  # VMware vCenter RCE

    # Older but still actively exploited
    "CVE-2020-1472",   # Zerologon
    "CVE-2019-11510",  # Pulse Secure
    "CVE-2019-19781",  # Citrix ADC
    "CVE-2018-13379",  # FortiGate
    "CVE-2017-0144",   # EternalBlue
}


def check_cve_for_technology(
    technology: str,
    version: str = None,
) -> List[Dict[str, Any]]:
    """
    Check for known CVEs affecting a technology/version.
    
    This is a stub implementation for the backend.
    Full implementation is in workers/src/cve_mapping.py.
    
    Args:
        technology: Technology name (e.g., "nginx", "apache")
        version: Optional version string
        
    Returns:
        List of matching CVE dictionaries
    """
    # Stub implementation - returns empty list
    # The workers module has full CVE database lookup
    return []
