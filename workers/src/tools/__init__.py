"""
EASM Scanning Tools Package.

This package provides a modular collection of security scanning tools.
All functions are re-exported here for backward compatibility with
existing code that imports from `src.tools`.

Modules:
    - common: Shared utilities and constants
    - subfinder: Subdomain enumeration (subfinder, amass, findomain, assetfinder)
    - naabu: Port scanning
    - nuclei: Vulnerability scanning
    - httpx_tool: HTTP probing, tech detection, security headers, favicon hashing
    - dns: DNS enumeration (dnsx, whois, reverse DNS, ASN lookup)
    - tls: TLS/SSL analysis (tlsx, crt.sh)
    - katana: Web crawling
    - wayback: Historical URL discovery (waybackurls, gau)
    - apis: External API integrations (Shodan, SecurityTrails, Censys, HackerTarget)
"""

# Common utilities and constants
from .common import (
    _parse_response_time,
    check_tool,
    normalize_severity,
    DEFAULT_SCAN_PORTS,
    DEFAULT_NAABU_RATE_LIMIT,
    MAX_THREADPOOL_WORKERS,
    DEFAULT_NUCLEI_TIMEOUT_TOTAL,
    DEFAULT_NUCLEI_RATE_LIMIT,
    DEFAULT_NUCLEI_TIMEOUT,
    DEFAULT_NUCLEI_RETRIES,
    DEFAULT_NUCLEI_SEVERITY,
)

# Subdomain enumeration
from .subfinder import (
    run_subfinder,
    run_amass,
    run_findomain,
    run_assetfinder,
    aggregate_subdomain_discovery,
)

# Port scanning
from .naabu import run_naabu

# Vulnerability scanning
from .nuclei import run_nuclei, run_nuclei_with_tags

# HTTP probing and tech detection
from .httpx_tool import (
    run_httpx,
    run_httpx_security_headers,
    calculate_favicon_hash,
)

# DNS enumeration
from .dns import (
    run_dnsx,
    run_whois,
    lookup_asn,
    run_reverse_dns,
)

# TLS/SSL analysis
from .tls import run_tlsx, query_crtsh

# Web crawling
from .katana import run_katana

# Historical URL discovery
from .wayback import run_waybackurls, run_gau

# External API integrations
from .apis import (
    query_shodan,
    query_securitytrails,
    query_censys,
    query_hackertarget,
)

__all__ = [
    # Common
    "_parse_response_time",
    "check_tool",
    "normalize_severity",
    "DEFAULT_SCAN_PORTS",
    "DEFAULT_NAABU_RATE_LIMIT",
    "MAX_THREADPOOL_WORKERS",
    "DEFAULT_NUCLEI_TIMEOUT_TOTAL",
    "DEFAULT_NUCLEI_RATE_LIMIT",
    "DEFAULT_NUCLEI_TIMEOUT",
    "DEFAULT_NUCLEI_RETRIES",
    "DEFAULT_NUCLEI_SEVERITY",
    # Subdomain enumeration
    "run_subfinder",
    "run_amass",
    "run_findomain",
    "run_assetfinder",
    "aggregate_subdomain_discovery",
    # Port scanning
    "run_naabu",
    # Vulnerability scanning
    "run_nuclei",
    "run_nuclei_with_tags",
    # HTTP probing
    "run_httpx",
    "run_httpx_security_headers",
    "calculate_favicon_hash",
    # DNS
    "run_dnsx",
    "run_whois",
    "lookup_asn",
    "run_reverse_dns",
    # TLS
    "run_tlsx",
    "query_crtsh",
    # Crawling
    "run_katana",
    # Historical URLs
    "run_waybackurls",
    "run_gau",
    # External APIs
    "query_shodan",
    "query_securitytrails",
    "query_censys",
    "query_hackertarget",
]
