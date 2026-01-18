"""
CVE Mapping Module for EASM Platform.

Maps detected technologies with versions to known CVEs for:
- Contextual vulnerability prioritization
- Risk scoring based on known vulnerabilities
- Proactive alerting on vulnerable versions

Uses NVD API and local CVE database for mapping.
"""
import logging
import re
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache

logger = logging.getLogger(__name__)

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = None  # Set via environment variable for higher rate limits


@dataclass
class CVEInfo:
    """Represents a CVE entry."""
    cve_id: str
    description: str
    severity: str  # critical, high, medium, low
    cvss_score: float
    cvss_version: str
    published_date: str
    exploited_in_wild: bool = False
    exploit_available: bool = False
    affected_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "published_date": self.published_date,
            "exploited_in_wild": self.exploited_in_wild,
            "exploit_available": self.exploit_available,
            "affected_versions": self.affected_versions,
            "references": self.references,
        }


# Known critical CVEs for common technologies
# This is a curated list of high-impact CVEs to check even without NVD API
CRITICAL_CVES = {
    "apache": [
        {
            "cve_id": "CVE-2021-41773",
            "description": "Apache HTTP Server Path Traversal and RCE",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["2.4.49"],
            "exploited_in_wild": True,
        },
        {
            "cve_id": "CVE-2021-42013",
            "description": "Apache HTTP Server Path Traversal (incomplete fix for CVE-2021-41773)",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["2.4.49", "2.4.50"],
            "exploited_in_wild": True,
        },
        {
            "cve_id": "CVE-2023-25690",
            "description": "Apache HTTP Server mod_proxy HTTP Request Smuggling",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["2.4.0-2.4.55"],
        },
    ],
    "nginx": [
        {
            "cve_id": "CVE-2021-23017",
            "description": "Nginx DNS Resolver Vulnerability",
            "severity": "high",
            "cvss_score": 7.7,
            "affected_versions": ["0.6.18-1.20.0"],
        },
    ],
    "wordpress": [
        {
            "cve_id": "CVE-2024-27956",
            "description": "WordPress Core SQL Injection",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["6.0.0-6.4.3"],
            "exploited_in_wild": True,
        },
    ],
    "spring": [
        {
            "cve_id": "CVE-2022-22965",
            "description": "Spring4Shell RCE Vulnerability",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["5.3.0-5.3.17", "5.2.0-5.2.19"],
            "exploited_in_wild": True,
        },
        {
            "cve_id": "CVE-2022-22963",
            "description": "Spring Cloud Function SpEL Injection",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["3.1.6", "3.2.2"],
            "exploited_in_wild": True,
        },
    ],
    "log4j": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell RCE Vulnerability",
            "severity": "critical",
            "cvss_score": 10.0,
            "affected_versions": ["2.0-2.14.1"],
            "exploited_in_wild": True,
        },
        {
            "cve_id": "CVE-2021-45046",
            "description": "Log4j DoS and RCE (incomplete fix)",
            "severity": "critical",
            "cvss_score": 9.0,
            "affected_versions": ["2.0-2.15.0"],
            "exploited_in_wild": True,
        },
    ],
    "jenkins": [
        {
            "cve_id": "CVE-2024-23897",
            "description": "Jenkins CLI Arbitrary File Read",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["<=2.441", "<=LTS 2.426.2"],
            "exploited_in_wild": True,
        },
    ],
    "grafana": [
        {
            "cve_id": "CVE-2021-43798",
            "description": "Grafana Path Traversal",
            "severity": "high",
            "cvss_score": 7.5,
            "affected_versions": ["8.0.0-8.3.0"],
            "exploited_in_wild": True,
        },
    ],
    "elasticsearch": [
        {
            "cve_id": "CVE-2015-1427",
            "description": "Elasticsearch Groovy Scripting RCE",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["1.3.0-1.3.7", "1.4.0-1.4.2"],
            "exploited_in_wild": True,
        },
    ],
    "redis": [
        {
            "cve_id": "CVE-2022-0543",
            "description": "Redis Lua Sandbox Escape RCE",
            "severity": "critical",
            "cvss_score": 10.0,
            "affected_versions": ["2.6-6.2.6", "7.0.0-7.0.8"],
            "exploited_in_wild": True,
        },
    ],
    "jquery": [
        {
            "cve_id": "CVE-2020-11022",
            "description": "jQuery Cross-Site Scripting (XSS)",
            "severity": "medium",
            "cvss_score": 6.1,
            "affected_versions": ["1.0.3-3.4.1"],
        },
        {
            "cve_id": "CVE-2020-11023",
            "description": "jQuery DOM-based XSS",
            "severity": "medium",
            "cvss_score": 6.1,
            "affected_versions": ["1.0.3-3.4.1"],
        },
    ],
    "drupal": [
        {
            "cve_id": "CVE-2018-7600",
            "description": "Drupalgeddon 2 RCE",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_versions": ["7.x-7.57", "8.x-8.5.0"],
            "exploited_in_wild": True,
        },
    ],
    "joomla": [
        {
            "cve_id": "CVE-2023-23752",
            "description": "Joomla Information Disclosure",
            "severity": "high",
            "cvss_score": 7.5,
            "affected_versions": ["4.0.0-4.2.7"],
            "exploited_in_wild": True,
        },
    ],
}

# Known Exploited Vulnerabilities (KEV) - subset of CISA KEV catalog
# These should be prioritized in scans
KEV_CVES = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2021-41773",  # Apache Path Traversal
    "CVE-2021-42013",  # Apache Path Traversal 2
    "CVE-2024-23897",  # Jenkins CLI
    "CVE-2018-7600",   # Drupalgeddon 2
    "CVE-2022-0543",   # Redis RCE
    "CVE-2021-43798",  # Grafana Path Traversal
    "CVE-2024-27956",  # WordPress SQLi
}


def parse_version(version_str: str) -> Tuple[int, ...]:
    """
    Parse version string to tuple for comparison.

    Args:
        version_str: Version like "1.2.3" or "2.4.49"

    Returns:
        Tuple of version parts (1, 2, 3)
    """
    # Extract numeric parts
    parts = re.findall(r'\d+', version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def version_in_range(version: str, range_str: str) -> bool:
    """
    Check if a version falls within a version range.

    Args:
        version: Version to check (e.g., "2.4.49")
        range_str: Range like "2.4.49", "2.0-2.14.1", "<=2.441"

    Returns:
        True if version is in range
    """
    if not version or not range_str:
        return False

    version_tuple = parse_version(version)

    # Handle exact version
    if "-" not in range_str and "<=" not in range_str and ">=" not in range_str:
        return version == range_str

    # Handle range (e.g., "2.0-2.14.1")
    if "-" in range_str and "<=" not in range_str:
        parts = range_str.split("-")
        if len(parts) == 2:
            min_ver = parse_version(parts[0])
            max_ver = parse_version(parts[1])
            return min_ver <= version_tuple <= max_ver

    # Handle <= (e.g., "<=2.441")
    if range_str.startswith("<="):
        max_ver = parse_version(range_str[2:])
        return version_tuple <= max_ver

    # Handle >= (e.g., ">=2.0")
    if range_str.startswith(">="):
        min_ver = parse_version(range_str[2:])
        return version_tuple >= min_ver

    return False


def check_cve_for_technology(
    technology: str,
    version: Optional[str] = None
) -> List[CVEInfo]:
    """
    Check for known CVEs affecting a technology and version.

    Args:
        technology: Technology name (e.g., "apache", "nginx")
        version: Optional version string

    Returns:
        List of matching CVEInfo objects
    """
    tech_lower = technology.lower()
    matching_cves: List[CVEInfo] = []

    # Check local database first
    if tech_lower in CRITICAL_CVES:
        for cve_data in CRITICAL_CVES[tech_lower]:
            # If no version specified, return all CVEs for the tech
            if version is None:
                matching_cves.append(CVEInfo(
                    cve_id=cve_data["cve_id"],
                    description=cve_data["description"],
                    severity=cve_data["severity"],
                    cvss_score=cve_data["cvss_score"],
                    cvss_version="3.1",
                    published_date="",
                    exploited_in_wild=cve_data.get("exploited_in_wild", False),
                    affected_versions=cve_data.get("affected_versions", []),
                ))
            else:
                # Check if version is affected
                for affected in cve_data.get("affected_versions", []):
                    if version_in_range(version, affected):
                        matching_cves.append(CVEInfo(
                            cve_id=cve_data["cve_id"],
                            description=cve_data["description"],
                            severity=cve_data["severity"],
                            cvss_score=cve_data["cvss_score"],
                            cvss_version="3.1",
                            published_date="",
                            exploited_in_wild=cve_data.get("exploited_in_wild", False),
                            affected_versions=cve_data.get("affected_versions", []),
                        ))
                        break

    return matching_cves


@lru_cache(maxsize=100)
def query_nvd_api(cpe: str, api_key: str = None) -> List[Dict[str, Any]]:
    """
    Query NVD API for CVEs matching a CPE.

    Args:
        cpe: CPE identifier (e.g., "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        api_key: Optional NVD API key for higher rate limits

    Returns:
        List of CVE dictionaries from NVD
    """
    if not cpe:
        return []

    try:
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        params = {"cpeName": cpe, "resultsPerPage": 50}
        response = requests.get(
            NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()

        data = response.json()
        return data.get("vulnerabilities", [])

    except requests.exceptions.RequestException as e:
        logger.warning(f"NVD API query failed for {cpe}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error querying NVD API: {e}")
        return []


def calculate_risk_score(
    cves: List[CVEInfo],
    asset_criticality: str = "medium"
) -> Dict[str, Any]:
    """
    Calculate aggregate risk score based on CVEs.

    Args:
        cves: List of CVEs affecting the asset
        asset_criticality: Asset criticality (critical, high, medium, low)

    Returns:
        Risk score dictionary
    """
    if not cves:
        return {
            "score": 0,
            "level": "low",
            "factors": [],
        }

    # Criticality multiplier
    criticality_multiplier = {
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.8,
    }.get(asset_criticality, 1.0)

    # Calculate base score from CVEs
    max_cvss = max(cve.cvss_score for cve in cves)
    avg_cvss = sum(cve.cvss_score for cve in cves) / len(cves)

    # Count severity levels
    critical_count = sum(1 for cve in cves if cve.severity == "critical")
    high_count = sum(1 for cve in cves if cve.severity == "high")
    exploited_count = sum(1 for cve in cves if cve.exploited_in_wild)

    # Weighted score
    base_score = (max_cvss * 0.5 + avg_cvss * 0.3 + min(len(cves) * 0.5, 2.0))

    # Adjust for exploited vulnerabilities
    if exploited_count > 0:
        base_score += exploited_count * 1.0

    # Apply criticality multiplier
    final_score = min(base_score * criticality_multiplier, 10.0)

    # Determine risk level
    if final_score >= 9.0:
        level = "critical"
    elif final_score >= 7.0:
        level = "high"
    elif final_score >= 4.0:
        level = "medium"
    else:
        level = "low"

    factors = []
    if critical_count > 0:
        factors.append(f"{critical_count} critical CVE(s)")
    if high_count > 0:
        factors.append(f"{high_count} high CVE(s)")
    if exploited_count > 0:
        factors.append(f"{exploited_count} exploited in wild")

    return {
        "score": round(final_score, 2),
        "level": level,
        "max_cvss": max_cvss,
        "avg_cvss": round(avg_cvss, 2),
        "cve_count": len(cves),
        "critical_count": critical_count,
        "high_count": high_count,
        "exploited_count": exploited_count,
        "factors": factors,
    }


def get_vulnerability_context(
    technologies: List[Dict[str, Any]],
    asset_criticality: str = "medium",
    use_nvd_api: bool = False,
    nvd_api_key: str = None
) -> Dict[str, Any]:
    """
    Get comprehensive vulnerability context for detected technologies.

    Args:
        technologies: List of technology dicts with name and version
        asset_criticality: Asset criticality level
        use_nvd_api: Whether to query NVD API (slower but more complete)
        nvd_api_key: Optional NVD API key

    Returns:
        Comprehensive vulnerability context dictionary
    """
    all_cves: List[CVEInfo] = []
    tech_cve_map: Dict[str, List[Dict]] = {}
    kev_matches: List[str] = []

    for tech in technologies:
        tech_name = tech.get("name", "")
        tech_version = tech.get("version")
        cpe = tech.get("cpe")

        # Check local CVE database
        local_cves = check_cve_for_technology(tech_name, tech_version)
        all_cves.extend(local_cves)

        if local_cves:
            tech_cve_map[tech_name] = [cve.to_dict() for cve in local_cves]

            # Check for KEV matches
            for cve in local_cves:
                if cve.cve_id in KEV_CVES:
                    kev_matches.append(cve.cve_id)

        # Optionally query NVD API
        if use_nvd_api and cpe:
            nvd_cves = query_nvd_api(cpe, nvd_api_key)
            # Process NVD results (simplified)
            for vuln in nvd_cves[:10]:  # Limit to avoid overload
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Skip if already in local results
                if any(c.cve_id == cve_id for c in all_cves):
                    continue

                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = cvss_v31.get("baseScore", 0)

                if cvss_score >= 7.0:  # Only include high/critical
                    all_cves.append(CVEInfo(
                        cve_id=cve_id,
                        description=cve_data.get("descriptions", [{}])[0].get("value", ""),
                        severity="critical" if cvss_score >= 9.0 else "high",
                        cvss_score=cvss_score,
                        cvss_version="3.1",
                        published_date=cve_data.get("published", ""),
                        exploited_in_wild=cve_id in KEV_CVES,
                    ))

    # Calculate risk score
    risk_score = calculate_risk_score(all_cves, asset_criticality)

    # Build response
    return {
        "technologies_analyzed": len(technologies),
        "total_cves": len(all_cves),
        "risk_score": risk_score,
        "cves_by_technology": tech_cve_map,
        "kev_matches": list(set(kev_matches)),
        "kev_count": len(set(kev_matches)),
        "critical_cves": [cve.to_dict() for cve in all_cves if cve.severity == "critical"],
        "high_cves": [cve.to_dict() for cve in all_cves if cve.severity == "high"],
        "exploited_cves": [cve.to_dict() for cve in all_cves if cve.exploited_in_wild],
        "recommendations": generate_recommendations(all_cves, technologies),
    }


def generate_recommendations(
    cves: List[CVEInfo],
    technologies: List[Dict[str, Any]]
) -> List[str]:
    """
    Generate remediation recommendations based on detected vulnerabilities.

    Args:
        cves: List of CVEs
        technologies: List of technology dicts

    Returns:
        List of recommendation strings
    """
    recommendations = []

    # Critical CVEs
    critical_cves = [cve for cve in cves if cve.severity == "critical"]
    if critical_cves:
        recommendations.append(
            f"URGENT: {len(critical_cves)} critical vulnerabilities detected. "
            "Immediate patching required."
        )

    # Exploited CVEs
    exploited = [cve for cve in cves if cve.exploited_in_wild]
    if exploited:
        recommendations.append(
            f"HIGH PRIORITY: {len(exploited)} vulnerabilities are actively exploited. "
            f"CVEs: {', '.join(cve.cve_id for cve in exploited[:3])}"
        )

    # Outdated technologies
    outdated = []
    for tech in technologies:
        if tech.get("version"):
            tech_cves = check_cve_for_technology(tech["name"], tech["version"])
            if tech_cves:
                outdated.append(f"{tech['name']} {tech['version']}")

    if outdated:
        recommendations.append(
            f"Update vulnerable components: {', '.join(outdated[:5])}"
        )

    # Generic recommendations
    if not recommendations:
        recommendations.append("No critical vulnerabilities detected based on version analysis.")

    return recommendations


def prioritize_nuclei_templates(
    technologies: List[Dict[str, Any]]
) -> List[str]:
    """
    Prioritize Nuclei templates based on detected technologies and known CVEs.

    Args:
        technologies: List of technology dicts with name and version

    Returns:
        List of prioritized Nuclei template IDs/tags
    """
    priority_templates = []

    for tech in technologies:
        tech_name = tech.get("name", "").lower()
        tech_version = tech.get("version")

        # Check for known CVEs
        cves = check_cve_for_technology(tech_name, tech_version)

        for cve in cves:
            # Map CVE to Nuclei template
            template_id = cve.cve_id.lower().replace("-", "_")
            priority_templates.append(template_id)

            # Add technology-specific templates
            if tech_name in ["apache", "nginx", "iis"]:
                priority_templates.extend(["web-server", "misconfig"])
            elif tech_name in ["wordpress", "drupal", "joomla"]:
                priority_templates.extend(["cms", tech_name])
            elif tech_name in ["jenkins", "gitlab"]:
                priority_templates.extend(["ci-cd", "devops"])

    # Add critical generic templates
    priority_templates.extend([
        "cve",
        "rce",
        "sqli",
        "auth-bypass",
        "default-login",
    ])

    return list(set(priority_templates))
