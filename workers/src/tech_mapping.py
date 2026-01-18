"""
Technology to Nuclei template tags mapping.

Maps detected technologies from httpx to relevant Nuclei template tags
for prioritized vulnerability scanning.

Also includes version detection and CVE mapping utilities.
"""
import re
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass

# Technology to Nuclei tags mapping
# Keys are lowercase technology names (as detected by httpx)
# Values are lists of Nuclei template tags to run
TECH_TO_NUCLEI_TAGS = {
    # Web Servers
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "microsoft"],
    "tomcat": ["tomcat", "apache-tomcat"],
    "lighttpd": ["lighttpd"],
    "caddy": ["caddy"],
    "openresty": ["nginx", "openresty"],

    # CMS
    "wordpress": ["wordpress", "wp-plugin", "wp-theme", "wpscan"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "shopify": ["shopify"],
    "wix": ["wix"],
    "squarespace": ["squarespace"],
    "ghost": ["ghost"],
    "typo3": ["typo3"],
    "prestashop": ["prestashop"],
    "opencart": ["opencart"],
    "moodle": ["moodle"],

    # Frameworks - Backend
    "laravel": ["laravel", "php"],
    "symfony": ["symfony", "php"],
    "codeigniter": ["codeigniter", "php"],
    "yii": ["yii", "php"],
    "cakephp": ["cakephp", "php"],
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "fastapi": ["fastapi", "python"],
    "tornado": ["tornado", "python"],
    "spring": ["spring", "springboot", "java"],
    "struts": ["struts", "java"],
    "express": ["express", "nodejs"],
    "nextjs": ["nextjs", "nodejs"],
    "nuxt": ["nuxt", "nodejs"],
    "rails": ["rails", "ruby"],
    "sinatra": ["sinatra", "ruby"],
    "asp.net": ["aspnet", "asp", "microsoft"],
    "dotnet": ["aspnet", "dotnet", "microsoft"],

    # Frameworks - Frontend (usually less vuln-related but worth noting)
    "react": ["react"],
    "angular": ["angular"],
    "vue": ["vue"],
    "jquery": ["jquery"],
    "bootstrap": ["bootstrap"],

    # Databases (exposed services)
    "mysql": ["mysql"],
    "mariadb": ["mysql", "mariadb"],
    "postgresql": ["postgres", "postgresql"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "couchdb": ["couchdb"],
    "cassandra": ["cassandra"],
    "memcached": ["memcached"],
    "oracle": ["oracle"],
    "mssql": ["mssql", "microsoft"],

    # Cloud/CDN
    "cloudflare": ["cloudflare"],
    "aws": ["aws", "amazon"],
    "azure": ["azure", "microsoft"],
    "gcp": ["google", "gcp"],
    "akamai": ["akamai"],
    "fastly": ["fastly"],
    "cloudfront": ["cloudfront", "aws"],

    # DevOps/CI-CD
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "github": ["github"],
    "bitbucket": ["bitbucket", "atlassian"],
    "teamcity": ["teamcity"],
    "bamboo": ["bamboo", "atlassian"],
    "circleci": ["circleci"],
    "travis": ["travis"],
    "drone": ["drone"],
    "argo": ["argo"],

    # Monitoring/Analytics
    "grafana": ["grafana"],
    "prometheus": ["prometheus"],
    "kibana": ["kibana", "elastic"],
    "zabbix": ["zabbix"],
    "nagios": ["nagios"],
    "datadog": ["datadog"],
    "new relic": ["newrelic"],
    "splunk": ["splunk"],

    # Collaboration
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "trello": ["trello"],
    "slack": ["slack"],
    "teams": ["microsoft-teams", "microsoft"],
    "zoom": ["zoom"],

    # Admin Panels
    "phpmyadmin": ["phpmyadmin"],
    "adminer": ["adminer"],
    "webmin": ["webmin"],
    "cpanel": ["cpanel"],
    "plesk": ["plesk"],
    "directadmin": ["directadmin"],

    # Security/Auth
    "keycloak": ["keycloak"],
    "okta": ["okta"],
    "auth0": ["auth0"],
    "oauth": ["oauth"],
    "saml": ["saml"],

    # E-commerce
    "woocommerce": ["woocommerce", "wordpress"],
    "bigcommerce": ["bigcommerce"],
    "stripe": ["stripe"],
    "paypal": ["paypal"],

    # API/Gateway
    "kong": ["kong"],
    "traefik": ["traefik"],
    "envoy": ["envoy"],
    "haproxy": ["haproxy"],

    # Container/Orchestration
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "rancher": ["rancher"],
    "portainer": ["portainer"],

    # Misc
    "php": ["php"],
    "java": ["java"],
    "python": ["python"],
    "ruby": ["ruby"],
    "node": ["nodejs"],
    "go": ["go", "golang"],
}

# Critical/High severity tags that should always be included
# These target common vulnerability classes regardless of technology
CRITICAL_GENERIC_TAGS = [
    "cve",
    "rce",
    "sqli",
    "ssrf",
    "lfi",
    "xss",
    "xxe",
    "ssti",
    "auth-bypass",
    "default-login",
    "exposure",
    "misconfig",
    "unauth",
    "token",
    "secrets",
    "upload",
    "traversal",
    "injection",
]


def get_nuclei_tags_for_technologies(technologies: List[str]) -> List[str]:
    """
    Convert detected technologies to Nuclei template tags.

    Args:
        technologies: List of detected technology names from httpx

    Returns:
        Deduplicated list of Nuclei template tags
    """
    tags: Set[str] = set()

    for tech in technologies:
        tech_lower = tech.lower().strip()

        # Direct match
        if tech_lower in TECH_TO_NUCLEI_TAGS:
            tags.update(TECH_TO_NUCLEI_TAGS[tech_lower])
        else:
            # Partial match (e.g., "nginx/1.18.0" should match "nginx")
            for key, tag_list in TECH_TO_NUCLEI_TAGS.items():
                if key in tech_lower or tech_lower in key:
                    tags.update(tag_list)
                    break

    return list(tags)


def build_nuclei_tags_argument(
    technologies: List[str],
    include_critical: bool = True
) -> str:
    """
    Build the -tags argument for Nuclei command.

    Args:
        technologies: List of detected technologies
        include_critical: Whether to include critical generic tags

    Returns:
        Comma-separated tag string for Nuclei -tags argument,
        or empty string if no tags
    """
    tags = get_nuclei_tags_for_technologies(technologies)

    if include_critical:
        tags.extend(CRITICAL_GENERIC_TAGS)

    if not tags:
        return ""

    # Deduplicate and join
    return ",".join(sorted(set(tags)))


def get_technology_summary(technologies: List[str]) -> str:
    """
    Get a human-readable summary of detected technologies.

    Args:
        technologies: List of detected technology names

    Returns:
        Summary string
    """
    if not technologies:
        return "No technologies detected"

    # Group by category
    cms = []
    frameworks = []
    servers = []
    databases = []
    other = []

    cms_keys = {"wordpress", "drupal", "joomla", "magento", "shopify", "ghost", "typo3"}
    framework_keys = {"laravel", "django", "flask", "spring", "express", "rails", "react", "angular", "vue"}
    server_keys = {"nginx", "apache", "iis", "tomcat", "caddy"}
    db_keys = {"mysql", "postgresql", "mongodb", "redis", "elasticsearch"}

    for tech in technologies:
        tech_lower = tech.lower()
        matched = False

        for key in cms_keys:
            if key in tech_lower:
                cms.append(tech)
                matched = True
                break

        if not matched:
            for key in framework_keys:
                if key in tech_lower:
                    frameworks.append(tech)
                    matched = True
                    break

        if not matched:
            for key in server_keys:
                if key in tech_lower:
                    servers.append(tech)
                    matched = True
                    break

        if not matched:
            for key in db_keys:
                if key in tech_lower:
                    databases.append(tech)
                    matched = True
                    break

        if not matched:
            other.append(tech)

    parts = []
    if servers:
        parts.append(f"Server: {', '.join(servers[:2])}")
    if cms:
        parts.append(f"CMS: {', '.join(cms[:2])}")
    if frameworks:
        parts.append(f"Framework: {', '.join(frameworks[:2])}")
    if databases:
        parts.append(f"DB: {', '.join(databases[:2])}")

    if not parts and other:
        parts.append(f"Tech: {', '.join(other[:3])}")

    return " | ".join(parts) if parts else f"Detected: {', '.join(technologies[:3])}"


# ============================================================================
# VERSION DETECTION
# ============================================================================

@dataclass
class TechnologyInfo:
    """Structured technology information with version."""
    name: str
    version: Optional[str] = None
    confidence: float = 1.0
    cpe: Optional[str] = None  # Common Platform Enumeration
    category: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "cpe": self.cpe,
            "category": self.category,
        }


# Version extraction patterns
VERSION_PATTERNS = {
    # Server headers
    "nginx": [
        r"nginx[/\s]*([\d.]+)",
        r"nginx",  # Fallback without version
    ],
    "apache": [
        r"Apache[/\s]*([\d.]+)",
        r"Apache",
    ],
    "iis": [
        r"Microsoft-IIS[/\s]*([\d.]+)",
        r"IIS[/\s]*([\d.]+)",
    ],
    # CMS
    "wordpress": [
        r"WordPress[/\s]*([\d.]+)",
        r"wp-content",  # Indicator without version
    ],
    "drupal": [
        r"Drupal[/\s]*([\d.]+)",
        r"X-Drupal-",
    ],
    "joomla": [
        r"Joomla![/\s]*([\d.]+)",
        r"Joomla",
    ],
    # Frameworks
    "laravel": [
        r"laravel[/\s]*([\d.]+)",
        r"laravel_session",
    ],
    "django": [
        r"Django[/\s]*([\d.]+)",
        r"csrfmiddlewaretoken",
    ],
    "spring": [
        r"Spring[/\s]*([\d.]+)",
        r"X-Application-Context",
    ],
    "express": [
        r"Express[/\s]*([\d.]+)",
        r"X-Powered-By:\s*Express",
    ],
    # JavaScript frameworks (from response body)
    "react": [
        r"react[.-]dom[/\s@]*([\d.]+)",
        r"__REACT_DEVTOOLS",
        r"react",
    ],
    "angular": [
        r"angular[/\s@]*([\d.]+)",
        r"ng-version=\"([\d.]+)\"",
        r"ng-app",
    ],
    "vue": [
        r"vue[/\s@]*([\d.]+)",
        r"__VUE__",
        r"data-v-",
    ],
    "jquery": [
        r"jquery[.-]*([\d.]+)",
        r"jQuery\s*v?([\d.]+)",
    ],
    # Databases (when exposed)
    "mysql": [
        r"MySQL[/\s]*([\d.]+)",
    ],
    "postgresql": [
        r"PostgreSQL[/\s]*([\d.]+)",
    ],
    "mongodb": [
        r"MongoDB[/\s]*([\d.]+)",
    ],
    "redis": [
        r"Redis[/\s]*([\d.]+)",
    ],
    "elasticsearch": [
        r"Elasticsearch[/\s]*([\d.]+)",
        r"\"version\".*?\"number\".*?\"([\d.]+)\"",
    ],
    # DevOps tools
    "jenkins": [
        r"Jenkins[/\s]*([\d.]+)",
        r"X-Jenkins:\s*([\d.]+)",
    ],
    "grafana": [
        r"Grafana[/\s]*([\d.]+)",
        r"grafana-app",
    ],
    "kibana": [
        r"Kibana[/\s]*([\d.]+)",
        r"kbn-version:\s*([\d.]+)",
    ],
    # Cloud/CDN
    "cloudflare": [
        r"cloudflare",
        r"cf-ray",
    ],
    "akamai": [
        r"akamai",
        r"x-akamai",
    ],
}

# CPE (Common Platform Enumeration) mapping
# Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
CPE_MAPPING = {
    "nginx": "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
    "apache": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "iis": "cpe:2.3:a:microsoft:iis:{version}:*:*:*:*:*:*:*",
    "wordpress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
    "joomla": "cpe:2.3:a:joomla:joomla:{version}:*:*:*:*:*:*:*",
    "laravel": "cpe:2.3:a:laravel:laravel:{version}:*:*:*:*:*:*:*",
    "django": "cpe:2.3:a:djangoproject:django:{version}:*:*:*:*:*:*:*",
    "spring": "cpe:2.3:a:vmware:spring_framework:{version}:*:*:*:*:*:*:*",
    "jenkins": "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*",
    "grafana": "cpe:2.3:a:grafana:grafana:{version}:*:*:*:*:*:*:*",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*",
    "kibana": "cpe:2.3:a:elastic:kibana:{version}:*:*:*:*:*:*:*",
    "mysql": "cpe:2.3:a:mysql:mysql:{version}:*:*:*:*:*:*:*",
    "postgresql": "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*",
    "mongodb": "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*",
    "redis": "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
    "jquery": "cpe:2.3:a:jquery:jquery:{version}:*:*:*:*:*:*:*",
    "react": "cpe:2.3:a:facebook:react:{version}:*:*:*:*:*:*:*",
    "angular": "cpe:2.3:a:google:angular:{version}:*:*:*:*:*:*:*",
    "vue": "cpe:2.3:a:vuejs:vue:{version}:*:*:*:*:*:*:*",
}

# Technology categories
TECH_CATEGORIES = {
    "nginx": "web_server",
    "apache": "web_server",
    "iis": "web_server",
    "tomcat": "web_server",
    "wordpress": "cms",
    "drupal": "cms",
    "joomla": "cms",
    "magento": "cms",
    "laravel": "framework",
    "django": "framework",
    "spring": "framework",
    "express": "framework",
    "react": "javascript_framework",
    "angular": "javascript_framework",
    "vue": "javascript_framework",
    "jquery": "javascript_library",
    "mysql": "database",
    "postgresql": "database",
    "mongodb": "database",
    "redis": "cache",
    "elasticsearch": "search",
    "jenkins": "ci_cd",
    "gitlab": "ci_cd",
    "grafana": "monitoring",
    "prometheus": "monitoring",
    "cloudflare": "cdn",
    "akamai": "cdn",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
}


def extract_version(tech_string: str) -> Tuple[str, Optional[str]]:
    """
    Extract technology name and version from a string.

    Args:
        tech_string: Technology string like "nginx/1.18.0" or "WordPress 5.8"

    Returns:
        Tuple of (technology_name, version or None)
    """
    tech_lower = tech_string.lower().strip()

    # Try each pattern set
    for tech_name, patterns in VERSION_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, tech_string, re.IGNORECASE)
            if match:
                # Check if pattern has a capture group for version
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1)
                    return tech_name, version
                else:
                    return tech_name, None

    # Generic version pattern fallback
    # Matches patterns like "Product/1.2.3" or "Product 1.2.3"
    generic_match = re.match(r"([a-zA-Z][a-zA-Z0-9_-]*)[/\s]*([\d]+(?:\.[\d]+)*)", tech_string)
    if generic_match:
        return generic_match.group(1).lower(), generic_match.group(2)

    # Return original string as name, no version
    return tech_lower.split()[0] if tech_lower else tech_string, None


def parse_technologies(
    technologies: List[str],
    include_cpe: bool = True
) -> List[TechnologyInfo]:
    """
    Parse a list of technology strings into structured TechnologyInfo objects.

    Args:
        technologies: List of technology strings from httpx/wappalyzer
        include_cpe: Whether to generate CPE identifiers

    Returns:
        List of TechnologyInfo objects with extracted versions
    """
    results: List[TechnologyInfo] = []
    seen: Set[str] = set()

    for tech_str in technologies:
        name, version = extract_version(tech_str)

        # Avoid duplicates
        key = f"{name}:{version or 'unknown'}"
        if key in seen:
            continue
        seen.add(key)

        # Get category
        category = TECH_CATEGORIES.get(name)

        # Generate CPE if version available
        cpe = None
        if include_cpe and version and name in CPE_MAPPING:
            cpe = CPE_MAPPING[name].format(version=version)

        results.append(TechnologyInfo(
            name=name,
            version=version,
            category=category,
            cpe=cpe,
            confidence=1.0 if version else 0.8,
        ))

    return results


def detect_waf(headers: Dict[str, str], body: str = "") -> Optional[Dict[str, Any]]:
    """
    Detect Web Application Firewall from headers and response.

    Args:
        headers: HTTP response headers
        body: Optional response body

    Returns:
        WAF information dict or None
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    waf_signatures = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "body_patterns": ["cloudflare"],
        },
        "akamai": {
            "headers": ["x-akamai", "akamai-origin-hop"],
            "body_patterns": ["akamai"],
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid", "x-amz-cf-id"],
            "body_patterns": [],
        },
        "azure_front_door": {
            "headers": ["x-azure-ref", "x-fd-healthprobe"],
            "body_patterns": [],
        },
        "imperva": {
            "headers": ["x-iinfo", "x-cdn"],
            "body_patterns": ["imperva", "incapsula"],
        },
        "f5_big_ip": {
            "headers": ["x-cnection", "x-wa-info"],
            "body_patterns": ["big-ip", "f5"],
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "body_patterns": ["sucuri"],
        },
        "modsecurity": {
            "headers": [],
            "body_patterns": ["mod_security", "modsecurity"],
        },
    }

    for waf_name, signatures in waf_signatures.items():
        # Check headers
        for header in signatures["headers"]:
            if header in headers_lower:
                return {
                    "name": waf_name,
                    "detected_via": "header",
                    "header": header,
                }

        # Check body patterns
        body_lower = body.lower() if body else ""
        for pattern in signatures["body_patterns"]:
            if pattern in body_lower:
                return {
                    "name": waf_name,
                    "detected_via": "body",
                    "pattern": pattern,
                }

    return None


def detect_api_gateway(url: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Detect API Gateway from URL patterns and headers.

    Args:
        url: Request URL
        headers: HTTP response headers

    Returns:
        API Gateway information dict or None
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    gateways = {
        "aws_api_gateway": {
            "url_patterns": [r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com"],
            "headers": ["x-amzn-requestid", "x-amz-apigw-id"],
        },
        "kong": {
            "url_patterns": [],
            "headers": ["x-kong-proxy-latency", "x-kong-upstream-latency"],
        },
        "apigee": {
            "url_patterns": [r"\.apigee\.net"],
            "headers": ["x-apigee-", "x-google-"],
        },
        "azure_api_management": {
            "url_patterns": [r"\.azure-api\.net"],
            "headers": ["ocp-apim-", "x-ms-"],
        },
        "traefik": {
            "url_patterns": [],
            "headers": ["x-traefik-"],
        },
        "envoy": {
            "url_patterns": [],
            "headers": ["x-envoy-", "server: envoy"],
        },
    }

    for gateway_name, signatures in gateways.items():
        # Check URL patterns
        for pattern in signatures.get("url_patterns", []):
            if re.search(pattern, url, re.IGNORECASE):
                return {
                    "name": gateway_name,
                    "detected_via": "url",
                }

        # Check headers
        for header in signatures.get("headers", []):
            if any(h.startswith(header.lower()) or header.lower() in h for h in headers_lower):
                return {
                    "name": gateway_name,
                    "detected_via": "header",
                }

    return None


def get_enhanced_fingerprint(
    technologies: List[str],
    headers: Dict[str, str] = None,
    body: str = "",
    url: str = ""
) -> Dict[str, Any]:
    """
    Get enhanced technology fingerprint including versions, WAF, and API gateway detection.

    Args:
        technologies: List of detected technologies
        headers: HTTP response headers
        body: Response body (optional, for deep analysis)
        url: Request URL

    Returns:
        Comprehensive fingerprint dictionary
    """
    headers = headers or {}

    # Parse technologies with versions
    parsed_techs = parse_technologies(technologies)

    # Detect WAF
    waf_info = detect_waf(headers, body)

    # Detect API gateway
    api_gateway = detect_api_gateway(url, headers)

    # Build fingerprint
    fingerprint = {
        "technologies": [t.to_dict() for t in parsed_techs],
        "technology_count": len(parsed_techs),
        "versions_detected": sum(1 for t in parsed_techs if t.version),
        "cpes": [t.cpe for t in parsed_techs if t.cpe],
        "categories": list(set(t.category for t in parsed_techs if t.category)),
        "waf": waf_info,
        "api_gateway": api_gateway,
        "nuclei_tags": build_nuclei_tags_argument(technologies),
    }

    return fingerprint
