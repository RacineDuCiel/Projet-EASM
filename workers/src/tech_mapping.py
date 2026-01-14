"""
Technology to Nuclei template tags mapping.

Maps detected technologies from httpx to relevant Nuclei template tags
for prioritized vulnerability scanning.
"""
from typing import List, Set

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
