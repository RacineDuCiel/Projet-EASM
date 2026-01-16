import enum

class ScopeType(str, enum.Enum):
    domain = "domain"
    ip_range = "ip_range"
    hostname = "hostname"

class ScanProfile(str, enum.Enum):
    """
    High-level scan profiles that abstract away complexity.
    Each profile defines which phases run and at what intensity.
    """
    discovery = "discovery"                     # Passive only: find assets
    quick_assessment = "quick_assessment"       # Discovery + basic vuln scan
    standard_assessment = "standard_assessment" # Balanced approach (recommended)
    full_audit = "full_audit"                   # Comprehensive, all templates


class ScanPhase(str, enum.Enum):
    """
    Discrete phases of a scan workflow.
    Profiles select which phases to execute.
    """
    asset_discovery = "asset_discovery"           # Phase 1: Subfinder, passive DNS
    service_enumeration = "service_enumeration"   # Phase 2: Naabu port scan
    tech_detection = "tech_detection"             # Phase 3: httpx
    vuln_assessment = "vuln_assessment"           # Phase 4: Nuclei prioritized
    deep_analysis = "deep_analysis"               # Phase 5: Full Nuclei + extended passive


class AssetCriticality(str, enum.Enum):
    """
    Asset importance level - drives scan intensity decisions.
    """
    critical = "critical"       # Crown jewels - always deep scan
    high = "high"               # Important assets - standard+ scans
    medium = "medium"           # Normal assets - follow profile
    low = "low"                 # Less important - fast scans only
    unclassified = "unclassified"  # Not yet classified (default)


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    stopped = "stopped"

class AssetType(str, enum.Enum):
    subdomain = "subdomain"
    ip = "ip"

class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class VulnStatus(str, enum.Enum):
    open = "open"
    fixed = "fixed"
    false_positive = "false_positive"

class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"

class ScanFrequency(str, enum.Enum):
    never = "never"
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"
