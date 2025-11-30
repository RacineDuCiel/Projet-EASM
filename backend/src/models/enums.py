import enum

class ScopeType(str, enum.Enum):
    domain = "domain"
    ip_range = "ip_range"
    hostname = "hostname"

class ScanType(str, enum.Enum):
    passive = "passive"
    active = "active"
    full = "full"

class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

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
