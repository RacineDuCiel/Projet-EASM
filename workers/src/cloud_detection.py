"""
Cloud Asset Detection Module for EASM Platform.

Detects cloud-hosted assets including:
- AWS S3 buckets, CloudFront distributions, ELB
- Azure Blob Storage, CDN endpoints
- GCP Cloud Storage, Load Balancers

Uses pattern matching on discovered subdomains, DNS records, and certificates.
"""
import re
import logging
import requests
import socket
from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CLOUDFLARE = "cloudflare"
    DIGITALOCEAN = "digitalocean"
    UNKNOWN = "unknown"


@dataclass
class CloudAsset:
    """Represents a detected cloud asset."""
    provider: CloudProvider
    asset_type: str  # s3_bucket, cloudfront, blob_storage, etc.
    identifier: str  # bucket name, distribution id, etc.
    url: Optional[str] = None
    region: Optional[str] = None
    is_public: Optional[bool] = None
    is_accessible: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.value,
            "asset_type": self.asset_type,
            "identifier": self.identifier,
            "url": self.url,
            "region": self.region,
            "is_public": self.is_public,
            "is_accessible": self.is_accessible,
            "metadata": self.metadata,
        }


# Cloud provider patterns
AWS_PATTERNS = {
    "s3_bucket": [
        r"([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3\.amazonaws\.com",
        r"([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3-([a-z0-9\-]+)\.amazonaws\.com",
        r"([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3\.([a-z0-9\-]+)\.amazonaws\.com",
        r"s3\.amazonaws\.com/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])",
        r"s3-([a-z0-9\-]+)\.amazonaws\.com/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])",
    ],
    "cloudfront": [
        r"([a-z0-9]+)\.cloudfront\.net",
    ],
    "elb": [
        r"([a-z0-9\-]+)\.([a-z0-9\-]+)\.elb\.amazonaws\.com",
        r"([a-z0-9\-]+)-([0-9]+)\.([a-z0-9\-]+)\.elb\.amazonaws\.com",
    ],
    "api_gateway": [
        r"([a-z0-9]+)\.execute-api\.([a-z0-9\-]+)\.amazonaws\.com",
    ],
    "ec2": [
        r"ec2-([0-9\-]+)\.([a-z0-9\-]+)\.compute\.amazonaws\.com",
    ],
    "rds": [
        r"([a-z0-9\-]+)\.([a-z0-9]+)\.([a-z0-9\-]+)\.rds\.amazonaws\.com",
    ],
    "elasticbeanstalk": [
        r"([a-z0-9\-]+)\.([a-z0-9\-]+)\.elasticbeanstalk\.com",
    ],
}

AZURE_PATTERNS = {
    "blob_storage": [
        r"([a-z0-9]{3,24})\.blob\.core\.windows\.net",
    ],
    "file_storage": [
        r"([a-z0-9]{3,24})\.file\.core\.windows\.net",
    ],
    "table_storage": [
        r"([a-z0-9]{3,24})\.table\.core\.windows\.net",
    ],
    "queue_storage": [
        r"([a-z0-9]{3,24})\.queue\.core\.windows\.net",
    ],
    "cdn": [
        r"([a-z0-9\-]+)\.azureedge\.net",
    ],
    "app_service": [
        r"([a-z0-9\-]+)\.azurewebsites\.net",
        r"([a-z0-9\-]+)\.scm\.azurewebsites\.net",
    ],
    "api_management": [
        r"([a-z0-9\-]+)\.azure-api\.net",
    ],
    "front_door": [
        r"([a-z0-9\-]+)\.azurefd\.net",
    ],
    "traffic_manager": [
        r"([a-z0-9\-]+)\.trafficmanager\.net",
    ],
}

GCP_PATTERNS = {
    "cloud_storage": [
        r"storage\.googleapis\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])",
        r"([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])\.storage\.googleapis\.com",
    ],
    "cloud_run": [
        r"([a-z0-9\-]+)-([a-z0-9]+)-([a-z]{2})\.a\.run\.app",
    ],
    "app_engine": [
        r"([a-z0-9\-]+)\.appspot\.com",
        r"([a-z0-9\-]+)\.([a-z]{2})\.r\.appspot\.com",
    ],
    "cloud_functions": [
        r"([a-z0-9\-]+)\.cloudfunctions\.net",
    ],
    "firebase": [
        r"([a-z0-9\-]+)\.firebaseapp\.com",
        r"([a-z0-9\-]+)\.web\.app",
        r"([a-z0-9\-]+)\.firebaseio\.com",
    ],
}

# Other cloud providers
OTHER_PATTERNS = {
    "cloudflare": [
        r"([a-z0-9\-]+)\.pages\.dev",
        r"([a-z0-9\-]+)\.workers\.dev",
    ],
    "digitalocean": [
        r"([a-z0-9\-]+)\.ondigitalocean\.app",
        r"([a-z0-9\-]+)\.([a-z0-9]+)\.digitaloceanspaces\.com",
    ],
    "heroku": [
        r"([a-z0-9\-]+)\.herokuapp\.com",
    ],
    "netlify": [
        r"([a-z0-9\-]+)\.netlify\.app",
    ],
    "vercel": [
        r"([a-z0-9\-]+)\.vercel\.app",
    ],
}


def detect_cloud_assets_from_hostnames(hostnames: List[str]) -> List[CloudAsset]:
    """
    Detect cloud assets from a list of hostnames/subdomains.

    Args:
        hostnames: List of hostnames to analyze

    Returns:
        List of detected CloudAsset objects
    """
    assets: List[CloudAsset] = []
    seen: Set[str] = set()

    for hostname in hostnames:
        hostname = hostname.lower().strip()

        # AWS patterns
        for asset_type, patterns in AWS_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, hostname, re.IGNORECASE)
                if match:
                    identifier = match.group(1)
                    key = f"aws:{asset_type}:{identifier}"
                    if key not in seen:
                        seen.add(key)
                        region = match.group(2) if match.lastindex >= 2 else None
                        assets.append(CloudAsset(
                            provider=CloudProvider.AWS,
                            asset_type=asset_type,
                            identifier=identifier,
                            url=f"https://{hostname}",
                            region=region,
                        ))

        # Azure patterns
        for asset_type, patterns in AZURE_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, hostname, re.IGNORECASE)
                if match:
                    identifier = match.group(1)
                    key = f"azure:{asset_type}:{identifier}"
                    if key not in seen:
                        seen.add(key)
                        assets.append(CloudAsset(
                            provider=CloudProvider.AZURE,
                            asset_type=asset_type,
                            identifier=identifier,
                            url=f"https://{hostname}",
                        ))

        # GCP patterns
        for asset_type, patterns in GCP_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, hostname, re.IGNORECASE)
                if match:
                    identifier = match.group(1)
                    key = f"gcp:{asset_type}:{identifier}"
                    if key not in seen:
                        seen.add(key)
                        assets.append(CloudAsset(
                            provider=CloudProvider.GCP,
                            asset_type=asset_type,
                            identifier=identifier,
                            url=f"https://{hostname}",
                        ))

        # Other providers
        for provider, patterns in OTHER_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, hostname, re.IGNORECASE)
                if match:
                    identifier = match.group(1)
                    key = f"{provider}:{identifier}"
                    if key not in seen:
                        seen.add(key)
                        assets.append(CloudAsset(
                            provider=CloudProvider.CLOUDFLARE if provider == "cloudflare"
                            else CloudProvider.DIGITALOCEAN if provider == "digitalocean"
                            else CloudProvider.UNKNOWN,
                            asset_type=provider,
                            identifier=identifier,
                            url=f"https://{hostname}",
                        ))

    logger.info(f"Detected {len(assets)} cloud assets from {len(hostnames)} hostnames")
    return assets


def check_s3_bucket_access(bucket_name: str) -> Dict[str, Any]:
    """
    Check if an S3 bucket is publicly accessible.

    Args:
        bucket_name: Name of the S3 bucket

    Returns:
        Dictionary with accessibility information
    """
    result = {
        "bucket": bucket_name,
        "exists": False,
        "is_public": False,
        "list_allowed": False,
        "error": None,
    }

    urls_to_check = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    for url in urls_to_check:
        try:
            response = requests.head(url, timeout=10, allow_redirects=True)

            if response.status_code == 200:
                result["exists"] = True
                result["is_public"] = True
                result["list_allowed"] = True
                logger.warning(f"S3 bucket {bucket_name} is publicly accessible!")
                break
            elif response.status_code == 403:
                result["exists"] = True
                result["is_public"] = False
                logger.info(f"S3 bucket {bucket_name} exists but is not public")
                break
            elif response.status_code == 404:
                continue  # Try next URL
            elif response.status_code == 301 or response.status_code == 307:
                result["exists"] = True
                # Check redirect location for region info
                location = response.headers.get("x-amz-bucket-region")
                if location:
                    result["region"] = location
                break

        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            continue

    return result


def check_azure_blob_access(storage_account: str, container: str = None) -> Dict[str, Any]:
    """
    Check if an Azure Blob Storage is publicly accessible.

    Args:
        storage_account: Azure storage account name
        container: Optional container name

    Returns:
        Dictionary with accessibility information
    """
    result = {
        "storage_account": storage_account,
        "exists": False,
        "is_public": False,
        "containers": [],
        "error": None,
    }

    # Check if storage account exists
    url = f"https://{storage_account}.blob.core.windows.net"

    try:
        response = requests.head(url, timeout=10)

        if response.status_code == 400:
            # Storage account exists (400 = missing container parameter)
            result["exists"] = True

            # If container specified, check it
            if container:
                container_url = f"{url}/{container}?restype=container&comp=list"
                container_resp = requests.get(container_url, timeout=10)

                if container_resp.status_code == 200:
                    result["is_public"] = True
                    result["containers"].append(container)
                    logger.warning(f"Azure container {storage_account}/{container} is publicly accessible!")

        elif response.status_code == 404:
            result["exists"] = False

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


def check_gcp_bucket_access(bucket_name: str) -> Dict[str, Any]:
    """
    Check if a GCP Cloud Storage bucket is publicly accessible.

    Args:
        bucket_name: Name of the GCP bucket

    Returns:
        Dictionary with accessibility information
    """
    result = {
        "bucket": bucket_name,
        "exists": False,
        "is_public": False,
        "error": None,
    }

    url = f"https://storage.googleapis.com/{bucket_name}"

    try:
        response = requests.head(url, timeout=10)

        if response.status_code == 200:
            result["exists"] = True
            result["is_public"] = True
            logger.warning(f"GCP bucket {bucket_name} is publicly accessible!")
        elif response.status_code == 403:
            result["exists"] = True
            result["is_public"] = False
        elif response.status_code == 404:
            result["exists"] = False

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


def enumerate_cloud_assets(
    domain: str,
    subdomains: List[str] = None,
    dns_records: Dict[str, List[str]] = None,
    certificates: List[Dict] = None,
    check_access: bool = True
) -> Dict[str, Any]:
    """
    Comprehensive cloud asset enumeration for a domain.

    Args:
        domain: Target domain
        subdomains: List of discovered subdomains
        dns_records: DNS records (CNAME particularly useful)
        certificates: Certificate data with SANs
        check_access: Whether to check public accessibility of discovered assets

    Returns:
        Dictionary with categorized cloud assets
    """
    logger.info(f"Starting cloud asset enumeration for {domain}")

    all_hostnames: Set[str] = set()

    # Add subdomains
    if subdomains:
        all_hostnames.update(subdomains)

    # Add CNAME targets from DNS records
    if dns_records:
        cnames = dns_records.get("CNAME", [])
        for cname in cnames:
            if isinstance(cname, dict):
                all_hostnames.add(cname.get("record_value", ""))
            else:
                all_hostnames.add(str(cname))

    # Add SANs from certificates
    if certificates:
        for cert in certificates:
            sans = cert.get("subject_alt_names", "")
            if isinstance(sans, str):
                try:
                    import json
                    sans = json.loads(sans)
                except Exception:
                    sans = [sans]
            if isinstance(sans, list):
                all_hostnames.update(sans)

    # Detect cloud assets from all hostnames
    assets = detect_cloud_assets_from_hostnames(list(all_hostnames))

    # Categorize assets
    result = {
        "domain": domain,
        "total_assets": len(assets),
        "aws": {"count": 0, "assets": []},
        "azure": {"count": 0, "assets": []},
        "gcp": {"count": 0, "assets": []},
        "other": {"count": 0, "assets": []},
        "public_assets": [],
        "checked_count": 0,
    }

    for asset in assets:
        asset_dict = asset.to_dict()

        # Check accessibility if requested
        if check_access:
            if asset.provider == CloudProvider.AWS and asset.asset_type == "s3_bucket":
                access_info = check_s3_bucket_access(asset.identifier)
                asset_dict.update(access_info)
                result["checked_count"] += 1
                if access_info.get("is_public"):
                    result["public_assets"].append(asset_dict)

            elif asset.provider == CloudProvider.AZURE and asset.asset_type == "blob_storage":
                access_info = check_azure_blob_access(asset.identifier)
                asset_dict.update(access_info)
                result["checked_count"] += 1
                if access_info.get("is_public"):
                    result["public_assets"].append(asset_dict)

            elif asset.provider == CloudProvider.GCP and asset.asset_type == "cloud_storage":
                access_info = check_gcp_bucket_access(asset.identifier)
                asset_dict.update(access_info)
                result["checked_count"] += 1
                if access_info.get("is_public"):
                    result["public_assets"].append(asset_dict)

        # Categorize by provider
        if asset.provider == CloudProvider.AWS:
            result["aws"]["assets"].append(asset_dict)
            result["aws"]["count"] += 1
        elif asset.provider == CloudProvider.AZURE:
            result["azure"]["assets"].append(asset_dict)
            result["azure"]["count"] += 1
        elif asset.provider == CloudProvider.GCP:
            result["gcp"]["assets"].append(asset_dict)
            result["gcp"]["count"] += 1
        else:
            result["other"]["assets"].append(asset_dict)
            result["other"]["count"] += 1

    logger.info(
        f"Cloud enumeration complete for {domain}: "
        f"AWS={result['aws']['count']}, Azure={result['azure']['count']}, "
        f"GCP={result['gcp']['count']}, Other={result['other']['count']}, "
        f"Public={len(result['public_assets'])}"
    )

    return result


def generate_bucket_permutations(domain: str, company_name: str = None) -> List[str]:
    """
    Generate potential bucket/storage names based on domain and company name.
    Useful for discovering unlinked cloud storage.

    Args:
        domain: Target domain
        company_name: Optional company name for additional permutations

    Returns:
        List of potential bucket names to check
    """
    base_name = domain.split(".")[0]
    names = [base_name]

    if company_name:
        names.append(company_name.lower().replace(" ", "-"))
        names.append(company_name.lower().replace(" ", ""))

    permutations: Set[str] = set()

    suffixes = [
        "", "-dev", "-prod", "-staging", "-test", "-backup", "-data",
        "-assets", "-static", "-media", "-uploads", "-files", "-logs",
        "-db", "-database", "-archive", "-public", "-private", "-internal",
        "-web", "-api", "-app", "-cdn", "-images", "-docs", "-config",
    ]

    prefixes = [
        "", "dev-", "prod-", "staging-", "test-", "backup-",
    ]

    for name in names:
        for suffix in suffixes:
            for prefix in prefixes:
                bucket = f"{prefix}{name}{suffix}".strip("-")
                if 3 <= len(bucket) <= 63:  # Valid bucket name length
                    permutations.add(bucket)

    return list(permutations)
