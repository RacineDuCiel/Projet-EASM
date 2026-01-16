"""
Profile configuration definitions and builders.
Central place defining what each profile does.
"""
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from src.models.enums import ScanProfile, ScanPhase, AssetCriticality


@dataclass
class ProfileConfig:
    """Configuration generated for a specific scan."""
    profile: ScanProfile
    phases: List[ScanPhase]

    # Port configuration
    ports: str

    # Nuclei configuration
    nuclei_rate_limit: int
    nuclei_timeout: int
    nuclei_retries: int
    run_prioritized_templates: bool
    run_full_templates: bool

    # Passive recon
    passive_recon_enabled: bool
    passive_extended_enabled: bool

    # Delta scanning
    is_delta_scan: bool
    delta_threshold_hours: Optional[int]

    # API integrations
    enable_api_integrations: bool


# Port presets - reusable across profiles
PORT_PRESETS = {
    "minimal": "80,443",
    "standard": "80,443,8080,8443",
    "extended": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8000-8010,8080-8090,8443,9000-9010",
    "full": "1-65535"
}


# Profile definitions - the source of truth for profile behavior
PROFILE_DEFINITIONS: Dict[ScanProfile, Dict[str, Any]] = {
    ScanProfile.discovery: {
        "display_name": "Discovery",
        "description": "Reconnaissance passive uniquement. Découvre les assets sans scan actif.",
        "phases": [ScanPhase.asset_discovery],
        "port_preset": "minimal",
        "nuclei_intensity": "none",
        "passive_level": "essential",
        "rate_limit": 300,
        "timeout": 5,
        "retries": 1,
        "delta_enabled": False,
        "api_integrations": False,
        "estimated_duration": "2-5 min",
        "intensity_label": "Light (passive)",
    },
    ScanProfile.quick_assessment: {
        "display_name": "Quick Assessment",
        "description": "Scan rapide pour vulnérabilités basiques. 80% des vulns en 20% du temps.",
        "phases": [
            ScanPhase.asset_discovery,
            ScanPhase.service_enumeration,
            ScanPhase.tech_detection,
            ScanPhase.vuln_assessment
        ],
        "port_preset": "standard",
        "nuclei_intensity": "prioritized",
        "passive_level": "essential",
        "rate_limit": 300,
        "timeout": 5,
        "retries": 1,
        "delta_enabled": False,
        "api_integrations": False,
        "estimated_duration": "5-15 min",
        "intensity_label": "Medium",
    },
    ScanProfile.standard_assessment: {
        "display_name": "Standard Assessment",
        "description": "Approche équilibrée. Recommandé pour la plupart des cas.",
        "phases": [
            ScanPhase.asset_discovery,
            ScanPhase.service_enumeration,
            ScanPhase.tech_detection,
            ScanPhase.vuln_assessment
        ],
        "port_preset": "extended",
        "nuclei_intensity": "prioritized",
        "passive_level": "essential",
        "rate_limit": 150,
        "timeout": 10,
        "retries": 2,
        "delta_enabled": False,
        "api_integrations": True,
        "estimated_duration": "15-45 min",
        "intensity_label": "Medium-High",
    },
    ScanProfile.full_audit: {
        "display_name": "Full Audit",
        "description": "Scan exhaustif. Tous les templates Nuclei et recon passive étendue.",
        "phases": [
            ScanPhase.asset_discovery,
            ScanPhase.service_enumeration,
            ScanPhase.tech_detection,
            ScanPhase.vuln_assessment,
            ScanPhase.deep_analysis
        ],
        "port_preset": "extended",
        "nuclei_intensity": "full",
        "passive_level": "extended",
        "rate_limit": 100,
        "timeout": 15,
        "retries": 3,
        "delta_enabled": False,
        "api_integrations": True,
        "estimated_duration": "1-4 heures",
        "intensity_label": "Heavy",
    },
}


def build_profile_config(
    profile: ScanProfile,
    program_overrides: Optional[Dict[str, Any]] = None,
    asset_criticality: Optional[AssetCriticality] = None
) -> ProfileConfig:
    """
    Build scan configuration from profile + program settings + asset criticality.

    Criticality adjustments:
    - critical: Always run deep_analysis phase, full templates
    - high: Add extended ports if not already
    - medium: Use profile defaults
    - low: Use minimal ports, prioritized only
    """
    definition = PROFILE_DEFINITIONS[profile]
    program_overrides = program_overrides or {}

    # Start with profile defaults
    phases = list(definition["phases"])
    port_preset = definition["port_preset"]
    nuclei_intensity = definition["nuclei_intensity"]
    rate_limit = definition["rate_limit"]
    timeout = definition["timeout"]
    retries = definition["retries"]

    # Apply criticality adjustments
    if asset_criticality == AssetCriticality.critical:
        # Critical assets always get deep analysis
        if ScanPhase.deep_analysis not in phases:
            phases.append(ScanPhase.deep_analysis)
        nuclei_intensity = "full"
        port_preset = "extended"
        retries = max(retries, 3)
    elif asset_criticality == AssetCriticality.high:
        if port_preset in ("minimal", "standard"):
            port_preset = "extended"
        retries = max(retries, 2)
    elif asset_criticality == AssetCriticality.low:
        port_preset = "standard"
        nuclei_intensity = "prioritized" if nuclei_intensity != "none" else "none"
        # Remove deep_analysis for low-priority assets
        phases = [p for p in phases if p != ScanPhase.deep_analysis]

    # Apply program overrides
    ports = program_overrides.get("custom_ports") or PORT_PRESETS.get(port_preset, PORT_PRESETS["standard"])
    rate_limit = program_overrides.get("nuclei_rate_limit") or rate_limit
    timeout = program_overrides.get("nuclei_timeout") or timeout

    return ProfileConfig(
        profile=profile,
        phases=phases,
        ports=ports,
        nuclei_rate_limit=rate_limit,
        nuclei_timeout=timeout,
        nuclei_retries=retries,
        run_prioritized_templates=nuclei_intensity in ("prioritized", "full"),
        run_full_templates=nuclei_intensity == "full",
        passive_recon_enabled=definition["passive_level"] != "none",
        passive_extended_enabled=definition["passive_level"] == "extended",
        is_delta_scan=definition["delta_enabled"],
        delta_threshold_hours=24 if definition["delta_enabled"] else None,
        enable_api_integrations=definition["api_integrations"],
    )


def get_profile_info(profile: ScanProfile) -> Dict[str, Any]:
    """Get display information for a profile."""
    definition = PROFILE_DEFINITIONS[profile]
    return {
        "profile": profile.value,
        "display_name": definition["display_name"],
        "description": definition["description"],
        "phases": [p.value for p in definition["phases"]],
        "estimated_duration": definition["estimated_duration"],
        "intensity": definition["intensity_label"],
    }


def get_all_profiles_info() -> List[Dict[str, Any]]:
    """Get display information for all profiles."""
    return [get_profile_info(profile) for profile in ScanProfile]
