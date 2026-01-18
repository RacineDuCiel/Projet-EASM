# Security modules for Phase 5 features
from .compliance_mapping import (
    ComplianceAnalyzer,
    ComplianceFramework,
    ControlStatus,
    analyze_compliance,
    get_compliance_score,
    generate_attestation_data,
    map_vulnerability_to_controls,
)

