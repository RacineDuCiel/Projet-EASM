"""
Schemes for Phase 5 Security Posture features:
- Compliance Mapping
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


# =============================================================================
# Compliance Mapping Schemas
# =============================================================================

class ComplianceFramework(str, Enum):
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"


class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class VulnerabilityForCompliance(BaseModel):
    id: Optional[str] = None
    title: str
    severity: str
    status: Optional[str] = None
    asset_value: Optional[str] = None


class ComplianceAnalysisRequest(BaseModel):
    vulnerabilities: List[VulnerabilityForCompliance]
    frameworks: Optional[List[ComplianceFramework]] = None
    asset_criticality: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class ControlDetail(BaseModel):
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    subcategory: Optional[str] = None
    status: ControlStatus
    finding_count: int
    remediation_guidance: Optional[str] = None


class ComplianceGap(BaseModel):
    control_id: str
    framework: str
    title: str
    severity: str
    priority: int = Field(ge=1, le=5)
    effort: str
    business_impact: str
    finding_count: int = 0


class FrameworkScore(BaseModel):
    framework: str
    score: float = Field(ge=0.0, le=100.0)
    total_controls: int
    affected_controls: int
    compliant_controls: int
    severity_breakdown: Dict[str, int]


class ComplianceAnalysisResponse(BaseModel):
    timestamp: datetime
    total_vulnerabilities: int
    framework_scores: Dict[str, FrameworkScore]
    gap_analysis: List[ComplianceGap]
    affected_controls_by_framework: Dict[str, List[str]]


class ComplianceReportRequest(BaseModel):
    organization_name: str = "Organization"
    vulnerabilities: List[VulnerabilityForCompliance]
    frameworks: Optional[List[ComplianceFramework]] = None
    include_details: bool = True


class RemediationItem(BaseModel):
    control: str
    framework: str
    title: str
    effort: str


class RemediationPhase(BaseModel):
    phase: str
    priority: int
    items: List[RemediationItem]
    total_items: int


class ExecutiveSummary(BaseModel):
    overall_compliance_score: float
    total_controls_assessed: int
    non_compliant_controls: int
    compliant_controls: int
    risk_level: str


class ComplianceReport(BaseModel):
    report_type: str = "Compliance Assessment Report"
    organization: str
    generated_at: datetime
    frameworks_assessed: List[str]
    executive_summary: ExecutiveSummary
    framework_details: Dict[str, Any]
    gaps: List[ComplianceGap]
    remediation_roadmap: List[RemediationPhase]


class SingleVulnerabilityMappingRequest(BaseModel):
    vulnerability: VulnerabilityForCompliance


class SingleVulnerabilityMappingResponse(BaseModel):
    vulnerability_title: str
    control_mappings: Dict[str, List[str]]
