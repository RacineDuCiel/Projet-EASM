"""
API endpoints for Phase 5 Security Posture features:
- Compliance Mapping

These endpoints provide advanced security analysis capabilities.
"""
import sys
import os
import json
from typing import Any, List, Optional, Dict
from uuid import UUID
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging

from src import crud, models, schemas
from src.schemas import security_posture as sp_schemas
from src.api.v1.endpoints import auth
from src.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# Compliance Mapping Endpoints
# =============================================================================

@router.post("/compliance/analyze", response_model=sp_schemas.ComplianceAnalysisResponse)
async def analyze_compliance(
    request: sp_schemas.ComplianceAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Analyze vulnerabilities against compliance frameworks.

    Supported frameworks:
    - ISO 27001:2022 - Information Security Management
    - SOC 2 Type II - Trust Service Criteria
    - NIST CSF 2.0 - Cybersecurity Framework
    - PCI-DSS 4.0 - Payment Card Industry Data Security Standard

    Returns compliance scores, affected controls, and gap analysis.
    """
    try:
        from src.security.compliance_mapping import analyze_compliance as do_analyze
    except ImportError as e:
        logger.error(f"Failed to import compliance_mapping module: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Compliance mapping module not available"
        )

    # Convert vulnerabilities to dict format
    vulns = [
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "status": v.status,
            "asset_value": v.asset_value,
        }
        for v in request.vulnerabilities
    ]

    # Convert frameworks
    frameworks = None
    if request.frameworks:
        frameworks = [f.value for f in request.frameworks]

    # Perform analysis
    result = do_analyze(
        vulnerabilities=vulns,
        frameworks=frameworks,
        asset_criticality=request.asset_criticality,
    )

    # Convert framework scores
    framework_scores = {}
    for fw, score_data in result.get("framework_scores", {}).items():
        if hasattr(fw, 'value'):
            fw_key = fw.value
        else:
            fw_key = str(fw)
        framework_scores[fw_key] = sp_schemas.FrameworkScore(
            framework=fw_key,
            score=score_data.get("score", 100),
            total_controls=score_data.get("total_controls", 0),
            affected_controls=score_data.get("affected_controls", 0),
            compliant_controls=score_data.get("compliant_controls", 0),
            severity_breakdown=score_data.get("severity_breakdown", {}),
        )

    # Convert gap analysis
    gaps = [
        sp_schemas.ComplianceGap(
            control_id=g["control_id"],
            framework=g["framework"],
            title=g["title"],
            severity=g["severity"],
            priority=g["priority"],
            effort=g["effort"],
            business_impact=g["business_impact"],
            finding_count=g.get("finding_count", 0),
        )
        for g in result.get("gap_analysis", [])
    ]

    return sp_schemas.ComplianceAnalysisResponse(
        timestamp=datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00")) if isinstance(result.get("timestamp"), str) else datetime.now(timezone.utc),
        total_vulnerabilities=result.get("total_vulnerabilities", len(vulns)),
        framework_scores=framework_scores,
        gap_analysis=gaps,
        affected_controls_by_framework=result.get("affected_controls_by_framework", {}),
    )


@router.post("/compliance/report", response_model=sp_schemas.ComplianceReport)
async def generate_compliance_report(
    request: sp_schemas.ComplianceReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Generate a comprehensive compliance report.

    Includes:
    - Executive summary with overall risk level
    - Framework-specific compliance scores
    - Gap analysis with prioritized findings
    - Remediation roadmap with phases
    """
    try:
        from src.security.compliance_mapping import generate_attestation_data
    except ImportError as e:
        logger.error(f"Failed to import compliance_mapping module: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Compliance mapping module not available"
        )

    # Convert vulnerabilities
    vulns = [
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "status": v.status,
            "asset_value": v.asset_value,
        }
        for v in request.vulnerabilities
    ]

    # Convert frameworks
    frameworks = None
    if request.frameworks:
        frameworks = [f.value for f in request.frameworks]

    # Generate report
    report = generate_attestation_data(
        organization=request.organization_name,
        vulnerabilities=vulns,
        frameworks=frameworks,
    )

    # Parse and return
    exec_summary = report.get("executive_summary", {})
    return sp_schemas.ComplianceReport(
        report_type=report.get("report_type", "Compliance Assessment Report"),
        organization=report.get("organization", request.organization_name),
        generated_at=datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00")) if isinstance(report.get("generated_at"), str) else datetime.now(timezone.utc),
        frameworks_assessed=report.get("frameworks_assessed", []),
        executive_summary=sp_schemas.ExecutiveSummary(
            overall_compliance_score=exec_summary.get("overall_compliance_score", 100),
            total_controls_assessed=exec_summary.get("total_controls_assessed", 0),
            non_compliant_controls=exec_summary.get("non_compliant_controls", 0),
            compliant_controls=exec_summary.get("compliant_controls", 0),
            risk_level=exec_summary.get("risk_level", "Low"),
        ),
        framework_details=report.get("framework_details", {}),
        gaps=[
            sp_schemas.ComplianceGap(
                control_id=g.get("control_id", ""),
                framework=g.get("framework", ""),
                title=g.get("title", ""),
                severity=g.get("severity", "info"),
                priority=g.get("priority", 5),
                effort=g.get("effort", "low"),
                business_impact=g.get("business_impact", ""),
                finding_count=g.get("finding_count", 0),
            )
            for g in report.get("gaps", [])
        ],
        remediation_roadmap=[
            sp_schemas.RemediationPhase(
                phase=phase.get("phase", ""),
                priority=phase.get("priority", 5),
                items=[
                    sp_schemas.RemediationItem(
                        control=item.get("control", ""),
                        framework=item.get("framework", ""),
                        title=item.get("title", ""),
                        effort=item.get("effort", "low"),
                    )
                    for item in phase.get("items", [])
                ],
                total_items=phase.get("total_items", 0),
            )
            for phase in report.get("remediation_roadmap", [])
        ],
    )


@router.post("/compliance/map-vulnerability", response_model=sp_schemas.SingleVulnerabilityMappingResponse)
async def map_single_vulnerability(
    request: sp_schemas.SingleVulnerabilityMappingRequest,
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Map a single vulnerability to compliance controls.

    Useful for understanding the compliance impact of individual findings.
    """
    try:
        from src.security.compliance_mapping import map_vulnerability_to_controls
    except ImportError as e:
        logger.error(f"Failed to import compliance_mapping module: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Compliance mapping module not available"
        )

    vuln = {
        "id": request.vulnerability.id,
        "title": request.vulnerability.title,
        "severity": request.vulnerability.severity,
    }

    mapping = map_vulnerability_to_controls(vuln)

    return sp_schemas.SingleVulnerabilityMappingResponse(
        vulnerability_title=request.vulnerability.title,
        control_mappings=mapping,
    )


@router.get("/compliance/frameworks")
async def get_compliance_frameworks(
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Get available compliance frameworks and their descriptions.
    """
    return {
        "frameworks": [
            {
                "id": "iso_27001",
                "name": "ISO 27001:2022",
                "description": "International standard for information security management systems (ISMS)",
                "categories": ["Organizational", "People", "Physical", "Technological"],
                "total_controls": 93,
            },
            {
                "id": "soc2",
                "name": "SOC 2 Type II",
                "description": "Trust Service Criteria for service organizations",
                "categories": ["Control Environment", "Risk Assessment", "Control Activities", "Logical and Physical Access", "System Operations", "Change Management", "Availability", "Confidentiality"],
                "total_controls": 64,
            },
            {
                "id": "nist_csf",
                "name": "NIST CSF 2.0",
                "description": "Cybersecurity Framework from the National Institute of Standards and Technology",
                "categories": ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"],
                "total_controls": 106,
            },
            {
                "id": "pci_dss",
                "name": "PCI-DSS 4.0",
                "description": "Payment Card Industry Data Security Standard",
                "categories": ["Network Security", "Secure Configurations", "Data Protection", "Transmission Security", "Malware Protection", "Secure Development", "Access Control", "Authentication", "Logging", "Security Testing", "Policy"],
                "total_controls": 78,
            },
        ]
    }


@router.get("/compliance/score/{framework}")
async def get_compliance_score_for_framework(
    framework: str,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Get compliance score for a specific framework based on current vulnerabilities.

    Pulls vulnerabilities from the database for the user's program.
    """
    if current_user.role == models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot access program-specific compliance scores"
        )

    try:
        from src.security.compliance_mapping import get_compliance_score
    except ImportError as e:
        logger.error(f"Failed to import compliance_mapping module: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Compliance mapping module not available"
        )

    # Get vulnerabilities for user's program
    vulnerabilities = await crud.vulnerability.get_multi(
        db,
        program_id=current_user.program_id,
        limit=1000,  # Get all for accurate scoring
    )

    vulns = [
        {
            "id": str(v.id),
            "title": v.title,
            "severity": v.severity.value if hasattr(v.severity, 'value') else v.severity,
        }
        for v in vulnerabilities
    ]

    result = get_compliance_score(vulns, framework)

    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )

    return result
