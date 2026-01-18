"""
Compliance Mapping Module for EASM Platform.

Maps vulnerabilities and security findings to compliance frameworks:
- ISO 27001:2022 - Information Security Management
- SOC 2 Type II - Trust Service Criteria
- NIST CSF 2.0 - Cybersecurity Framework
- PCI-DSS 4.0 - Payment Card Industry Data Security Standard

Features:
- Automatic control mapping from vulnerabilities
- Gap analysis and compliance scoring
- Remediation prioritization based on compliance impact
- Audit-ready report generation
"""
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"


class ControlStatus(Enum):
    """Status of a compliance control."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceControl:
    """Represents a compliance control/requirement."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    subcategory: Optional[str] = None
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    findings: List[Dict[str, Any]] = field(default_factory=list)
    remediation_guidance: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class ComplianceGap:
    """Represents a compliance gap identified."""
    control: ComplianceControl
    vulnerability_ids: List[str]
    severity: Severity
    business_impact: str
    remediation_priority: int  # 1-5, 1 being highest
    estimated_effort: str  # "low", "medium", "high"


# =============================================================================
# ISO 27001:2022 Controls Mapping
# =============================================================================

ISO_27001_CONTROLS = {
    # A.5 - Organizational controls
    "A.5.1": {
        "title": "Policies for information security",
        "description": "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties.",
        "category": "Organizational",
        "subcategory": "Policies"
    },
    "A.5.7": {
        "title": "Threat intelligence",
        "description": "Information relating to information security threats shall be collected and analysed to produce threat intelligence.",
        "category": "Organizational",
        "subcategory": "Threat Intelligence"
    },
    "A.5.23": {
        "title": "Information security for use of cloud services",
        "description": "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements.",
        "category": "Organizational",
        "subcategory": "Cloud Security"
    },
    # A.8 - Technological controls
    "A.8.2": {
        "title": "Privileged access rights",
        "description": "The allocation and use of privileged access rights shall be restricted and managed.",
        "category": "Technological",
        "subcategory": "Access Control"
    },
    "A.8.5": {
        "title": "Secure authentication",
        "description": "Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.",
        "category": "Technological",
        "subcategory": "Authentication"
    },
    "A.8.7": {
        "title": "Protection against malware",
        "description": "Protection against malware shall be implemented and supported by appropriate user awareness.",
        "category": "Technological",
        "subcategory": "Malware Protection"
    },
    "A.8.8": {
        "title": "Management of technical vulnerabilities",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken.",
        "category": "Technological",
        "subcategory": "Vulnerability Management"
    },
    "A.8.9": {
        "title": "Configuration management",
        "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        "category": "Technological",
        "subcategory": "Configuration"
    },
    "A.8.12": {
        "title": "Data leakage prevention",
        "description": "Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.",
        "category": "Technological",
        "subcategory": "Data Protection"
    },
    "A.8.15": {
        "title": "Logging",
        "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
        "category": "Technological",
        "subcategory": "Logging"
    },
    "A.8.20": {
        "title": "Networks security",
        "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
        "category": "Technological",
        "subcategory": "Network Security"
    },
    "A.8.21": {
        "title": "Security of network services",
        "description": "Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.",
        "category": "Technological",
        "subcategory": "Network Services"
    },
    "A.8.24": {
        "title": "Use of cryptography",
        "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
        "category": "Technological",
        "subcategory": "Cryptography"
    },
    "A.8.26": {
        "title": "Application security requirements",
        "description": "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
        "category": "Technological",
        "subcategory": "Application Security"
    },
    "A.8.28": {
        "title": "Secure coding",
        "description": "Secure coding principles shall be applied to software development.",
        "category": "Technological",
        "subcategory": "Secure Development"
    },
}


# =============================================================================
# SOC 2 Trust Service Criteria Mapping
# =============================================================================

SOC2_CONTROLS = {
    # CC - Common Criteria (Security)
    "CC1.1": {
        "title": "COSO Principle 1 - Integrity and Ethical Values",
        "description": "The entity demonstrates a commitment to integrity and ethical values.",
        "category": "Control Environment",
        "subcategory": "Integrity"
    },
    "CC3.1": {
        "title": "COSO Principle 6 - Risk Assessment",
        "description": "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.",
        "category": "Risk Assessment",
        "subcategory": "Objectives"
    },
    "CC3.2": {
        "title": "COSO Principle 7 - Risk Identification",
        "description": "The entity identifies risks to the achievement of its objectives and analyzes risks as a basis for determining how the risks should be managed.",
        "category": "Risk Assessment",
        "subcategory": "Risk Identification"
    },
    "CC5.1": {
        "title": "COSO Principle 10 - Control Activities",
        "description": "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
        "category": "Control Activities",
        "subcategory": "Control Selection"
    },
    "CC6.1": {
        "title": "Logical and Physical Access",
        "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
        "category": "Logical and Physical Access",
        "subcategory": "Access Control"
    },
    "CC6.2": {
        "title": "Access Provisioning",
        "description": "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
        "category": "Logical and Physical Access",
        "subcategory": "Provisioning"
    },
    "CC6.3": {
        "title": "Access Removal",
        "description": "The entity removes access to protected information assets when appropriate.",
        "category": "Logical and Physical Access",
        "subcategory": "Deprovisioning"
    },
    "CC6.6": {
        "title": "System Boundaries",
        "description": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
        "category": "Logical and Physical Access",
        "subcategory": "Boundary Protection"
    },
    "CC6.7": {
        "title": "Information Transmission",
        "description": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
        "category": "Logical and Physical Access",
        "subcategory": "Data Transmission"
    },
    "CC7.1": {
        "title": "Vulnerability Management",
        "description": "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
        "category": "System Operations",
        "subcategory": "Vulnerability Detection"
    },
    "CC7.2": {
        "title": "Security Event Monitoring",
        "description": "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.",
        "category": "System Operations",
        "subcategory": "Monitoring"
    },
    "CC7.3": {
        "title": "Security Incident Evaluation",
        "description": "The entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives.",
        "category": "System Operations",
        "subcategory": "Incident Evaluation"
    },
    "CC7.4": {
        "title": "Incident Response",
        "description": "The entity responds to identified security incidents by executing a defined incident response program.",
        "category": "System Operations",
        "subcategory": "Incident Response"
    },
    "CC8.1": {
        "title": "Change Management",
        "description": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
        "category": "Change Management",
        "subcategory": "Change Control"
    },
    # A - Availability
    "A1.1": {
        "title": "Capacity Management",
        "description": "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand.",
        "category": "Availability",
        "subcategory": "Capacity"
    },
    "A1.2": {
        "title": "Recovery Procedures",
        "description": "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure.",
        "category": "Availability",
        "subcategory": "Recovery"
    },
    # C - Confidentiality
    "C1.1": {
        "title": "Confidential Information Identification",
        "description": "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
        "category": "Confidentiality",
        "subcategory": "Data Classification"
    },
    "C1.2": {
        "title": "Confidential Information Disposal",
        "description": "The entity disposes of confidential information to meet the entity's objectives related to confidentiality.",
        "category": "Confidentiality",
        "subcategory": "Data Disposal"
    },
}


# =============================================================================
# NIST CSF 2.0 Controls Mapping
# =============================================================================

NIST_CSF_CONTROLS = {
    # GV - Govern
    "GV.OC-01": {
        "title": "Organizational Context",
        "description": "The organizational mission is understood and informs cybersecurity risk management.",
        "category": "Govern",
        "subcategory": "Organizational Context"
    },
    "GV.RM-01": {
        "title": "Risk Management Strategy",
        "description": "Risk management objectives are established and agreed to by organizational stakeholders.",
        "category": "Govern",
        "subcategory": "Risk Management"
    },
    # ID - Identify
    "ID.AM-01": {
        "title": "Hardware Asset Inventory",
        "description": "Inventories of hardware managed by the organization are maintained.",
        "category": "Identify",
        "subcategory": "Asset Management"
    },
    "ID.AM-02": {
        "title": "Software Asset Inventory",
        "description": "Inventories of software, services, and systems managed by the organization are maintained.",
        "category": "Identify",
        "subcategory": "Asset Management"
    },
    "ID.AM-03": {
        "title": "Network Mapping",
        "description": "Representations of the organization's authorized network communication and internal and external network data flows are maintained.",
        "category": "Identify",
        "subcategory": "Asset Management"
    },
    "ID.RA-01": {
        "title": "Vulnerability Identification",
        "description": "Vulnerabilities in assets are identified, validated, and recorded.",
        "category": "Identify",
        "subcategory": "Risk Assessment"
    },
    "ID.RA-02": {
        "title": "Threat Intelligence",
        "description": "Cyber threat intelligence is received from information sharing forums and sources.",
        "category": "Identify",
        "subcategory": "Risk Assessment"
    },
    "ID.RA-05": {
        "title": "Risk Prioritization",
        "description": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization.",
        "category": "Identify",
        "subcategory": "Risk Assessment"
    },
    # PR - Protect
    "PR.AA-01": {
        "title": "Identity Management",
        "description": "Identities and credentials for authorized users, services, and hardware are managed by the organization.",
        "category": "Protect",
        "subcategory": "Identity Management"
    },
    "PR.AA-03": {
        "title": "Authentication",
        "description": "Users, services, and hardware are authenticated.",
        "category": "Protect",
        "subcategory": "Identity Management"
    },
    "PR.AA-05": {
        "title": "Access Permissions",
        "description": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.",
        "category": "Protect",
        "subcategory": "Identity Management"
    },
    "PR.DS-01": {
        "title": "Data-at-Rest Protection",
        "description": "The confidentiality, integrity, and availability of data-at-rest are protected.",
        "category": "Protect",
        "subcategory": "Data Security"
    },
    "PR.DS-02": {
        "title": "Data-in-Transit Protection",
        "description": "The confidentiality, integrity, and availability of data-in-transit are protected.",
        "category": "Protect",
        "subcategory": "Data Security"
    },
    "PR.PS-01": {
        "title": "Configuration Management",
        "description": "Configuration management practices are established and applied.",
        "category": "Protect",
        "subcategory": "Platform Security"
    },
    "PR.PS-02": {
        "title": "Software Maintenance",
        "description": "Software is maintained, replaced, and removed commensurate with risk.",
        "category": "Protect",
        "subcategory": "Platform Security"
    },
    "PR.PS-06": {
        "title": "Secure Development",
        "description": "Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle.",
        "category": "Protect",
        "subcategory": "Platform Security"
    },
    # DE - Detect
    "DE.CM-01": {
        "title": "Network Monitoring",
        "description": "Networks and network services are monitored to find potentially adverse events.",
        "category": "Detect",
        "subcategory": "Continuous Monitoring"
    },
    "DE.CM-02": {
        "title": "Physical Environment Monitoring",
        "description": "The physical environment is monitored to find potentially adverse events.",
        "category": "Detect",
        "subcategory": "Continuous Monitoring"
    },
    "DE.CM-03": {
        "title": "Personnel Activity Monitoring",
        "description": "Personnel activity and technology usage are monitored to find potentially adverse events.",
        "category": "Detect",
        "subcategory": "Continuous Monitoring"
    },
    "DE.CM-06": {
        "title": "External Service Provider Monitoring",
        "description": "External service provider activities and services are monitored to find potentially adverse events.",
        "category": "Detect",
        "subcategory": "Continuous Monitoring"
    },
    "DE.CM-09": {
        "title": "Malicious Code Detection",
        "description": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events.",
        "category": "Detect",
        "subcategory": "Continuous Monitoring"
    },
    "DE.AE-02": {
        "title": "Event Analysis",
        "description": "Potentially adverse events are analyzed to better understand associated activities.",
        "category": "Detect",
        "subcategory": "Adverse Event Analysis"
    },
    "DE.AE-06": {
        "title": "Event Correlation",
        "description": "Information on adverse events is correlated from multiple sources.",
        "category": "Detect",
        "subcategory": "Adverse Event Analysis"
    },
    # RS - Respond
    "RS.MA-01": {
        "title": "Incident Management",
        "description": "The incident response plan is executed in coordination with relevant third parties once an incident is declared.",
        "category": "Respond",
        "subcategory": "Incident Management"
    },
    "RS.AN-03": {
        "title": "Incident Analysis",
        "description": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident.",
        "category": "Respond",
        "subcategory": "Incident Analysis"
    },
    # RC - Recover
    "RC.RP-01": {
        "title": "Recovery Execution",
        "description": "The recovery portion of the incident response plan is executed once initiated from the incident response process.",
        "category": "Recover",
        "subcategory": "Incident Recovery"
    },
}


# =============================================================================
# PCI-DSS 4.0 Requirements Mapping
# =============================================================================

PCI_DSS_CONTROLS = {
    # Requirement 1 - Network Security Controls
    "1.2.1": {
        "title": "Network Security Controls Configuration",
        "description": "Configuration standards for NSCs are defined, implemented, and maintained.",
        "category": "Network Security",
        "subcategory": "Configuration"
    },
    "1.3.1": {
        "title": "Inbound Traffic Restriction",
        "description": "Inbound traffic to the CDE is restricted to only traffic that is necessary.",
        "category": "Network Security",
        "subcategory": "Traffic Control"
    },
    "1.4.1": {
        "title": "Cardholder Data Environment Isolation",
        "description": "NSCs are implemented between trusted and untrusted networks.",
        "category": "Network Security",
        "subcategory": "Segmentation"
    },
    # Requirement 2 - Secure Configurations
    "2.2.1": {
        "title": "Configuration Standards",
        "description": "Configuration standards are developed, implemented, and maintained for system components.",
        "category": "Secure Configurations",
        "subcategory": "Standards"
    },
    "2.2.2": {
        "title": "Vendor Default Accounts",
        "description": "Vendor default accounts are managed appropriately.",
        "category": "Secure Configurations",
        "subcategory": "Default Credentials"
    },
    "2.2.4": {
        "title": "Unnecessary Services",
        "description": "Only necessary services, protocols, daemons, and functions are enabled.",
        "category": "Secure Configurations",
        "subcategory": "Hardening"
    },
    "2.2.5": {
        "title": "Security Parameters",
        "description": "Security parameters are set appropriately to prevent misuse.",
        "category": "Secure Configurations",
        "subcategory": "Security Settings"
    },
    # Requirement 3 - Protect Account Data
    "3.4.1": {
        "title": "PAN Display Masking",
        "description": "PAN is masked when displayed such that only personnel with a business need can see more than the first six/last four digits of the PAN.",
        "category": "Data Protection",
        "subcategory": "Display"
    },
    "3.5.1": {
        "title": "Encryption Key Management",
        "description": "Strong cryptography is used to render all stored PAN unreadable.",
        "category": "Data Protection",
        "subcategory": "Encryption"
    },
    # Requirement 4 - Protect Data in Transit
    "4.2.1": {
        "title": "Transmission Encryption",
        "description": "Strong cryptography is used during transmission of PAN.",
        "category": "Transmission Security",
        "subcategory": "Encryption"
    },
    "4.2.2": {
        "title": "Secure Protocols",
        "description": "PAN is secured with strong cryptography whenever it is transmitted over end-user messaging technologies.",
        "category": "Transmission Security",
        "subcategory": "Protocols"
    },
    # Requirement 5 - Malware Protection
    "5.2.1": {
        "title": "Anti-Malware Deployment",
        "description": "An anti-malware solution is deployed on all system components.",
        "category": "Malware Protection",
        "subcategory": "Deployment"
    },
    "5.3.1": {
        "title": "Anti-Malware Mechanisms",
        "description": "The anti-malware solution performs periodic scans and active or real-time scans.",
        "category": "Malware Protection",
        "subcategory": "Scanning"
    },
    # Requirement 6 - Secure Development
    "6.2.1": {
        "title": "Secure Development Standards",
        "description": "Bespoke and custom software are developed securely.",
        "category": "Secure Development",
        "subcategory": "Development"
    },
    "6.2.4": {
        "title": "Code Review",
        "description": "Software engineering techniques are defined and in use by developers.",
        "category": "Secure Development",
        "subcategory": "Review"
    },
    "6.3.1": {
        "title": "Vulnerability Identification",
        "description": "Security vulnerabilities are identified and managed.",
        "category": "Secure Development",
        "subcategory": "Vulnerability Management"
    },
    "6.3.3": {
        "title": "Security Patching",
        "description": "System components are protected from known vulnerabilities by installing applicable security patches/updates.",
        "category": "Secure Development",
        "subcategory": "Patching"
    },
    "6.4.1": {
        "title": "Public-Facing Web Applications",
        "description": "Public-facing web applications are protected against attacks.",
        "category": "Secure Development",
        "subcategory": "Web Security"
    },
    # Requirement 7 - Access Control
    "7.2.1": {
        "title": "Access Control Model",
        "description": "An access control model is defined and includes granting access based on job responsibilities.",
        "category": "Access Control",
        "subcategory": "Model"
    },
    "7.2.2": {
        "title": "User Assignment",
        "description": "Access is assigned to users based on job classification and function.",
        "category": "Access Control",
        "subcategory": "Assignment"
    },
    # Requirement 8 - Authentication
    "8.2.1": {
        "title": "User Identification",
        "description": "All users are assigned a unique ID before access to system components.",
        "category": "Authentication",
        "subcategory": "Identification"
    },
    "8.3.1": {
        "title": "Strong Authentication",
        "description": "All user access to system components is authenticated via strong authentication.",
        "category": "Authentication",
        "subcategory": "Strength"
    },
    "8.3.6": {
        "title": "Password Complexity",
        "description": "Passwords/passphrases meet minimum complexity requirements.",
        "category": "Authentication",
        "subcategory": "Password Policy"
    },
    "8.3.10": {
        "title": "Password History",
        "description": "Passwords/passphrases must be different from the last four passwords used.",
        "category": "Authentication",
        "subcategory": "Password Policy"
    },
    # Requirement 10 - Logging and Monitoring
    "10.2.1": {
        "title": "Audit Log Content",
        "description": "Audit logs are enabled and active for all system components.",
        "category": "Logging",
        "subcategory": "Content"
    },
    "10.4.1": {
        "title": "Audit Log Review",
        "description": "Audit logs are reviewed at least once daily.",
        "category": "Logging",
        "subcategory": "Review"
    },
    # Requirement 11 - Security Testing
    "11.3.1": {
        "title": "Vulnerability Scanning",
        "description": "Internal vulnerability scans are performed at least quarterly.",
        "category": "Security Testing",
        "subcategory": "Vulnerability Scanning"
    },
    "11.3.2": {
        "title": "External Vulnerability Scanning",
        "description": "External vulnerability scans are performed at least quarterly by an ASV.",
        "category": "Security Testing",
        "subcategory": "Vulnerability Scanning"
    },
    "11.4.1": {
        "title": "Penetration Testing",
        "description": "Penetration testing is performed at least annually and after significant changes.",
        "category": "Security Testing",
        "subcategory": "Penetration Testing"
    },
    # Requirement 12 - Policies and Programs
    "12.1.1": {
        "title": "Security Policy",
        "description": "An overall information security policy is established, published, maintained, and disseminated.",
        "category": "Policy",
        "subcategory": "Documentation"
    },
    "12.10.1": {
        "title": "Incident Response Plan",
        "description": "An incident response plan exists to be activated in the event of a suspected or confirmed security incident.",
        "category": "Policy",
        "subcategory": "Incident Response"
    },
}


# =============================================================================
# Vulnerability to Control Mapping
# =============================================================================

VULNERABILITY_CONTROL_MAPPING = {
    # SQL Injection variants
    "sql-injection": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06", "DE.CM-09"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.2.4", "6.4.1"],
    },
    "blind-sql-injection": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06", "DE.CM-09"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.2.4", "6.4.1"],
    },
    # XSS variants
    "xss": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.4.1"],
    },
    "cross-site-scripting": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.4.1"],
    },
    "reflected-xss": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.4.1"],
    },
    "stored-xss": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.4.1"],
    },
    # Authentication/Access issues
    "authentication-bypass": {
        ComplianceFramework.ISO_27001: ["A.8.2", "A.8.5"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.2", "CC6.3"],
        ComplianceFramework.NIST_CSF: ["PR.AA-01", "PR.AA-03"],
        ComplianceFramework.PCI_DSS: ["7.2.1", "8.2.1", "8.3.1"],
    },
    "broken-authentication": {
        ComplianceFramework.ISO_27001: ["A.8.2", "A.8.5"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.2"],
        ComplianceFramework.NIST_CSF: ["PR.AA-01", "PR.AA-03"],
        ComplianceFramework.PCI_DSS: ["8.2.1", "8.3.1", "8.3.6"],
    },
    "weak-password": {
        ComplianceFramework.ISO_27001: ["A.8.5"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.AA-03"],
        ComplianceFramework.PCI_DSS: ["8.3.6", "8.3.10"],
    },
    "default-credentials": {
        ComplianceFramework.ISO_27001: ["A.8.5", "A.8.9"],
        ComplianceFramework.SOC2: ["CC6.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.AA-03", "PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["2.2.2", "8.3.1"],
    },
    "exposed-admin-panel": {
        ComplianceFramework.ISO_27001: ["A.8.2", "A.8.20"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.AA-05", "PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["7.2.1", "1.3.1"],
    },
    # Injection attacks
    "command-injection": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.2.4"],
    },
    "os-command-injection": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "6.2.4"],
    },
    "code-injection": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    "template-injection": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    "ssti": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    # Path traversal / File inclusion
    "path-traversal": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.12"],
        ComplianceFramework.SOC2: ["CC6.1", "C1.1"],
        ComplianceFramework.NIST_CSF: ["PR.DS-01", "PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1", "3.4.1"],
    },
    "local-file-inclusion": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.12"],
        ComplianceFramework.SOC2: ["CC6.1", "C1.1"],
        ComplianceFramework.NIST_CSF: ["PR.DS-01"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    "remote-file-inclusion": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.7"],
        ComplianceFramework.SOC2: ["CC6.1", "CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.DS-01", "DE.CM-09"],
        ComplianceFramework.PCI_DSS: ["5.2.1", "6.2.1"],
    },
    # SSRF
    "ssrf": {
        ComplianceFramework.ISO_27001: ["A.8.20", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.6", "CC7.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06", "DE.CM-01"],
        ComplianceFramework.PCI_DSS: ["1.3.1", "6.2.1"],
    },
    "server-side-request-forgery": {
        ComplianceFramework.ISO_27001: ["A.8.20", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.6", "CC7.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06", "DE.CM-01"],
        ComplianceFramework.PCI_DSS: ["1.3.1", "6.2.1"],
    },
    # Exposure/Disclosure
    "information-disclosure": {
        ComplianceFramework.ISO_27001: ["A.8.12", "A.8.9"],
        ComplianceFramework.SOC2: ["C1.1", "CC6.7"],
        ComplianceFramework.NIST_CSF: ["PR.DS-01", "PR.DS-02"],
        ComplianceFramework.PCI_DSS: ["3.4.1", "6.2.1"],
    },
    "sensitive-data-exposure": {
        ComplianceFramework.ISO_27001: ["A.8.12", "A.8.24"],
        ComplianceFramework.SOC2: ["C1.1", "CC6.7"],
        ComplianceFramework.NIST_CSF: ["PR.DS-01", "PR.DS-02"],
        ComplianceFramework.PCI_DSS: ["3.4.1", "3.5.1", "4.2.1"],
    },
    "exposed-credentials": {
        ComplianceFramework.ISO_27001: ["A.8.5", "A.8.12"],
        ComplianceFramework.SOC2: ["CC6.1", "C1.1"],
        ComplianceFramework.NIST_CSF: ["PR.AA-01", "PR.DS-01"],
        ComplianceFramework.PCI_DSS: ["8.2.1", "3.5.1"],
    },
    "exposed-api-key": {
        ComplianceFramework.ISO_27001: ["A.8.5", "A.8.12"],
        ComplianceFramework.SOC2: ["CC6.1", "C1.1"],
        ComplianceFramework.NIST_CSF: ["PR.AA-01", "PR.DS-01"],
        ComplianceFramework.PCI_DSS: ["8.2.1", "3.5.1"],
    },
    # SSL/TLS issues
    "ssl-certificate-expired": {
        ComplianceFramework.ISO_27001: ["A.8.24"],
        ComplianceFramework.SOC2: ["CC6.7"],
        ComplianceFramework.NIST_CSF: ["PR.DS-02"],
        ComplianceFramework.PCI_DSS: ["4.2.1"],
    },
    "weak-ssl-cipher": {
        ComplianceFramework.ISO_27001: ["A.8.24"],
        ComplianceFramework.SOC2: ["CC6.7"],
        ComplianceFramework.NIST_CSF: ["PR.DS-02"],
        ComplianceFramework.PCI_DSS: ["4.2.1", "4.2.2"],
    },
    "ssl-tls-vulnerability": {
        ComplianceFramework.ISO_27001: ["A.8.24", "A.8.21"],
        ComplianceFramework.SOC2: ["CC6.7"],
        ComplianceFramework.NIST_CSF: ["PR.DS-02"],
        ComplianceFramework.PCI_DSS: ["4.2.1", "4.2.2"],
    },
    "missing-https": {
        ComplianceFramework.ISO_27001: ["A.8.24"],
        ComplianceFramework.SOC2: ["CC6.7"],
        ComplianceFramework.NIST_CSF: ["PR.DS-02"],
        ComplianceFramework.PCI_DSS: ["4.2.1"],
    },
    # Security misconfiguration
    "misconfiguration": {
        ComplianceFramework.ISO_27001: ["A.8.9"],
        ComplianceFramework.SOC2: ["CC8.1", "CC7.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["2.2.1", "2.2.5"],
    },
    "security-misconfiguration": {
        ComplianceFramework.ISO_27001: ["A.8.9"],
        ComplianceFramework.SOC2: ["CC8.1", "CC7.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["2.2.1", "2.2.5"],
    },
    "cors-misconfiguration": {
        ComplianceFramework.ISO_27001: ["A.8.9", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["6.4.1"],
    },
    "open-redirect": {
        ComplianceFramework.ISO_27001: ["A.8.26"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    # Header security
    "missing-security-headers": {
        ComplianceFramework.ISO_27001: ["A.8.9", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["6.4.1"],
    },
    "missing-csp": {
        ComplianceFramework.ISO_27001: ["A.8.26"],
        ComplianceFramework.SOC2: ["CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.4.1"],
    },
    "clickjacking": {
        ComplianceFramework.ISO_27001: ["A.8.26"],
        ComplianceFramework.SOC2: ["CC6.6"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.4.1"],
    },
    # Network/Infrastructure
    "open-port": {
        ComplianceFramework.ISO_27001: ["A.8.20"],
        ComplianceFramework.SOC2: ["CC6.6"],
        ComplianceFramework.NIST_CSF: ["DE.CM-01"],
        ComplianceFramework.PCI_DSS: ["1.3.1", "2.2.4"],
    },
    "unnecessary-service": {
        ComplianceFramework.ISO_27001: ["A.8.9", "A.8.20"],
        ComplianceFramework.SOC2: ["CC6.6", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["2.2.4"],
    },
    "dns-zone-transfer": {
        ComplianceFramework.ISO_27001: ["A.8.20", "A.8.12"],
        ComplianceFramework.SOC2: ["CC6.6"],
        ComplianceFramework.NIST_CSF: ["DE.CM-01"],
        ComplianceFramework.PCI_DSS: ["1.2.1"],
    },
    # Vulnerabilities / CVEs
    "cve": {
        ComplianceFramework.ISO_27001: ["A.8.8"],
        ComplianceFramework.SOC2: ["CC7.1"],
        ComplianceFramework.NIST_CSF: ["ID.RA-01", "PR.PS-02"],
        ComplianceFramework.PCI_DSS: ["6.3.1", "6.3.3", "11.3.1"],
    },
    "outdated-software": {
        ComplianceFramework.ISO_27001: ["A.8.8", "A.8.9"],
        ComplianceFramework.SOC2: ["CC7.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["ID.RA-01", "PR.PS-02"],
        ComplianceFramework.PCI_DSS: ["6.3.3"],
    },
    "unpatched-vulnerability": {
        ComplianceFramework.ISO_27001: ["A.8.8"],
        ComplianceFramework.SOC2: ["CC7.1"],
        ComplianceFramework.NIST_CSF: ["ID.RA-01", "PR.PS-02"],
        ComplianceFramework.PCI_DSS: ["6.3.1", "6.3.3"],
    },
    # Cloud-specific
    "public-s3-bucket": {
        ComplianceFramework.ISO_27001: ["A.5.23", "A.8.12"],
        ComplianceFramework.SOC2: ["CC6.1", "C1.1"],
        ComplianceFramework.NIST_CSF: ["PR.DS-01", "PR.AA-05"],
        ComplianceFramework.PCI_DSS: ["3.4.1", "7.2.1"],
    },
    "cloud-misconfiguration": {
        ComplianceFramework.ISO_27001: ["A.5.23", "A.8.9"],
        ComplianceFramework.SOC2: ["CC6.1", "CC8.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-01"],
        ComplianceFramework.PCI_DSS: ["2.2.1"],
    },
    # Malware / Remote Code Execution
    "rce": {
        ComplianceFramework.ISO_27001: ["A.8.7", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.1", "CC7.1"],
        ComplianceFramework.NIST_CSF: ["DE.CM-09", "PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["5.2.1", "6.2.1"],
    },
    "remote-code-execution": {
        ComplianceFramework.ISO_27001: ["A.8.7", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.1", "CC7.1"],
        ComplianceFramework.NIST_CSF: ["DE.CM-09", "PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["5.2.1", "6.2.1"],
    },
    "file-upload": {
        ComplianceFramework.ISO_27001: ["A.8.7", "A.8.26"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["DE.CM-09"],
        ComplianceFramework.PCI_DSS: ["5.2.1", "6.2.1"],
    },
    # XXE
    "xxe": {
        ComplianceFramework.ISO_27001: ["A.8.26"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    "xml-external-entity": {
        ComplianceFramework.ISO_27001: ["A.8.26"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    # Deserialization
    "deserialization": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
    "insecure-deserialization": {
        ComplianceFramework.ISO_27001: ["A.8.26", "A.8.28"],
        ComplianceFramework.SOC2: ["CC6.1"],
        ComplianceFramework.NIST_CSF: ["PR.PS-06"],
        ComplianceFramework.PCI_DSS: ["6.2.1"],
    },
}


# =============================================================================
# Compliance Analyzer Class
# =============================================================================

class ComplianceAnalyzer:
    """
    Analyzes vulnerabilities against compliance frameworks.

    Provides mapping, gap analysis, and reporting capabilities.
    """

    def __init__(self, frameworks: List[ComplianceFramework] = None):
        """
        Initialize the compliance analyzer.

        Args:
            frameworks: List of frameworks to analyze against. Defaults to all.
        """
        self.frameworks = frameworks or list(ComplianceFramework)
        self.controls: Dict[ComplianceFramework, Dict[str, ComplianceControl]] = {}
        self.gaps: List[ComplianceGap] = []
        self._initialize_controls()

    def _initialize_controls(self) -> None:
        """Initialize control objects for each framework."""
        framework_controls = {
            ComplianceFramework.ISO_27001: ISO_27001_CONTROLS,
            ComplianceFramework.SOC2: SOC2_CONTROLS,
            ComplianceFramework.NIST_CSF: NIST_CSF_CONTROLS,
            ComplianceFramework.PCI_DSS: PCI_DSS_CONTROLS,
        }

        for framework in self.frameworks:
            self.controls[framework] = {}
            control_defs = framework_controls.get(framework, {})
            for control_id, control_data in control_defs.items():
                self.controls[framework][control_id] = ComplianceControl(
                    control_id=control_id,
                    framework=framework,
                    title=control_data["title"],
                    description=control_data["description"],
                    category=control_data["category"],
                    subcategory=control_data.get("subcategory"),
                )

    def _normalize_vulnerability_type(self, vuln_title: str) -> str:
        """
        Normalize vulnerability title to a mapping key.

        Args:
            vuln_title: The vulnerability title or type

        Returns:
            Normalized key for mapping lookup
        """
        # Lowercase and replace spaces/special chars
        normalized = vuln_title.lower()
        normalized = normalized.replace(" ", "-").replace("_", "-")

        # Remove common prefixes
        prefixes = ["nuclei:", "detected-", "potential-", "possible-"]
        for prefix in prefixes:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]

        # Try to find direct match
        if normalized in VULNERABILITY_CONTROL_MAPPING:
            return normalized

        # Try to find partial match
        for vuln_type in VULNERABILITY_CONTROL_MAPPING:
            if vuln_type in normalized or normalized in vuln_type:
                return vuln_type

        # Generic categorization based on keywords
        keyword_mapping = {
            "sql": "sql-injection",
            "xss": "xss",
            "inject": "code-injection",
            "auth": "broken-authentication",
            "credential": "exposed-credentials",
            "password": "weak-password",
            "ssl": "ssl-tls-vulnerability",
            "tls": "ssl-tls-vulnerability",
            "certificate": "ssl-certificate-expired",
            "cve": "cve",
            "rce": "rce",
            "ssrf": "ssrf",
            "xxe": "xxe",
            "traversal": "path-traversal",
            "lfi": "local-file-inclusion",
            "rfi": "remote-file-inclusion",
            "disclosure": "information-disclosure",
            "exposure": "sensitive-data-exposure",
            "header": "missing-security-headers",
            "config": "misconfiguration",
            "redirect": "open-redirect",
            "cors": "cors-misconfiguration",
            "s3": "public-s3-bucket",
            "cloud": "cloud-misconfiguration",
            "port": "open-port",
            "default": "default-credentials",
            "admin": "exposed-admin-panel",
            "deserial": "deserialization",
            "upload": "file-upload",
            "template": "template-injection",
            "command": "command-injection",
            "dns": "dns-zone-transfer",
        }

        for keyword, vuln_type in keyword_mapping.items():
            if keyword in normalized:
                return vuln_type

        # Default to generic CVE if nothing matches
        return "cve"

    def map_vulnerability(
        self,
        vulnerability: Dict[str, Any]
    ) -> Dict[ComplianceFramework, List[str]]:
        """
        Map a vulnerability to compliance controls.

        Args:
            vulnerability: Vulnerability dict with 'title', 'severity', etc.

        Returns:
            Dict mapping frameworks to affected control IDs
        """
        vuln_title = vulnerability.get("title", vulnerability.get("name", ""))
        vuln_type = self._normalize_vulnerability_type(vuln_title)

        mapping = VULNERABILITY_CONTROL_MAPPING.get(vuln_type, {})
        result = {}

        for framework in self.frameworks:
            if framework in mapping:
                result[framework] = mapping[framework]
                # Update control findings
                for control_id in mapping[framework]:
                    if control_id in self.controls.get(framework, {}):
                        control = self.controls[framework][control_id]
                        control.findings.append(vulnerability)
                        control.status = ControlStatus.NON_COMPLIANT

        return result

    def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze a list of vulnerabilities against compliance frameworks.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Analysis results with mappings and statistics
        """
        mappings = []
        affected_controls = defaultdict(set)
        severity_counts = defaultdict(lambda: defaultdict(int))

        for vuln in vulnerabilities:
            vuln_mapping = self.map_vulnerability(vuln)
            severity = vuln.get("severity", "info").lower()

            mapping_entry = {
                "vulnerability": vuln,
                "controls": vuln_mapping,
                "severity": severity,
            }
            mappings.append(mapping_entry)

            for framework, controls in vuln_mapping.items():
                for control_id in controls:
                    affected_controls[framework].add(control_id)
                    severity_counts[framework][severity] += 1

        # Calculate compliance scores
        scores = {}
        for framework in self.frameworks:
            total_controls = len(self.controls.get(framework, {}))
            affected = len(affected_controls.get(framework, set()))
            if total_controls > 0:
                score = ((total_controls - affected) / total_controls) * 100
                scores[framework] = {
                    "score": round(score, 1),
                    "total_controls": total_controls,
                    "affected_controls": affected,
                    "compliant_controls": total_controls - affected,
                    "severity_breakdown": dict(severity_counts.get(framework, {})),
                }
            else:
                scores[framework] = {
                    "score": 100.0,
                    "total_controls": 0,
                    "affected_controls": 0,
                    "compliant_controls": 0,
                    "severity_breakdown": {},
                }

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "mappings": mappings,
            "framework_scores": scores,
            "affected_controls_by_framework": {
                fw.value: list(controls)
                for fw, controls in affected_controls.items()
            },
        }

    def get_gap_analysis(
        self,
        asset_criticality: str = "medium"
    ) -> List[ComplianceGap]:
        """
        Perform gap analysis based on analyzed vulnerabilities.

        Args:
            asset_criticality: Criticality level of assets ("low", "medium", "high", "critical")

        Returns:
            List of compliance gaps with prioritization
        """
        gaps = []
        criticality_multiplier = {
            "low": 0.5,
            "medium": 1.0,
            "high": 1.5,
            "critical": 2.0,
        }.get(asset_criticality, 1.0)

        for framework in self.frameworks:
            for control_id, control in self.controls.get(framework, {}).items():
                if control.status == ControlStatus.NON_COMPLIANT and control.findings:
                    # Calculate severity based on findings
                    severity_scores = {
                        "critical": 5,
                        "high": 4,
                        "medium": 3,
                        "low": 2,
                        "info": 1,
                    }
                    max_severity_score = max(
                        severity_scores.get(f.get("severity", "info").lower(), 1)
                        for f in control.findings
                    )

                    # Determine severity enum
                    severity_map = {
                        5: Severity.CRITICAL,
                        4: Severity.HIGH,
                        3: Severity.MEDIUM,
                        2: Severity.LOW,
                        1: Severity.INFO,
                    }
                    severity = severity_map.get(max_severity_score, Severity.INFO)

                    # Calculate priority (1-5, 1 being highest)
                    base_priority = 6 - max_severity_score
                    priority = max(1, min(5, int(base_priority / criticality_multiplier)))

                    # Estimate effort
                    finding_count = len(control.findings)
                    if finding_count > 10:
                        effort = "high"
                    elif finding_count > 3:
                        effort = "medium"
                    else:
                        effort = "low"

                    # Business impact description
                    impact_templates = {
                        Severity.CRITICAL: f"Critical security gap in {control.category}. Immediate remediation required to prevent potential breach.",
                        Severity.HIGH: f"Significant security gap in {control.category}. High risk of exploitation or compliance failure.",
                        Severity.MEDIUM: f"Moderate security gap in {control.category}. Should be addressed in near-term remediation cycle.",
                        Severity.LOW: f"Minor security gap in {control.category}. Can be addressed during routine maintenance.",
                        Severity.INFO: f"Informational finding in {control.category}. Consider for security posture improvement.",
                    }

                    gap = ComplianceGap(
                        control=control,
                        vulnerability_ids=[
                            f.get("id", f.get("title", "unknown"))
                            for f in control.findings
                        ],
                        severity=severity,
                        business_impact=impact_templates.get(severity, ""),
                        remediation_priority=priority,
                        estimated_effort=effort,
                    )
                    gaps.append(gap)

        # Sort by priority then severity
        gaps.sort(key=lambda g: (g.remediation_priority, -list(Severity).index(g.severity)))
        self.gaps = gaps
        return gaps

    def get_control_details(
        self,
        framework: ComplianceFramework,
        control_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific control.

        Args:
            framework: The compliance framework
            control_id: The control identifier

        Returns:
            Control details dict or None if not found
        """
        control = self.controls.get(framework, {}).get(control_id)
        if not control:
            return None

        return {
            "control_id": control.control_id,
            "framework": framework.value,
            "title": control.title,
            "description": control.description,
            "category": control.category,
            "subcategory": control.subcategory,
            "status": control.status.value,
            "finding_count": len(control.findings),
            "findings": control.findings[:10],  # Limit to first 10
            "remediation_guidance": control.remediation_guidance,
            "evidence": control.evidence,
        }

    def generate_compliance_report(
        self,
        organization_name: str = "Organization",
        include_details: bool = True
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive compliance report.

        Args:
            organization_name: Name for the report header
            include_details: Whether to include detailed findings

        Returns:
            Complete compliance report dictionary
        """
        report = {
            "report_type": "Compliance Assessment Report",
            "organization": organization_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "frameworks_assessed": [fw.value for fw in self.frameworks],
            "executive_summary": {},
            "framework_details": {},
            "gaps": [],
            "remediation_roadmap": [],
        }

        # Executive summary
        total_controls = sum(
            len(self.controls.get(fw, {})) for fw in self.frameworks
        )
        non_compliant = sum(
            1 for fw in self.frameworks
            for ctrl in self.controls.get(fw, {}).values()
            if ctrl.status == ControlStatus.NON_COMPLIANT
        )

        overall_score = ((total_controls - non_compliant) / total_controls * 100) if total_controls > 0 else 100

        report["executive_summary"] = {
            "overall_compliance_score": round(overall_score, 1),
            "total_controls_assessed": total_controls,
            "non_compliant_controls": non_compliant,
            "compliant_controls": total_controls - non_compliant,
            "risk_level": (
                "Critical" if overall_score < 50 else
                "High" if overall_score < 70 else
                "Medium" if overall_score < 85 else
                "Low"
            ),
        }

        # Framework-specific details
        for framework in self.frameworks:
            fw_controls = self.controls.get(framework, {})
            fw_non_compliant = [
                ctrl for ctrl in fw_controls.values()
                if ctrl.status == ControlStatus.NON_COMPLIANT
            ]

            categories = defaultdict(lambda: {"total": 0, "non_compliant": 0})
            for ctrl in fw_controls.values():
                categories[ctrl.category]["total"] += 1
                if ctrl.status == ControlStatus.NON_COMPLIANT:
                    categories[ctrl.category]["non_compliant"] += 1

            fw_score = (
                (len(fw_controls) - len(fw_non_compliant)) / len(fw_controls) * 100
                if fw_controls else 100
            )

            report["framework_details"][framework.value] = {
                "compliance_score": round(fw_score, 1),
                "total_controls": len(fw_controls),
                "non_compliant_controls": len(fw_non_compliant),
                "category_breakdown": dict(categories),
                "non_compliant_control_ids": [ctrl.control_id for ctrl in fw_non_compliant],
            }

            if include_details:
                report["framework_details"][framework.value]["control_details"] = [
                    self.get_control_details(framework, ctrl.control_id)
                    for ctrl in fw_non_compliant[:20]  # Limit to 20 per framework
                ]

        # Gap analysis
        if self.gaps:
            report["gaps"] = [
                {
                    "control_id": gap.control.control_id,
                    "framework": gap.control.framework.value,
                    "title": gap.control.title,
                    "severity": gap.severity.value,
                    "priority": gap.remediation_priority,
                    "effort": gap.estimated_effort,
                    "business_impact": gap.business_impact,
                    "finding_count": len(gap.vulnerability_ids),
                }
                for gap in self.gaps[:50]  # Limit to top 50 gaps
            ]

        # Remediation roadmap
        priority_groups = defaultdict(list)
        for gap in self.gaps:
            priority_groups[gap.remediation_priority].append(gap)

        phases = [
            "Immediate (0-30 days)",
            "Short-term (30-60 days)",
            "Medium-term (60-90 days)",
            "Long-term (90-180 days)",
            "Strategic (180+ days)",
        ]

        for priority in range(1, 6):
            phase_gaps = priority_groups.get(priority, [])
            if phase_gaps:
                report["remediation_roadmap"].append({
                    "phase": phases[priority - 1],
                    "priority": priority,
                    "items": [
                        {
                            "control": gap.control.control_id,
                            "framework": gap.control.framework.value,
                            "title": gap.control.title,
                            "effort": gap.estimated_effort,
                        }
                        for gap in phase_gaps[:10]  # Limit per phase
                    ],
                    "total_items": len(phase_gaps),
                })

        return report


# =============================================================================
# Convenience Functions
# =============================================================================

def analyze_compliance(
    vulnerabilities: List[Dict[str, Any]],
    frameworks: List[str] = None,
    asset_criticality: str = "medium"
) -> Dict[str, Any]:
    """
    Analyze vulnerabilities against compliance frameworks.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        frameworks: List of framework names (iso_27001, soc2, nist_csf, pci_dss)
        asset_criticality: Asset criticality level

    Returns:
        Complete compliance analysis results
    """
    # Parse framework names
    if frameworks:
        fw_list = []
        for fw_name in frameworks:
            try:
                fw_list.append(ComplianceFramework(fw_name.lower()))
            except ValueError:
                logger.warning(f"Unknown framework: {fw_name}")
        frameworks = fw_list if fw_list else None

    analyzer = ComplianceAnalyzer(frameworks)
    analysis = analyzer.analyze_vulnerabilities(vulnerabilities)
    gaps = analyzer.get_gap_analysis(asset_criticality)

    return {
        **analysis,
        "gap_analysis": [
            {
                "control_id": gap.control.control_id,
                "framework": gap.control.framework.value,
                "title": gap.control.title,
                "severity": gap.severity.value,
                "priority": gap.remediation_priority,
                "effort": gap.estimated_effort,
                "business_impact": gap.business_impact,
            }
            for gap in gaps
        ],
    }


def get_compliance_score(
    vulnerabilities: List[Dict[str, Any]],
    framework: str
) -> Dict[str, Any]:
    """
    Get compliance score for a specific framework.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        framework: Framework name (iso_27001, soc2, nist_csf, pci_dss)

    Returns:
        Framework-specific compliance score and details
    """
    try:
        fw = ComplianceFramework(framework.lower())
    except ValueError:
        return {"error": f"Unknown framework: {framework}"}

    analyzer = ComplianceAnalyzer([fw])
    analysis = analyzer.analyze_vulnerabilities(vulnerabilities)

    return {
        "framework": framework,
        "score": analysis["framework_scores"].get(fw, {}).get("score", 100),
        "details": analysis["framework_scores"].get(fw, {}),
        "affected_controls": analysis["affected_controls_by_framework"].get(fw.value, []),
    }


def generate_attestation_data(
    organization: str,
    vulnerabilities: List[Dict[str, Any]],
    frameworks: List[str] = None
) -> Dict[str, Any]:
    """
    Generate data for compliance attestation.

    Args:
        organization: Organization name
        vulnerabilities: List of vulnerability dictionaries
        frameworks: List of framework names

    Returns:
        Attestation-ready compliance data
    """
    # Parse frameworks
    if frameworks:
        fw_list = []
        for fw_name in frameworks:
            try:
                fw_list.append(ComplianceFramework(fw_name.lower()))
            except ValueError:
                pass
        frameworks = fw_list if fw_list else None

    analyzer = ComplianceAnalyzer(frameworks)
    analyzer.analyze_vulnerabilities(vulnerabilities)
    analyzer.get_gap_analysis()

    report = analyzer.generate_compliance_report(
        organization_name=organization,
        include_details=True
    )

    return report


def map_vulnerability_to_controls(
    vulnerability: Dict[str, Any]
) -> Dict[str, List[str]]:
    """
    Map a single vulnerability to compliance controls.

    Args:
        vulnerability: Vulnerability dictionary

    Returns:
        Dict mapping framework names to control IDs
    """
    analyzer = ComplianceAnalyzer()
    mapping = analyzer.map_vulnerability(vulnerability)

    return {
        fw.value: controls
        for fw, controls in mapping.items()
    }
