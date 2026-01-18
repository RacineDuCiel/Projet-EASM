"""
Standardized result types for tool execution.
Provides consistent error handling and status reporting across all tools.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Generic, List, Optional, TypeVar
from enum import Enum
from datetime import datetime


class ResultStatus(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    ERROR = "error"
    INVALID_INPUT = "invalid_input"
    TOOL_MISSING = "tool_missing"


class ErrorCategory(Enum):
    CRITICAL = "critical"
    BUSINESS = "business"
    NETWORK = "network"
    SYSTEM = "system"
    VALIDATION = "validation"


T = TypeVar('T')


@dataclass
class ErrorDetail:
    category: ErrorCategory
    message: str
    code: Optional[str] = None
    original_exception: Optional[str] = None
    recoverable: bool = True


@dataclass
class ToolResult(Generic[T]):
    status: ResultStatus
    data: T
    error: Optional[ErrorDetail] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        return self.status in (ResultStatus.SUCCESS, ResultStatus.PARTIAL)
    
    @property
    def is_critical_error(self) -> bool:
        return (
            self.error is not None and 
            self.error.category == ErrorCategory.CRITICAL
        )
    
    def get_data_or_default(self, default: T) -> T:
        return self.data if self.is_success else default
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "status": self.status.value,
            "data": self.data,
        }
        if self.error:
            result["error"] = {
                "category": self.error.category.value,
                "message": self.error.message,
                "code": self.error.code,
                "recoverable": self.error.recoverable
            }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class SubdomainResult:
    subdomains: List[str]
    source: str
    count: int
    duration_ms: Optional[int] = None
    error: Optional[str] = None


@dataclass
class PortScanResult:
    host: str
    ports: List[Dict[str, Any]]
    count: int
    duration_ms: Optional[int] = None
    error: Optional[str] = None


@dataclass
class TechnologyResult:
    target: str
    technologies: List[str]
    web_server: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    tls_version: Optional[str] = None
    waf_detected: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VulnerabilityFinding:
    title: str
    severity: str
    description: Optional[str] = None
    matched: Optional[str] = None
    template_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class DNSRecordResult:
    records: Dict[str, List[Dict[str, Any]]]
    count: int
    duration_ms: Optional[int] = None


@dataclass
class CertificateResult:
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    subject_alt_names: List[str] = field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool = False
    is_self_signed: bool = False
    fingerprint_sha256: Optional[str] = None
    error: Optional[str] = None


def success_result(data: T, metadata: Dict[str, Any] = None) -> ToolResult[T]:
    return ToolResult(
        status=ResultStatus.SUCCESS,
        data=data,
        metadata=metadata or {}
    )


def partial_result(data: T, error: ErrorDetail, metadata: Dict[str, Any] = None) -> ToolResult[T]:
    return ToolResult(
        status=ResultStatus.PARTIAL,
        data=data,
        error=error,
        metadata=metadata or {}
    )


def timeout_result(message: str, data: T = None, recoverable: bool = True) -> ToolResult[T]:
    return ToolResult(
        status=ResultStatus.TIMEOUT,
        data=data if data is not None else [],
        error=ErrorDetail(
            category=ErrorCategory.NETWORK,
            message=message,
            code="TIMEOUT",
            recoverable=recoverable
        )
    )


def error_result(
    message: str,
    category: ErrorCategory = ErrorCategory.SYSTEM,
    code: str = None,
    original_exception: str = None,
    recoverable: bool = True,
    data: T = None
) -> ToolResult[T]:
    return ToolResult(
        status=ResultStatus.ERROR,
        data=data if data is not None else [],
        error=ErrorDetail(
            category=category,
            message=message,
            code=code,
            original_exception=original_exception,
            recoverable=recoverable
        )
    )


def tool_missing_result(tool_name: str) -> ToolResult[List[str]]:
    return ToolResult(
        status=ResultStatus.TOOL_MISSING,
        data=[],
        error=ErrorDetail(
            category=ErrorCategory.CRITICAL,
            message=f"Tool '{tool_name}' not found in PATH",
            code="TOOL_MISSING",
            recoverable=False
        ),
        metadata={"tool_name": tool_name}
    )


def invalid_input_result(message: str, input_value: str) -> ToolResult[List[str]]:
    return ToolResult(
        status=ResultStatus.INVALID_INPUT,
        data=[],
        error=ErrorDetail(
            category=ErrorCategory.VALIDATION,
            message=message,
            code="INVALID_INPUT",
            recoverable=False
        ),
        metadata={"input_value": input_value}
    )


def not_found_result(message: str, data: T = None) -> ToolResult[T]:
    return ToolResult(
        status=ResultStatus.NOT_FOUND,
        data=data if data is not None else [],
        error=ErrorDetail(
            category=ErrorCategory.BUSINESS,
            message=message,
            code="NOT_FOUND",
            recoverable=True
        )
    )
