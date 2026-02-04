"""
Custom exceptions for structured error handling in the EASM Platform.

These exceptions provide consistent error codes and messages across the application,
making debugging and logging more effective.
"""
from typing import Optional, Any
from fastapi import HTTPException, status


class EASMBaseException(Exception):
    """
    Base exception for all EASM application errors.
    
    Provides a consistent structure with error code and message.
    """
    
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    
    def __init__(
        self, 
        message: str, 
        code: str = "EASM_ERROR",
        details: Optional[dict[str, Any]] = None
    ) -> None:
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"
    
    def to_http_exception(self) -> HTTPException:
        """Convert to FastAPI HTTPException for API responses."""
        content = {"detail": self.message, "code": self.code}
        if self.details:
            content["details"] = self.details
        return HTTPException(status_code=self.status_code, detail=content)


class ScanNotFoundError(EASMBaseException):
    """Raised when a scan cannot be found in the database."""
    status_code = status.HTTP_404_NOT_FOUND
    
    def __init__(self, scan_id: str) -> None:
        super().__init__(
            message=f"Scan with ID '{scan_id}' not found",
            code="SCAN_NOT_FOUND",
            details={"scan_id": scan_id}
        )
        self.scan_id = scan_id


class ScopeNotFoundError(EASMBaseException):
    """Raised when a scope cannot be found in the database."""
    status_code = status.HTTP_404_NOT_FOUND
    
    def __init__(self, scope_id: str) -> None:
        super().__init__(
            message=f"Scope with ID '{scope_id}' not found",
            code="SCOPE_NOT_FOUND",
            details={"scope_id": scope_id}
        )
        self.scope_id = scope_id


class ProgramNotFoundError(EASMBaseException):
    """Raised when a program cannot be found in the database."""
    status_code = status.HTTP_404_NOT_FOUND
    
    def __init__(self, program_id: str) -> None:
        super().__init__(
            message=f"Program with ID '{program_id}' not found",
            code="PROGRAM_NOT_FOUND",
            details={"program_id": program_id}
        )
        self.program_id = program_id


class AssetNotFoundError(EASMBaseException):
    """Raised when an asset cannot be found in the database."""
    status_code = status.HTTP_404_NOT_FOUND
    
    def __init__(self, asset_id: str) -> None:
        super().__init__(
            message=f"Asset with ID '{asset_id}' not found",
            code="ASSET_NOT_FOUND",
            details={"asset_id": asset_id}
        )
        self.asset_id = asset_id


class ValidationError(EASMBaseException):
    """Raised for input validation failures."""
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def __init__(self, message: str, field: Optional[str] = None) -> None:
        code = f"VALIDATION_ERROR_{field.upper()}" if field else "VALIDATION_ERROR"
        details = {"field": field} if field else None
        super().__init__(message=message, code=code, details=details)
        self.field = field


class ToolExecutionError(EASMBaseException):
    """Raised when an external tool (Subfinder, Naabu, Nuclei) fails."""
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    
    def __init__(
        self, 
        tool_name: str, 
        message: str, 
        target: Optional[str] = None,
        exit_code: Optional[int] = None
    ) -> None:
        details: dict[str, Any] = {"tool": tool_name}
        if target:
            details["target"] = target
        if exit_code is not None:
            details["exit_code"] = exit_code
            
        super().__init__(
            message=f"{tool_name} failed: {message}",
            code=f"TOOL_{tool_name.upper()}_ERROR",
            details=details
        )
        self.tool_name = tool_name
        self.target = target
        self.exit_code = exit_code


class ToolTimeoutError(ToolExecutionError):
    """Raised when an external tool times out."""
    status_code = status.HTTP_504_GATEWAY_TIMEOUT
    
    def __init__(self, tool_name: str, timeout_seconds: int, target: Optional[str] = None) -> None:
        super().__init__(
            tool_name=tool_name,
            message=f"Timed out after {timeout_seconds}s",
            target=target
        )
        self.code = f"TOOL_{tool_name.upper()}_TIMEOUT"
        self.timeout_seconds = timeout_seconds


class ScanAlreadyRunningError(EASMBaseException):
    """Raised when attempting to start a scan that is already running."""
    status_code = status.HTTP_409_CONFLICT
    
    def __init__(self, scan_id: str) -> None:
        super().__init__(
            message=f"Scan '{scan_id}' is already running",
            code="SCAN_ALREADY_RUNNING",
            details={"scan_id": scan_id}
        )
        self.scan_id = scan_id


class AuthenticationError(EASMBaseException):
    """Raised for authentication failures."""
    status_code = status.HTTP_401_UNAUTHORIZED
    
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message=message, code="AUTH_ERROR")


class AuthorizationError(EASMBaseException):
    """Raised when a user lacks permission for an action."""
    status_code = status.HTTP_403_FORBIDDEN
    
    def __init__(self, action: str, resource: Optional[str] = None) -> None:
        msg = f"Permission denied for action: {action}"
        details: dict[str, Any] = {"action": action}
        if resource:
            msg += f" on resource: {resource}"
            details["resource"] = resource
        super().__init__(message=msg, code="AUTHZ_ERROR", details=details)
        self.action = action
        self.resource = resource


class DatabaseError(EASMBaseException):
    """Raised for database operation failures."""
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    
    def __init__(self, message: str = "Database operation failed", operation: Optional[str] = None) -> None:
        details = {"operation": operation} if operation else None
        super().__init__(message=message, code="DB_ERROR", details=details)
        self.operation = operation


class CircuitBreakerOpenError(EASMBaseException):
    """Raised when a circuit breaker is open (service unavailable)."""
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    
    def __init__(self, service_name: str, retry_after: Optional[int] = None) -> None:
        details: dict[str, Any] = {"service": service_name}
        if retry_after:
            details["retry_after_seconds"] = retry_after
            
        super().__init__(
            message=f"Service '{service_name}' is temporarily unavailable. Please try again later.",
            code="CIRCUIT_BREAKER_OPEN",
            details=details
        )
        self.service_name = service_name
        self.retry_after = retry_after


class ExternalAPIError(EASMBaseException):
    """Raised when an external API call fails (e.g., Shodan, Censys)."""
    status_code = status.HTTP_502_BAD_GATEWAY
    
    def __init__(
        self, 
        api_name: str, 
        message: str, 
        status_code: Optional[int] = None
    ) -> None:
        details: dict[str, Any] = {"api": api_name}
        if status_code:
            details["http_status"] = status_code
            
        super().__init__(
            message=f"External API '{api_name}' error: {message}",
            code=f"EXTERNAL_API_{api_name.upper()}_ERROR",
            details=details
        )
        self.api_name = api_name
        self.http_status = status_code


class RateLimitExceededError(EASMBaseException):
    """Raised when rate limit is exceeded for external APIs."""
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    
    def __init__(self, service_name: str, retry_after: Optional[int] = None) -> None:
        details: dict[str, Any] = {"service": service_name}
        if retry_after:
            details["retry_after_seconds"] = retry_after
            
        super().__init__(
            message=f"Rate limit exceeded for '{service_name}'",
            code="RATE_LIMIT_EXCEEDED",
            details=details
        )
        self.service_name = service_name
        self.retry_after = retry_after
