"""
Custom exceptions for structured error handling in the EASM Platform.

These exceptions provide consistent error codes and messages across the application,
making debugging and logging more effective.
"""
from typing import Optional


class EASMBaseException(Exception):
    """
    Base exception for all EASM application errors.
    
    Provides a consistent structure with error code and message.
    """
    
    def __init__(self, message: str, code: str = "EASM_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(self.message)
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"


class ScanNotFoundError(EASMBaseException):
    """Raised when a scan cannot be found in the database."""
    
    def __init__(self, scan_id: str) -> None:
        super().__init__(
            message=f"Scan with ID '{scan_id}' not found",
            code="SCAN_NOT_FOUND"
        )
        self.scan_id = scan_id


class ScopeNotFoundError(EASMBaseException):
    """Raised when a scope cannot be found in the database."""
    
    def __init__(self, scope_id: str) -> None:
        super().__init__(
            message=f"Scope with ID '{scope_id}' not found",
            code="SCOPE_NOT_FOUND"
        )
        self.scope_id = scope_id


class ProgramNotFoundError(EASMBaseException):
    """Raised when a program cannot be found in the database."""
    
    def __init__(self, program_id: str) -> None:
        super().__init__(
            message=f"Program with ID '{program_id}' not found",
            code="PROGRAM_NOT_FOUND"
        )
        self.program_id = program_id


class AssetNotFoundError(EASMBaseException):
    """Raised when an asset cannot be found in the database."""
    
    def __init__(self, asset_id: str) -> None:
        super().__init__(
            message=f"Asset with ID '{asset_id}' not found",
            code="ASSET_NOT_FOUND"
        )
        self.asset_id = asset_id


class ValidationError(EASMBaseException):
    """Raised for input validation failures."""
    
    def __init__(self, message: str, field: Optional[str] = None) -> None:
        code = f"VALIDATION_ERROR_{field.upper()}" if field else "VALIDATION_ERROR"
        super().__init__(message=message, code=code)
        self.field = field


class ToolExecutionError(EASMBaseException):
    """Raised when an external tool (Subfinder, Naabu, Nuclei) fails."""
    
    def __init__(self, tool_name: str, message: str, target: Optional[str] = None) -> None:
        super().__init__(
            message=f"{tool_name} failed: {message}" + (f" (target: {target})" if target else ""),
            code=f"TOOL_{tool_name.upper()}_ERROR"
        )
        self.tool_name = tool_name
        self.target = target


class ToolTimeoutError(ToolExecutionError):
    """Raised when an external tool times out."""
    
    def __init__(self, tool_name: str, timeout_seconds: int, target: Optional[str] = None) -> None:
        super().__init__(
            tool_name=tool_name,
            message=f"Timed out after {timeout_seconds}s",
            target=target
        )
        self.timeout_seconds = timeout_seconds


class ScanAlreadyRunningError(EASMBaseException):
    """Raised when attempting to start a scan that is already running."""
    
    def __init__(self, scan_id: str) -> None:
        super().__init__(
            message=f"Scan '{scan_id}' is already running",
            code="SCAN_ALREADY_RUNNING"
        )
        self.scan_id = scan_id


class AuthenticationError(EASMBaseException):
    """Raised for authentication failures."""
    
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message=message, code="AUTH_ERROR")


class AuthorizationError(EASMBaseException):
    """Raised when a user lacks permission for an action."""
    
    def __init__(self, action: str, resource: Optional[str] = None) -> None:
        msg = f"Permission denied for action: {action}"
        if resource:
            msg += f" on resource: {resource}"
        super().__init__(message=msg, code="AUTHZ_ERROR")
        self.action = action
        self.resource = resource
