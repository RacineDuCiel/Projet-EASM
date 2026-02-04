"""
Circuit Breaker pattern implementation for external service resilience.

Provides fault tolerance for external API calls (Shodan, Censys, etc.)
by preventing cascading failures when services are down or slow.
"""
import time
import threading
from enum import Enum
from typing import Callable, Optional, TypeVar, Any
from functools import wraps
from src.core.exceptions import CircuitBreakerOpenError

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit Breaker implementation for external service calls.
    
    Automatically opens when failures exceed threshold, preventing
    cascading failures and giving services time to recover.
    
    Usage:
        breaker = CircuitBreaker("shodan", fail_max=5, reset_timeout=60)
        
        @breaker
        def query_shodan(ip: str) -> dict:
            # API call here
            pass
    """
    
    def __init__(
        self,
        service_name: str,
        fail_max: int = 5,
        reset_timeout: int = 60,
        expected_exception: type[Exception] = Exception
    ):
        """
        Initialize circuit breaker.
        
        Args:
            service_name: Name of the service being protected
            fail_max: Number of failures before opening circuit
            reset_timeout: Seconds to wait before attempting reset
            expected_exception: Exception type that counts as failure
        """
        self.service_name = service_name
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.expected_exception = expected_exception
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.RLock()
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            return self._state
    
    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        with self._lock:
            return self._failure_count
    
    def _can_attempt_reset(self) -> bool:
        """Check if enough time has passed to try reset."""
        if self._last_failure_time is None:
            return True
        return time.time() - self._last_failure_time >= self.reset_timeout
    
    def _on_success(self) -> None:
        """Handle successful call."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                # Service recovered
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._last_failure_time = None
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0
    
    def _on_failure(self) -> None:
        """Handle failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                # Failed in half-open, go back to open
                self._state = CircuitState.OPEN
            elif self._state == CircuitState.CLOSED and self._failure_count >= self.fail_max:
                # Too many failures, open circuit
                self._state = CircuitState.OPEN
    
    def _should_allow_call(self) -> bool:
        """Determine if call should be allowed."""
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            
            if self._state == CircuitState.OPEN:
                if self._can_attempt_reset():
                    # Try to close circuit
                    self._state = CircuitState.HALF_OPEN
                    return True
                else:
                    # Still open
                    return False
            
            # HALF_OPEN: allow one test call
            return True
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator for circuit breaker protection."""
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            if not self._should_allow_call():
                raise CircuitBreakerOpenError(
                    service_name=self.service_name,
                    retry_after=self.reset_timeout
                )
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except self.expected_exception:
                self._on_failure()
                raise
        
        return wrapper
    
    async def call_async(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Async version for circuit breaker protection.
        
        Usage:
            result = await breaker.call_async(query_shodan, ip)
        """
        if not self._should_allow_call():
            raise CircuitBreakerOpenError(
                service_name=self.service_name,
                retry_after=self.reset_timeout
            )
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception:
            self._on_failure()
            raise


import asyncio


# Pre-configured circuit breakers for common external services
shodan_breaker = CircuitBreaker(
    service_name="shodan",
    fail_max=3,
    reset_timeout=120,
    expected_exception=Exception
)

censys_breaker = CircuitBreaker(
    service_name="censys",
    fail_max=3,
    reset_timeout=120,
    expected_exception=Exception
)

securitytrails_breaker = CircuitBreaker(
    service_name="securitytrails",
    fail_max=3,
    reset_timeout=120,
    expected_exception=Exception
)

virustotal_breaker = CircuitBreaker(
    service_name="virustotal",
    fail_max=3,
    reset_timeout=120,
    expected_exception=Exception
)

whois_breaker = CircuitBreaker(
    service_name="whois",
    fail_max=5,
    reset_timeout=60,
    expected_exception=Exception
)
