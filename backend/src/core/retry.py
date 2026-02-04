"""
Retry logic and resilience utilities for external tool execution.

Provides configurable retry policies with exponential backoff for
external tools and API calls.
"""
from typing import Callable, TypeVar, Any, Optional
from functools import wraps
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RetryConfig:
    """Configuration for retry behavior."""
    
    def __init__(
        self,
        max_attempts: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 10.0,
        exponential_base: float = 2.0,
        exceptions: tuple[type[Exception], ...] = (Exception,)
    ):
        """
        Configure retry behavior.
        
        Args:
            max_attempts: Maximum number of retry attempts
            initial_delay: Initial delay between retries (seconds)
            max_delay: Maximum delay between retries (seconds)
            exponential_base: Base for exponential backoff
            exceptions: Tuple of exception types to catch and retry
        """
        self.max_attempts = max_attempts
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.exceptions = exceptions
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt using exponential backoff."""
        import time
        delay = self.initial_delay * (self.exponential_base ** (attempt - 1))
        return min(delay, self.max_delay)


def with_retry(config: Optional[RetryConfig] = None):
    """
    Decorator that adds retry logic with exponential backoff.
    
    Usage:
        @with_retry(RetryConfig(max_attempts=3, initial_delay=1.0))
        def run_subfinder(domain: str) -> list:
            # Tool execution here
            pass
    
    Args:
        config: RetryConfig instance, uses defaults if None
    
    Returns:
        Decorated function with retry logic
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            import time
            
            last_exception: Optional[Exception] = None
            
            for attempt in range(1, config.max_attempts + 1):
                try:
                    result = func(*args, **kwargs)
                    
                    # Log success after retries
                    if attempt > 1:
                        logger.info(
                            f"Function '{func.__name__}' succeeded on attempt {attempt}"
                        )
                    
                    return result
                    
                except config.exceptions as e:
                    last_exception = e
                    
                    if attempt < config.max_attempts:
                        delay = config.calculate_delay(attempt)
                        logger.warning(
                            f"Function '{func.__name__}' failed on attempt {attempt}/{config.max_attempts}. "
                            f"Retrying in {delay:.1f}s... Error: {e}"
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"Function '{func.__name__}' failed after {config.max_attempts} attempts. "
                            f"Last error: {e}"
                        )
            
            # All retries exhausted
            if last_exception:
                raise last_exception
            
            raise RuntimeError("Unexpected error in retry logic")
        
        return wrapper
    
    return decorator


def with_async_retry(config: Optional[RetryConfig] = None):
    """
    Async version of retry decorator.
    
    Usage:
        @with_async_retry(RetryConfig(max_attempts=3))
        async def fetch_data(url: str) -> dict:
            # Async API call here
            pass
    """
    import asyncio
    
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Optional[Exception] = None
            
            for attempt in range(1, config.max_attempts + 1):
                try:
                    result = await func(*args, **kwargs)
                    
                    if attempt > 1:
                        logger.info(
                            f"Async function '{func.__name__}' succeeded on attempt {attempt}"
                        )
                    
                    return result
                    
                except config.exceptions as e:
                    last_exception = e
                    
                    if attempt < config.max_attempts:
                        delay = config.calculate_delay(attempt)
                        logger.warning(
                            f"Async function '{func.__name__}' failed on attempt {attempt}/{config.max_attempts}. "
                            f"Retrying in {delay:.1f}s... Error: {e}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"Async function '{func.__name__}' failed after {config.max_attempts} attempts. "
                            f"Last error: {e}"
                        )
            
            if last_exception:
                raise last_exception
            
            raise RuntimeError("Unexpected error in async retry logic")
        
        return wrapper
    
    return decorator


# Pre-configured retry policies for common use cases

# For network-based tools (Subfinder, etc.)
NETWORK_RETRY = RetryConfig(
    max_attempts=3,
    initial_delay=1.0,
    max_delay=10.0,
    exponential_base=2.0,
    exceptions=(Exception,)
)

# For external APIs (Shodan, Censys)
API_RETRY = RetryConfig(
    max_attempts=3,
    initial_delay=2.0,
    max_delay=30.0,
    exponential_base=2.0,
    exceptions=(Exception,)
)

# For scanning tools (Naabu, Nuclei) - more retries as they can be flaky
SCAN_RETRY = RetryConfig(
    max_attempts=2,  # Don't retry too much as scans are expensive
    initial_delay=5.0,
    max_delay=30.0,
    exponential_base=2.0,
    exceptions=(Exception,)
)

# For database operations
DB_RETRY = RetryConfig(
    max_attempts=3,
    initial_delay=0.5,
    max_delay=5.0,
    exponential_base=2.0,
    exceptions=(Exception,)
)
