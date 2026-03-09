"""
Subdomain enumeration tools: subfinder, amass, findomain, assetfinder.
"""
import subprocess
import time
import logging
from typing import Dict, Any

from src.validation import validate_input, InputType
from src.result import (
    ToolResult, SubdomainResult, ErrorCategory,
    success_result, error_result, timeout_result,
    tool_missing_result, invalid_input_result,
)
from .common import check_tool

logger = logging.getLogger(__name__)


def run_subfinder(domain: str, timeout: int = 120) -> ToolResult[SubdomainResult]:
    """
    Runs subfinder to discover subdomains.
    Returns a ToolResult with SubdomainResult containing unique subdomains found.
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("subfinder"):
        return tool_missing_result("subfinder")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Subfinder on {domain}...")

    try:
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Subfinder found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="subfinder",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Subfinder timed out on {domain}")
        return timeout_result(
            f"Subfinder timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="subfinder", count=0, duration_ms=duration_ms)
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"Subfinder failed on {domain}: {e.stderr}")
        return error_result(
            f"Subfinder failed: {e.stderr}",
            ErrorCategory.SYSTEM,
            "SUBFINDER_ERROR",
            str(e)
        )

    except Exception as e:
        logger.error(f"Unexpected error running Subfinder on {domain}: {e}")
        return error_result(
            f"Unexpected error: {str(e)}",
            ErrorCategory.CRITICAL,
            "UNEXPECTED_ERROR",
            str(e)
        )


def run_amass(domain: str, timeout: int = 300, passive_only: bool = True) -> ToolResult[SubdomainResult]:
    """
    Runs Amass for subdomain enumeration.
    More comprehensive than Subfinder but slower.

    Args:
        domain: Target domain
        timeout: Maximum execution time in seconds
        passive_only: If True, only use passive sources (faster, no DNS bruteforce)

    Returns:
        ToolResult with SubdomainResult containing unique subdomains found
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("amass"):
        logger.warning("Amass not found in PATH, skipping")
        return tool_missing_result("amass")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Amass on {domain} (passive={passive_only})...")

    try:
        cmd = ["amass", "enum", "-d", domain, "-silent"]
        if passive_only:
            cmd.append("-passive")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Amass found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="amass",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Amass timed out on {domain} after {timeout}s")
        return timeout_result(
            f"Amass timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="amass", count=0, duration_ms=duration_ms)
        )

    except Exception as e:
        logger.error(f"Amass failed on {domain}: {e}")
        return error_result(
            f"Amass failed: {str(e)}",
            ErrorCategory.SYSTEM,
            "AMASS_ERROR",
            str(e)
        )


def run_findomain(domain: str, timeout: int = 120) -> ToolResult[SubdomainResult]:
    """
    Runs Findomain for fast subdomain enumeration.
    Very fast tool that aggregates multiple sources.

    Args:
        domain: Target domain
        timeout: Maximum execution time in seconds

    Returns:
        ToolResult with SubdomainResult containing unique subdomains found
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("findomain"):
        logger.warning("Findomain not found in PATH, skipping")
        return tool_missing_result("findomain")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Findomain on {domain}...")

    try:
        cmd = ["findomain", "-t", domain, "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Findomain found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="findomain",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Findomain timed out on {domain}")
        return timeout_result(
            f"Findomain timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="findomain", count=0, duration_ms=duration_ms)
        )

    except Exception as e:
        logger.error(f"Findomain failed on {domain}: {e}")
        return error_result(
            f"Findomain failed: {str(e)}",
            ErrorCategory.SYSTEM,
            "FINDOMAIN_ERROR",
            str(e)
        )


def run_assetfinder(domain: str, timeout: int = 60) -> ToolResult[SubdomainResult]:
    """
    Runs assetfinder for subdomain enumeration.
    Fast and lightweight tool.

    Args:
        domain: Target domain
        timeout: Maximum execution time in seconds

    Returns:
        ToolResult with SubdomainResult containing unique subdomains found
    """
    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        return invalid_input_result(
            validation.error_message or "Invalid domain",
            domain
        )

    if not check_tool("assetfinder"):
        logger.warning("Assetfinder not found in PATH, skipping")
        return tool_missing_result("assetfinder")

    domain = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Assetfinder on {domain}...")

    try:
        cmd = ["assetfinder", "--subs-only", domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration_ms = int((time.time() - start_time) * 1000)

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        subdomains = [s for s in subdomains if s.endswith(f".{domain}") or s == domain]
        unique_subdomains = list(set(subdomains))

        logger.info(f"Assetfinder found {len(unique_subdomains)} subdomains for {domain}")

        return success_result(
            SubdomainResult(
                subdomains=unique_subdomains,
                source="assetfinder",
                count=len(unique_subdomains),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.warning(f"Assetfinder timed out on {domain}")
        return timeout_result(
            f"Assetfinder timed out after {timeout}s",
            SubdomainResult(subdomains=[], source="assetfinder", count=0, duration_ms=duration_ms)
        )

    except Exception as e:
        logger.error(f"Assetfinder failed on {domain}: {e}")
        return error_result(
            f"Assetfinder failed: {str(e)}",
            ErrorCategory.SYSTEM,
            "ASSETFINDER_ERROR",
            str(e)
        )


def aggregate_subdomain_discovery(
    domain: str,
    use_amass: bool = False,
    use_findomain: bool = True,
    use_assetfinder: bool = True,
    parallel: bool = True
) -> Dict[str, Any]:
    """
    Aggregate results from multiple subdomain enumeration tools.
    Runs tools in parallel for faster results.

    Args:
        domain: Target domain
        use_amass: Include Amass (slower but more comprehensive)
        use_findomain: Include Findomain
        use_assetfinder: Include Assetfinder
        parallel: Run tools in parallel

    Returns:
        Dictionary with aggregated results and per-tool breakdown
    """
    import concurrent.futures
    from src.result import ToolResult

    validation = validate_input(domain, InputType.DOMAIN)
    if not validation.is_valid:
        logger.error(f"Invalid domain for aggregation: {domain}")
        return {
            "domain": domain,
            "subdomains": [],
            "sources": {},
            "total_unique": 0,
            "error": validation.error_message
        }

    domain = validation.sanitized_value
    logger.info(f"Starting aggregated subdomain discovery for {domain}")

    results = {
        "domain": domain,
        "subdomains": set(),
        "sources": {},
        "total_unique": 0,
    }

    def run_tool_wrapper(tool_info):
        name, func = tool_info
        try:
            result = func(domain)
            if isinstance(result, ToolResult):
                if result.is_success:
                    return name, result.data.subdomains, None
                else:
                    return name, [], result.error.message if result.error else "Unknown error"
            else:
                return name, result, None
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return name, [], str(e)

    tools_to_run = [("subfinder", run_subfinder)]

    if use_findomain:
        tools_to_run.append(("findomain", run_findomain))
    if use_assetfinder:
        tools_to_run.append(("assetfinder", run_assetfinder))
    if use_amass:
        tools_to_run.append(("amass", lambda d: run_amass(d, passive_only=True)))

    if parallel and len(tools_to_run) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(run_tool_wrapper, t) for t in tools_to_run]
            for future in concurrent.futures.as_completed(futures):
                name, subs, error = future.result()
                if error:
                    results["sources"][name] = {"count": 0, "error": error}
                else:
                    results["sources"][name] = {"count": len(subs)}
                    results["subdomains"].update(subs)
    else:
        for tool_info in tools_to_run:
            name, subs, error = run_tool_wrapper(tool_info)
            if error:
                results["sources"][name] = {"count": 0, "error": error}
            else:
                results["sources"][name] = {"count": len(subs)}
                results["subdomains"].update(subs)

    results["subdomains"] = list(results["subdomains"])
    results["total_unique"] = len(results["subdomains"])

    logger.info(
        f"Aggregated discovery for {domain}: {results['total_unique']} unique subdomains "
        f"from {len(results['sources'])} sources"
    )

    return results
