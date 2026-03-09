"""
Port scanning tools: naabu.
"""
import subprocess
import json
import socket
import time
import logging

from src.validation import validate_input, InputType
from src.result import (
    ToolResult, PortScanResult, ErrorCategory,
    success_result, error_result, timeout_result,
    tool_missing_result, invalid_input_result, not_found_result,
)
from .common import check_tool, DEFAULT_SCAN_PORTS, DEFAULT_NAABU_RATE_LIMIT

logger = logging.getLogger(__name__)


def run_naabu(host: str, ports: str = None, rate_limit: str = None) -> ToolResult[PortScanResult]:
    """
    Runs naabu to scan ports on a host.
    Returns a ToolResult with PortScanResult containing open ports metadata.

    Args:
        host: Target hostname or IP
        ports: Comma-separated ports or ranges (e.g., "80,443,8000-8010")
        rate_limit: Scan rate limit
    """
    if not check_tool("naabu"):
        return tool_missing_result("naabu")

    validation = validate_input(host, InputType.DOMAIN)
    if not validation.is_valid:
        validation = validate_input(host, InputType.IP)
        if not validation.is_valid:
            return invalid_input_result(
                validation.error_message or "Invalid host",
                host
            )

    host = validation.sanitized_value
    start_time = time.time()

    logger.info(f"Running Naabu on {host}...")

    try:
        ip_address = socket.gethostbyname(host)
        logger.info(f"Resolved {host} to {ip_address}")
    except socket.gaierror as e:
        logger.error(f"Failed to resolve hostname {host}: {e}")
        return error_result(
            f"Failed to resolve hostname: {str(e)}",
            ErrorCategory.BUSINESS,
            "DNS_RESOLUTION_FAILED",
            str(e)
        )

    try:
        ports = ports or DEFAULT_SCAN_PORTS
        rate_limit = rate_limit or DEFAULT_NAABU_RATE_LIMIT

        cmd = ["naabu", "-host", ip_address, "-json", "-p", ports, "-rate", rate_limit, "-silent"]
        logger.debug(f"Executing Naabu command: [REDACTED]")

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        duration_ms = int((time.time() - start_time) * 1000)

        open_ports = []
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                open_ports.append({
                    "port": data.get("port"),
                    "protocol": data.get("protocol", "tcp"),
                    "service_name": "unknown"
                })
            except json.JSONDecodeError:
                pass

        if not open_ports:
             logger.warning(f"Naabu completed but found NO open ports on {host} ({ip_address})")
             return not_found_result(
                 "No open ports found",
                 PortScanResult(host=host, ports=[], count=0, duration_ms=duration_ms)
             )

        logger.info(f"Naabu found {len(open_ports)} open ports on {host} ({ip_address})")

        return success_result(
            PortScanResult(
                host=host,
                ports=open_ports,
                count=len(open_ports),
                duration_ms=duration_ms
            )
        )

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Naabu timed out on {host}")
        return timeout_result(
            "Naabu timed out after 300s",
            PortScanResult(host=host, ports=[], count=0, duration_ms=duration_ms)
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"Naabu failed on {host}: {e.stderr}")
        return error_result(
            f"Naabu failed: {e.stderr}",
            ErrorCategory.SYSTEM,
            "NAABU_ERROR",
            str(e)
        )

    except Exception as e:
        logger.error(f"Unexpected error running Naabu on {host}: {e}")
        return error_result(
            f"Unexpected error: {str(e)}",
            ErrorCategory.CRITICAL,
            "UNEXPECTED_ERROR",
            str(e)
        )
