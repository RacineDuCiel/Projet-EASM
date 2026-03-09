"""
Vulnerability scanning tools: nuclei.
Includes the unified run_nuclei function and the run_nuclei_with_tags wrapper.
"""
import subprocess
import json
import time
import logging
from typing import List, Dict, Any, Generator

from src.validation import validate_input, InputType
from .common import (
    check_tool, normalize_severity,
    DEFAULT_NUCLEI_TIMEOUT_TOTAL, DEFAULT_NUCLEI_RATE_LIMIT,
    DEFAULT_NUCLEI_TIMEOUT, DEFAULT_NUCLEI_RETRIES, DEFAULT_NUCLEI_SEVERITY,
)

logger = logging.getLogger(__name__)


def run_nuclei(
    target: str,
    tags: str = None,
    severity: str = None,
    rate_limit: str = None,
    timeout: str = None,
    retries: str = None,
    timeout_total: int = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Runs Nuclei to scan for vulnerabilities.
    Unified function replacing run_nuclei and run_nuclei_with_tags.
    Yields findings (vulnerabilities) as they are found.

    Args:
        target: Target URL or hostname
        tags: Comma-separated Nuclei template tags (if None, runs all templates)
        severity: Severity filter
        rate_limit: Request rate limit
        timeout: Per-request timeout
        retries: Number of retries
        timeout_total: Global timeout for entire scan (default: 600s)
    """
    if not check_tool("nuclei"):
        logger.error("Nuclei not found in PATH")
        return

    validation = validate_input(target, InputType.URL)
    if not validation.is_valid:
        validation = validate_input(target, InputType.DOMAIN)
        if not validation.is_valid:
            logger.error(f"Invalid target for Nuclei: {target}")
            return

    target = validation.sanitized_value
    NUCLEI_TIMEOUT_TOTAL = timeout_total or DEFAULT_NUCLEI_TIMEOUT_TOTAL

    logger.info(f"Running Nuclei on {target} (max {NUCLEI_TIMEOUT_TOTAL}s)...")

    severity = severity or DEFAULT_NUCLEI_SEVERITY
    rate_limit = rate_limit or DEFAULT_NUCLEI_RATE_LIMIT
    timeout = timeout or DEFAULT_NUCLEI_TIMEOUT
    retries = retries or DEFAULT_NUCLEI_RETRIES

    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-silent",
        "-severity", severity,
        "-rate-limit", rate_limit,
        "-timeout", timeout,
        "-retries", retries
    ]

    if tags:
        cmd.extend(["-tags", tags])

    logger.debug(f"Executing Nuclei command: [REDACTED]")

    process = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        import threading
        import queue

        findings_queue: queue.Queue = queue.Queue()
        reader_error: List[Exception] = []

        def read_output():
            """Thread function to read Nuclei output."""
            try:
                if process.stdout:
                    for line in process.stdout:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            finding = {
                                "title": data.get("info", {}).get("name"),
                                "severity": normalize_severity(data.get("info", {}).get("severity")),
                                "description": data.get("info", {}).get("description"),
                                "status": "open",
                                "matched": data.get("matched-at", ""),
                                "template_id": data.get("template-id", ""),
                                "tags": data.get("info", {}).get("tags", []),
                            }
                            findings_queue.put(finding)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                reader_error.append(e)
            finally:
                findings_queue.put(None)

        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()

        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            remaining_timeout = max(0.1, NUCLEI_TIMEOUT_TOTAL - elapsed)

            if elapsed >= NUCLEI_TIMEOUT_TOTAL:
                logger.error(f"Nuclei global timeout ({NUCLEI_TIMEOUT_TOTAL}s) reached on {target}")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                break

            try:
                finding = findings_queue.get(timeout=min(1.0, remaining_timeout))
                if finding is None:
                    break
                yield finding
            except queue.Empty:
                if process.poll() is not None:
                    while True:
                        try:
                            finding = findings_queue.get_nowait()
                            if finding is None:
                                break
                            yield finding
                        except queue.Empty:
                            break
                    break

        reader_thread.join(timeout=5)

        if reader_error:
            logger.error(f"Nuclei reader error on {target}: {reader_error[0]}")

        stderr = process.stderr.read() if process.stderr else ""
        if process.returncode and process.returncode != 0 and stderr:
            logger.error(f"Nuclei process error on {target}: {stderr}")

    except Exception as e:
        logger.error(f"Nuclei failed on {target}: {e}")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def run_nuclei_with_tags(
    target: str,
    tags: str = None,
    severity: str = None,
    rate_limit: str = None,
    timeout: str = None,
    retries: str = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Enhanced Nuclei function with tag-based filtering and configurable parameters.
    Now delegates to unified run_nuclei function.

    Args:
        target: Target URL
        tags: Comma-separated Nuclei template tags (if None, runs all templates)
        severity: Severity filter
        rate_limit: Request rate limit
        timeout: Per-request timeout
        retries: Number of retries
    """
    tags_info = f"tags={tags}" if tags else "all templates"
    logger.info(f"Running Nuclei on {target} ({tags_info})...")

    yield from run_nuclei(
        target=target,
        tags=tags,
        severity=severity,
        rate_limit=rate_limit,
        timeout=timeout,
        retries=retries
    )
