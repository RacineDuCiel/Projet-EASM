import subprocess
import json
import os
import shutil
import logging
import socket
from typing import List, Dict, Any, Generator

logger = logging.getLogger(__name__)

def check_tool(tool_name: str) -> bool:
    """Check if a tool is installed and available in PATH."""
    return shutil.which(tool_name) is not None

def run_subfinder(domain: str) -> List[str]:
    """
    Runs subfinder to discover subdomains.
    Returns a list of unique subdomains found.
    """
    if not check_tool("subfinder"):
        logger.error("Subfinder not found in PATH")
        return []

    logger.info(f"Running Subfinder on {domain}...")
    try:
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
        return list(set(subdomains))
    except subprocess.TimeoutExpired:
        logger.error(f"Subfinder timed out on {domain}")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Subfinder failed on {domain}: {e.stderr}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error running Subfinder on {domain}: {e}")
        return []

def run_naabu(host: str, ports: str = None, rate_limit: str = None) -> List[Dict[str, Any]]:
    """
    Runs naabu to scan ports on a host.
    Returns a list of open ports with metadata.

    Args:
        host: Target hostname or IP
        ports: Comma-separated ports or ranges (e.g., "80,443,8000-8010")
        rate_limit: Scan rate limit
    """
    if not check_tool("naabu"):
        logger.error("Naabu not found in PATH")
        return []

    logger.info(f"Running Naabu on {host}...")

    try:
        ip_address = socket.gethostbyname(host)
        logger.info(f"Resolved {host} to {ip_address}")
    except socket.gaierror as e:
        logger.error(f"Failed to resolve hostname {host}: {e}")
        return []

    try:
        # Use provided params or fall back to env vars
        ports = ports or os.getenv("NAABU_PORTS", "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090")
        rate_limit = rate_limit or os.getenv("NAABU_RATE_LIMIT", "1000")

        cmd = ["naabu", "-host", ip_address, "-json", "-p", ports, "-rate", rate_limit, "-silent"]
        logger.debug(f"Executing Naabu command: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)

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
        else:
             logger.info(f"Naabu found {len(open_ports)} open ports on {host} ({ip_address})")

        return open_ports
    except subprocess.TimeoutExpired:
        logger.error(f"Naabu timed out on {host}")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Naabu failed on {host}: {e.stderr}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error running Naabu on {host}: {e}")
        return []

def run_nuclei(target: str) -> Generator[Dict[str, Any], None, None]:
    """
    Runs Nuclei to scan for vulnerabilities.
    Yields findings (vulnerabilities) as they are found.
    
    Includes a global timeout protection to prevent indefinite blocking.
    """
    if not check_tool("nuclei"):
        logger.error("Nuclei not found in PATH")
        return

    # Global timeout for entire Nuclei scan (default: 10 minutes)
    NUCLEI_TIMEOUT_TOTAL = int(os.getenv("NUCLEI_TIMEOUT_TOTAL", "600"))
    
    logger.info(f"Running Nuclei on {target} (max {NUCLEI_TIMEOUT_TOTAL}s)...")
    
    rate_limit = os.getenv("NUCLEI_RATE_LIMIT", "150")
    timeout = os.getenv("NUCLEI_TIMEOUT", "5")
    retries = os.getenv("NUCLEI_RETRIES", "1")
    severity = os.getenv("NUCLEI_SEVERITY", "info,low,medium,high,critical")
    
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
    logger.debug(f"Executing Nuclei command: {' '.join(cmd)}")
    
    process = None
    try:
        # Use Popen to stream output
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            bufsize=1
        )
        
        import threading
        import queue
        
        # Queue to collect findings from reader thread
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
                                "status": "open"
                            }
                            findings_queue.put(finding)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                reader_error.append(e)
            finally:
                findings_queue.put(None)  # Signal end of output
        
        # Start reader thread
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()
        
        # Yield findings with timeout protection
        start_time = __import__('time').time()
        while True:
            elapsed = __import__('time').time() - start_time
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
                if finding is None:  # End signal
                    break
                yield finding
            except queue.Empty:
                # Check if process is still running
                if process.poll() is not None:
                    # Process finished, drain remaining queue
                    while True:
                        try:
                            finding = findings_queue.get_nowait()
                            if finding is None:
                                break
                            yield finding
                        except queue.Empty:
                            break
                    break
        
        # Wait for reader thread to complete
        reader_thread.join(timeout=5)
        
        # Check for errors
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

def normalize_severity(severity: str) -> str:
    """Normalizes Nuclei severity to match backend Enum."""
    if not severity:
        return "info"

    severity = severity.lower()
    mapping = {
        "informational": "info",
        "unknown": "info",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical"
    }
    return mapping.get(severity, "info")


def run_httpx(target: str, port: int = None) -> Dict[str, Any]:
    """
    Runs httpx for technology detection on a target.

    Args:
        target: Domain or IP to scan
        port: Optional specific port

    Returns:
        Dictionary with detected technologies and metadata
    """
    if not check_tool("httpx"):
        logger.error("httpx not found in PATH")
        return {"technologies": [], "error": "httpx not installed"}

    # Build target URL
    if port:
        if port == 443:
            url = f"https://{target}:{port}"
        else:
            url = f"http://{target}:{port}"
    else:
        url = target

    logger.info(f"Running httpx tech detection on {url}...")

    try:
        cmd = [
            "httpx",
            "-u", url,
            "-tech-detect",
            "-json",
            "-silent",
            "-timeout", "15",
            "-no-color",
            "-follow-redirects"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if not result.stdout.strip():
            logger.warning(f"httpx returned no output for {url}")
            return {"technologies": [], "target": url}

        # Parse JSON output (httpx outputs one JSON per line)
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                # Extract technology info
                tech_result = {
                    "target": url,
                    "technologies": data.get("tech", []),
                    "web_server": data.get("webserver"),
                    "status_code": data.get("status_code"),
                    "content_length": data.get("content_length"),
                    "response_time": data.get("time"),
                    "tls": data.get("tls", {}),
                    "waf": data.get("waf"),
                    "cdn": data.get("cdn"),
                    "title": data.get("title"),
                }

                logger.info(f"httpx detected {len(tech_result['technologies'])} technologies on {url}")
                return tech_result

            except json.JSONDecodeError:
                continue

        return {"technologies": [], "target": url}

    except subprocess.TimeoutExpired:
        logger.error(f"httpx timed out on {url}")
        return {"technologies": [], "error": "timeout", "target": url}
    except Exception as e:
        logger.error(f"httpx failed on {url}: {e}")
        return {"technologies": [], "error": str(e), "target": url}


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

    Args:
        target: Target URL
        tags: Comma-separated Nuclei template tags (if None, runs all templates)
        severity: Severity filter
        rate_limit: Request rate limit
        timeout: Per-request timeout
        retries: Number of retries
    """
    if not check_tool("nuclei"):
        logger.error("Nuclei not found in PATH")
        return

    # Global timeout for entire Nuclei scan
    NUCLEI_TIMEOUT_TOTAL = int(os.getenv("NUCLEI_TIMEOUT_TOTAL", "600"))

    # Use provided params or fall back to env vars
    severity = severity or os.getenv("NUCLEI_SEVERITY", "info,low,medium,high,critical")
    rate_limit = rate_limit or os.getenv("NUCLEI_RATE_LIMIT", "150")
    timeout = timeout or os.getenv("NUCLEI_TIMEOUT", "5")
    retries = retries or os.getenv("NUCLEI_RETRIES", "1")

    tags_info = f"tags={tags}" if tags else "all templates"
    logger.info(f"Running Nuclei on {target} ({tags_info}, max {NUCLEI_TIMEOUT_TOTAL}s)...")

    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-silent",
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-retries", str(retries)
    ]

    # Add tags filter if specified
    if tags:
        cmd.extend(["-tags", tags])

    logger.debug(f"Executing Nuclei command: {' '.join(cmd)}")

    process = None
    try:
        # Use Popen to stream output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        import threading
        import queue
        import time

        # Queue to collect findings from reader thread
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
                findings_queue.put(None)  # Signal end of output

        # Start reader thread
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()

        # Yield findings with timeout protection
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
                if finding is None:  # End signal
                    break
                yield finding
            except queue.Empty:
                # Check if process is still running
                if process.poll() is not None:
                    # Process finished, drain remaining queue
                    while True:
                        try:
                            finding = findings_queue.get_nowait()
                            if finding is None:
                                break
                            yield finding
                        except queue.Empty:
                            break
                    break

        # Wait for reader thread to complete
        reader_thread.join(timeout=5)

        # Check for errors
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
