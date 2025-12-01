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

def run_naabu(host: str) -> List[Dict[str, Any]]:
    """
    Runs naabu to scan ports on a host.
    Returns a list of open ports with metadata.
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
        ports = os.getenv("NAABU_PORTS", "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090")
        rate_limit = os.getenv("NAABU_RATE_LIMIT", "1000")
        
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
    """
    if not check_tool("nuclei"):
        logger.error("Nuclei not found in PATH")
        return

    logger.info(f"Running Nuclei on {target}...")
    try:
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
        
        # Use Popen to stream output
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1) as process:
            if process.stdout:
                for line in process.stdout:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        finding = {
                            "title": data.get("info", {}).get("name"),
                            "severity": normalize_severity(data.get("info", {}).get("severity")),
                            "description": data.get("info", {}).get("description"),
                            "status": "open"
                        }
                        yield finding
                    except json.JSONDecodeError:
                        pass
            
            # Check for errors after process finishes
            stderr = process.stderr.read() if process.stderr else ""
            if process.returncode != 0 and stderr:
                logger.error(f"Nuclei process error on {target}: {stderr}")

    except Exception as e:
        logger.error(f"Nuclei failed on {target}: {e}")

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
