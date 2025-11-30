import subprocess
import json
import os
import shutil

def run_subfinder(domain: str):
    """
    Runs subfinder to discover subdomains.
    Returns a list of unique subdomains found.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"Running Subfinder on {domain}...")
    try:
        # -silent: only output subdomains
        # -all: use all sources
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

def run_naabu(host: str):
    """
    Runs naabu to scan ports on a host.
    Returns a list of open ports with metadata.
    """
    import logging
    import socket
    logger = logging.getLogger(__name__)
    
    logger.info(f"Running Naabu on {host}...")
    
    # Naabu requires IP address, not hostname
    # Resolve hostname to IP first
    try:
        ip_address = socket.gethostbyname(host)
        logger.info(f"Resolved {host} to {ip_address}")
    except socket.gaierror as e:
        logger.error(f"Failed to resolve hostname {host}: {e}")
        return []
    
    try:
        # Configuration from Env
        ports = os.getenv("NAABU_PORTS", "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090")
        rate_limit = os.getenv("NAABU_RATE_LIMIT", "1000")
        
        # -json: output json
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
                logger.warning(f"Failed to parse Naabu JSON output: {line[:100]}")
                pass
        
        if not open_ports:
             logger.warning(f"Naabu completed but found NO open ports on {host} ({ip_address}). Stderr: {result.stderr}")
        else:
             logger.info(f"Naabu found {len(open_ports)} open ports on {host} ({ip_address})")
             
        return open_ports
    except subprocess.TimeoutExpired:
        logger.error(f"Naabu timed out on {host}")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Naabu failed on {host}: {e.stderr}")
        return []

def run_nuclei(target: str):
    """
    Runs Nuclei to scan for vulnerabilities.
    Returns a list of findings (vulnerabilities).
    """
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"Running Nuclei on {target}...")
    try:
        # Configuration from Env
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
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Log stderr pour diagnostic
        if result.stderr:
            logger.debug(f"Nuclei stderr: {result.stderr[:500]}")
        
        findings = []
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                findings.append({
                    "title": data.get("info", {}).get("name"),
                    "severity": normalize_severity(data.get("info", {}).get("severity")),
                    "description": data.get("info", {}).get("description"),
                    "status": "open"
                })
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Nuclei JSON output: {line[:100]}")
                pass
        
        if not findings:
            logger.warning(f"Nuclei completed but found NO vulnerabilities on {target}.")
            logger.warning(f"Exit code: {result.returncode}, Stderr: {result.stderr[:200]}")
        else:
            logger.info(f"Nuclei scan completed on {target}: {len(findings)} vulnerabilities found")
            
        return findings
    except Exception as e:
        logger.error(f"Nuclei failed on {target}: {e}")
        return []

def normalize_severity(severity: str) -> str:
    """
    Normalizes Nuclei severity to match backend Enum.
    """
    if not severity:
        return "info"
    
    severity = severity.lower()
    
    # Mapping
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

