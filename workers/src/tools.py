import subprocess
import json
import os
import shutil

def run_subfinder(domain: str):
    """
    Runs subfinder to discover subdomains.
    Returns a list of unique subdomains found.
    """
    print(f"[*] Running Subfinder on {domain}...")
    try:
        # -silent: only output subdomains
        # -all: use all sources
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return list(set(subdomains))
    except subprocess.CalledProcessError as e:
        print(f"[!] Subfinder failed: {e.stderr}")
        return []

def run_naabu(host: str):
    """
    Runs naabu to scan ports on a host.
    Returns a list of open ports with metadata.
    """
    print(f"[*] Running Naabu on {host}...")
    try:
        # -json: output json
        # -top-ports 100: scan top 100 ports for speed in POC
        cmd = ["naabu", "-host", host, "-json", "-top-ports", "100", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        open_ports = []
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                open_ports.append({
                    "port": data.get("port"),
                    "protocol": data.get("protocol", "tcp"),
                    "service_name": "unknown" # Naabu doesn't always give service name in simple mode
                })
            except json.JSONDecodeError:
                pass
        return open_ports
    except subprocess.CalledProcessError as e:
        print(f"[!] Naabu failed: {e.stderr}")
        return []

def run_nuclei(target: str):
    """
    Runs nuclei to scan for vulnerabilities.
    Returns a list of findings.
    """
    print(f"[*] Running Nuclei on {target}...")
    try:
        # -jsonl: output json lines
        # -t http/misconfiguration,http/cves: limit templates for POC speed
        cmd = ["nuclei", "-u", target, "-jsonl", "-t", "http/misconfiguration", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        findings = []
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                findings.append({
                    "title": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "description": data.get("info", {}).get("description"),
                    "matcher_name": data.get("matcher-name"),
                    "status": "open"
                })
            except json.JSONDecodeError:
                pass
        return findings
    except subprocess.CalledProcessError as e:
        print(f"[!] Nuclei failed: {e.stderr}")
        return []
