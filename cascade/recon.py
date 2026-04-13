"""
recon.py — Subnet discovery and port scan via nmap
"""

import subprocess, re, socket, ipaddress
from . import tui


def local_subnet() -> str:
    """Best-guess local subnet in CIDR notation (e.g. 192.168.1.0/24)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(net)
    except Exception:
        return "192.168.1.0/24"


def scan(subnet: str = None, fast: bool = True) -> list[dict]:
    """
    Run nmap on subnet. Returns list of host dicts:
    { ip, hostname, os, ports, mac }
    """
    if not subnet:
        subnet = local_subnet()

    tui.info(f"Scanning {subnet} ...")

    if fast:
        # Quick port detection — top 100 ports, no service probing
        args = ["nmap", "--open", "-T4", "-n", "-F",
                "--host-timeout", "30s", subnet]
    else:
        # Full scan — service detection, all ports
        args = ["nmap", "-sV", "--open", "-T4", "-n", "-p-",
                "--min-rate=1000", "--host-timeout", "60s", subnet]

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=300
        )
        output = result.stdout
    except FileNotFoundError:
        tui.error("nmap not found — install: sudo apt install nmap")
        return []
    except subprocess.TimeoutExpired:
        tui.warn("nmap timed out — partial results may be available")
        output = ""

    return _parse_nmap(output)


def _parse_nmap(output: str) -> list[dict]:
    hosts = []
    current = None

    for line in output.splitlines():
        # New host block
        m = re.match(r"Nmap scan report for (.+?)(?:\s+\((.+?)\))?$", line)
        if m:
            if current:
                hosts.append(current)
            hostname = m.group(1)
            ip       = m.group(2) or hostname
            current  = {"ip": ip, "hostname": hostname if m.group(2) else "", "ports": [], "os": "", "mac": ""}
            continue

        if current is None:
            continue

        # Open port
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            current["ports"].append(int(m.group(1)))
            continue

        # OS detection
        m = re.match(r"OS details?:\s+(.+)", line, re.IGNORECASE)
        if m:
            current["os"] = m.group(1)[:40]
            continue

        # MAC
        m = re.match(r"MAC Address:\s+([0-9A-Fa-f:]{17})", line)
        if m:
            current["mac"] = m.group(1)

    if current:
        hosts.append(current)

    return hosts
