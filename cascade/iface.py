"""
iface.py — Interface detection, adapter mode, network connection utilities
"""

import os, re, shutil, socket, subprocess, ipaddress
from . import tui


# ── list all network interfaces ───────────────────────────────────────────────

def list_interfaces() -> list[dict]:
    """
    Returns list of dicts:
    { name, ip, subnet, mac, mode, state }
    """
    ifaces = []
    try:
        out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []

    current = None
    for line in out.splitlines():
        # New interface block
        m = re.match(r"^\d+:\s+(\S+?)[@:]?\s.*state\s+(\S+)", line)
        if m:
            if current:
                ifaces.append(current)
            current = {"name": m.group(1), "state": m.group(2),
                       "ip": None, "subnet": None, "mac": None, "mode": "?"}
            continue

        if not current:
            continue

        # MAC
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
        if m:
            current["mac"] = m.group(1)

        # IP
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            current["ip"]     = m.group(1)
            prefix            = int(m.group(2))
            net               = ipaddress.IPv4Network(f"{m.group(1)}/{prefix}", strict=False)
            current["subnet"] = str(net)

    if current:
        ifaces.append(current)

    # Add wireless mode for wireless interfaces
    for iface in ifaces:
        mode = _get_wireless_mode(iface["name"])
        if mode:
            iface["mode"] = mode

    return [i for i in ifaces if i["name"] not in ("lo",)]


def _get_wireless_mode(name: str) -> str:
    try:
        out = subprocess.check_output(
            ["iwconfig", name], stderr=subprocess.DEVNULL, text=True
        )
        m = re.search(r"Mode:(\S+)", out)
        return m.group(1).upper() if m else None
    except Exception:
        return None


def is_wireless(name: str) -> bool:
    return _get_wireless_mode(name) is not None


# ── adapter mode switching ────────────────────────────────────────────────────

def get_mode(name: str) -> str:
    return _get_wireless_mode(name) or "N/A"


def set_mode(name: str, mode: str) -> bool:
    """Switch interface to 'monitor' or 'managed'. Returns True on success."""
    mode = mode.lower()
    tui.info(f"Switching {name} to {mode} mode ...")
    try:
        subprocess.call(["ip", "link", "set", name, "down"])
        subprocess.call(["iwconfig", name, "mode", mode])
        subprocess.call(["ip", "link", "set", name, "up"])
        time.sleep(0.5)
        actual = _get_wireless_mode(name) or ""
        if mode in actual.lower():
            tui.success(f"{name} is now in {actual} mode.")
            return True
        else:
            tui.warn(f"Mode switch may have failed — current mode: {actual}")
            return False
    except Exception as e:
        tui.error(f"Failed to switch mode: {e}")
        return False


import time  # needed by set_mode — placed after function defs to avoid forward ref issue


# ── connection check ──────────────────────────────────────────────────────────

def has_ip(name: str) -> bool:
    for iface in list_interfaces():
        if iface["name"] == name and iface["ip"]:
            return True
    return False


def get_subnet(name: str) -> str | None:
    for iface in list_interfaces():
        if iface["name"] == name and iface["subnet"]:
            return iface["subnet"]
    return None


def internet_reachable() -> bool:
    try:
        socket.setdefaulttimeout(3)
        socket.create_connection(("8.8.8.8", 53))
        return True
    except OSError:
        return False


# ── nmtui / connection helper ─────────────────────────────────────────────────

def launch_nmtui():
    """Launch nmtui for interactive network management."""
    if not shutil.which("nmtui"):
        tui.error("nmtui not found — install: sudo apt install network-manager")
        return
    subprocess.call(["nmtui"])


def connection_advice(name: str):
    """Print advice for getting the interface connected."""
    tui.warn(f"{name} has no IP address — not connected to a network.")
    print(f"""
  {tui.WH}To connect:{tui.R}

  {tui.RED}{tui.B}Option A — WiFi (nmtui){tui.R}
    {tui.DIM}Interactive network manager in the terminal:{tui.R}
    sudo nmtui
    → Select "Activate a connection" → pick the network → enter password

  {tui.RED}{tui.B}Option B — Ethernet{tui.R}
    Plug the Pi into a switch/router port. eth0 should get an IP via DHCP
    automatically within a few seconds.

  {tui.RED}{tui.B}Option C — Evil twin (get on network via rogue AP){tui.R}
    Use portal_cloner.py or airgeddon to set up a rogue AP and capture
    the real WiFi password, then connect legitimately.

  {tui.DIM}Note: Cascade needs to be on the same LAN segment as your targets.
  Responder and CME do not work across routed boundaries.{tui.R}
""")


# ── dependency check ──────────────────────────────────────────────────────────

_REQUIRED_TOOLS = [
    ("nmap",                 "sudo apt install nmap",                   "recon"),
    ("responder",            "sudo apt install responder",              "hash harvest"),
    ("hashcat",              "sudo apt install hashcat",                "cracking"),
    ("crackmapexec",         "sudo apt install crackmapexec",           "lateral movement"),
    ("impacket-psexec",      "sudo apt install python3-impacket",       "psexec shells"),
    ("evil-winrm",           "sudo gem install evil-winrm",             "winrm shells"),
    ("sshpass",              "sudo apt install sshpass",                "ssh shells"),
    ("smbclient",            "sudo apt install smbclient",              "smb browse"),
]

def check_tools() -> list[dict]:
    """Return list of { tool, install, used_for, found } for all tools."""
    return [
        {"tool": t, "install": i, "used_for": u, "found": bool(shutil.which(t))}
        for t, i, u in _REQUIRED_TOOLS
    ]


def print_tool_status():
    missing = [t for t in check_tools() if not t["found"]]
    present = [t for t in check_tools() if t["found"]]

    if present:
        print(f"\n  {tui.GRN}{tui.B}Installed:{tui.R}")
        for t in present:
            print(f"    {tui.GRN}✓{tui.R}  {tui.WH}{t['tool']:<22}{tui.R}  {tui.DIM}{t['used_for']}{tui.R}")

    if missing:
        print(f"\n  {tui.YLW}{tui.B}Missing:{tui.R}")
        for t in missing:
            print(f"    {tui.RED}✗{tui.R}  {tui.WH}{t['tool']:<22}{tui.R}  "
                  f"{tui.DIM}{t['used_for']:<20}{tui.R}  {tui.YLW}{t['install']}{tui.R}")
    print()
