"""
iface.py — Interface detection, adapter mode, WiFi scan, connection utilities
"""

import re, shutil, socket, subprocess, ipaddress, time
from . import tui


# ── list all network interfaces ───────────────────────────────────────────────

def list_interfaces() -> list[dict]:
    """
    Returns list of dicts:
    { name, ip, subnet, mac, mode, state, wireless }
    mode is None for wired interfaces.
    """
    ifaces = []
    try:
        out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []

    current = None
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)[@:]?\s.*state\s+(\S+)", line)
        if m:
            if current:
                ifaces.append(current)
            current = {"name": m.group(1), "state": m.group(2),
                       "ip": None, "subnet": None, "mac": None,
                       "mode": None, "wireless": False}
            continue
        if not current:
            continue
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
        if m:
            current["mac"] = m.group(1)
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            current["ip"]     = m.group(1)
            net               = ipaddress.IPv4Network(
                f"{m.group(1)}/{m.group(2)}", strict=False)
            current["subnet"] = str(net)

    if current:
        ifaces.append(current)

    for i in ifaces:
        mode = _get_wireless_mode(i["name"])
        if mode is not None:
            i["mode"]     = mode
            i["wireless"] = True
        i["nm"] = nm_managed(i["name"])

    return [i for i in ifaces if i["name"] != "lo"]


def _get_wireless_mode(name: str):
    try:
        out = subprocess.check_output(
            ["iwconfig", name], stderr=subprocess.DEVNULL, text=True)
        if "no wireless extensions" in out:
            return None
        m = re.search(r"Mode:(\S+)", out)
        return m.group(1).upper() if m else "UNKNOWN"
    except Exception:
        return None


def list_wireless() -> list[dict]:
    return [i for i in list_interfaces() if i["wireless"]]


# ── NetworkManager management status ─────────────────────────────────────────

def nm_managed(name: str) -> bool:
    """
    Return True if NetworkManager is actively managing this interface.
    NOTE: iwconfig Mode:Managed (802.11 client mode) is completely separate
    from this — an interface can be 802.11 managed-mode but NM-unmanaged.
    """
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[0].strip() == name:
                return parts[1].strip() not in ("unmanaged", "unavailable", "")
    except Exception:
        pass
    return False


def set_nm_managed(name: str, managed: bool = True) -> bool:
    """Tell NetworkManager to manage (or stop managing) an interface."""
    val = "yes" if managed else "no"
    try:
        result = subprocess.run(
            ["nmcli", "device", "set", name, "managed", val],
            text=True, capture_output=True
        )
        if result.returncode == 0:
            tui.success(f"NetworkManager now {'manages' if managed else 'ignores'} {name}")
            time.sleep(1)
            return True
        tui.error(result.stderr.strip())
        return False
    except FileNotFoundError:
        tui.error("nmcli not found — install: sudo apt install network-manager")
        return False


# ── adapter mode switching ────────────────────────────────────────────────────

def get_mode(name: str) -> str:
    return _get_wireless_mode(name) or "N/A"


def set_mode(name: str, mode: str) -> bool:
    """Switch to 'monitor' or 'managed'. Returns True on success."""
    mode = mode.lower()
    tui.info(f"Switching {name} → {mode} mode ...")
    try:
        subprocess.call(["ip", "link", "set", name, "down"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["iwconfig", name, "mode", mode],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["ip", "link", "set", name, "up"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        actual = _get_wireless_mode(name) or ""
        if mode in actual.lower():
            tui.success(f"{name} is now {actual}.")
            return True
        tui.warn(f"Switch may have failed — current: {actual}")
        return False
    except Exception as e:
        tui.error(f"Mode switch failed: {e}")
        return False


def ensure_managed(name: str) -> bool:
    """
    If a wireless interface is in monitor mode, offer to switch it back
    to managed (required for Responder, nmap, CME).
    Returns True if managed (or wired), False if still in monitor.
    """
    mode = _get_wireless_mode(name)
    if mode is None:
        return True   # wired — fine
    if "MONITOR" in mode.upper():
        tui.warn(f"{name} is in MONITOR mode.")
        tui.info("Cascade needs MANAGED mode for nmap, Responder, and CME.")
        ans = input(f"  {tui.WH}Switch {name} to MANAGED now? [Y/n] {tui.R}").strip().lower()
        if ans != "n":
            return set_mode(name, "managed")
        return False
    return True


# ── WiFi scanning ─────────────────────────────────────────────────────────────

def scan_wifi(iface_name: str) -> list[dict]:
    """
    Scan for nearby WiFi networks. Tries nmcli first, falls back to iwlist.
    Returns list of { bssid, ssid, channel, signal, security }.
    """
    # Switch to managed if in monitor mode
    mode = _get_wireless_mode(iface_name)
    if mode and "MONITOR" in mode.upper():
        tui.warn(f"{iface_name} is in monitor mode — switching to managed for scan ...")
        set_mode(iface_name, "managed")

    # Bring interface up if it's DOWN
    try:
        out = subprocess.check_output(["ip", "link", "show", iface_name],
                                      text=True, stderr=subprocess.DEVNULL)
        if "state DOWN" in out or "NO-CARRIER" in out:
            subprocess.call(["ip", "link", "set", iface_name, "up"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
    except Exception:
        pass

    tui.info(f"Scanning for WiFi networks on {iface_name} ...")

    # nmcli only works if NetworkManager manages the interface
    if nm_managed(iface_name):
        networks = _scan_wifi_nmcli(iface_name)
        if networks:
            return networks
        tui.info("nmcli returned no results — falling back to iwlist ...")
    else:
        tui.info(f"{iface_name} is not managed by NetworkManager — using iwlist ...")

    return _scan_wifi_iwlist(iface_name)


def _scan_wifi_nmcli(iface_name: str) -> list[dict]:
    try:
        subprocess.call(
            ["nmcli", "device", "wifi", "rescan", "ifname", iface_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
             "device", "wifi", "list", "ifname", iface_name],
            text=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        return []

    networks = []
    for line in out.strip().splitlines():
        line  = line.replace("\\:", "\x00")
        parts = line.split(":")
        if len(parts) < 5:
            continue
        bssid    = parts[0].replace("\x00", ":").strip()
        ssid     = parts[1].strip()
        channel  = parts[2].strip()
        signal   = parts[3].strip()
        security = ":".join(parts[4:]).strip() or "OPEN"
        if not bssid or bssid == "--":
            continue
        networks.append({"bssid": bssid, "ssid": ssid or "<hidden>",
                         "channel": channel, "signal": signal, "security": security})

    seen, unique = set(), []
    for n in networks:
        if n["bssid"] not in seen:
            seen.add(n["bssid"])
            unique.append(n)
    unique.sort(key=lambda x: int(x["signal"]) if x["signal"].lstrip("-").isdigit() else 0,
                reverse=True)
    return unique


def _scan_wifi_iwlist(iface_name: str) -> list[dict]:
    """Fallback WiFi scan using iwlist."""
    try:
        out = subprocess.check_output(
            ["iwlist", iface_name, "scan"],
            text=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        return []

    networks = []
    current  = None
    for line in out.splitlines():
        line = line.strip()
        m = re.search(r"Cell \d+ - Address: ([0-9A-Fa-f:]{17})", line)
        if m:
            if current:
                networks.append(current)
            current = {"bssid": m.group(1), "ssid": "<hidden>",
                       "channel": "", "signal": "", "security": "OPEN"}
            continue
        if current is None:
            continue
        m = re.search(r'ESSID:"(.*?)"', line)
        if m:
            current["ssid"] = m.group(1) or "<hidden>"
        m = re.search(r"Channel:(\d+)", line)
        if m:
            current["channel"] = m.group(1)
        m = re.search(r"Signal level=(-?\d+)", line)
        if m:
            current["signal"] = m.group(1)
        # WPA2 > WPA > WEP > OPEN  (upgrade security label as we see IE lines)
        if "WPA2" in line or "802.11i" in line:
            current["security"] = "WPA2"
        elif "WPA" in line and current["security"] == "OPEN":
            current["security"] = "WPA"
        elif "WEP" in line and current["security"] == "OPEN":
            current["security"] = "WEP"

    if current:
        networks.append(current)

    # Sort by signal strength descending
    networks.sort(
        key=lambda x: int(x["signal"]) if x["signal"].lstrip("-").isdigit() else -99,
        reverse=True
    )
    return networks


def print_wifi_table(networks: list[dict]):
    print(f"\n  {tui.WH}{tui.B}  #  BSSID              SSID                       CH   SIG  SECURITY{tui.R}")
    tui.divider()
    for i, n in enumerate(networks, 1):
        sec    = n["security"]
        s_col  = tui.RED if sec == "OPEN" else (tui.YLW if "WPA" in sec else tui.WH)
        sig    = n["signal"]
        sg_col = (tui.GRN if sig.lstrip("-").isdigit() and int(sig) > 60
                  else tui.YLW if sig.lstrip("-").isdigit() and int(sig) > 40
                  else tui.RED)
        print(
            f"  {tui.DIM}{i:>2}{tui.R}  "
            f"{tui.WH}{n['bssid']:<18}{tui.R}  "
            f"{tui.WH}{n['ssid'][:26]:<26}{tui.R}  "
            f"{tui.DIM}{n['channel']:>2}{tui.R}  "
            f"{sg_col}{sig:>4}{tui.R}  "
            f"{s_col}{sec}{tui.R}"
        )
    tui.divider()


# ── WiFi connection ───────────────────────────────────────────────────────────

def connect_wifi(iface_name: str, ssid: str, password: str = None,
                 bssid: str = None) -> bool:
    """
    Connect to a WiFi network.
    Uses nmcli for NM-managed interfaces, wpa_supplicant+dhcpcd for others
    (e.g. RTL8187/Alfa adapters that NM refuses to manage).
    Returns True on success.
    """
    tui.info(f"Connecting to '{ssid}' on {iface_name} ...")

    if nm_managed(iface_name):
        return _connect_wifi_nmcli(iface_name, ssid, password, bssid)
    else:
        return _connect_wifi_wpa(iface_name, ssid, password)


def _connect_wifi_nmcli(iface_name: str, ssid: str, password: str,
                        bssid: str) -> bool:
    target = bssid if bssid else ssid
    cmd = ["nmcli", "device", "wifi", "connect", target, "ifname", iface_name]
    if password:
        cmd += ["password", password]
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        if result.returncode == 0:
            tui.success(f"Connected to '{ssid}'")
            time.sleep(2)
            return True
        tui.error(f"Connection failed: {result.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        tui.error("Connection timed out.")
        return False
    except FileNotFoundError:
        tui.error("nmcli not found — install: sudo apt install network-manager")
        return False


_WPA_CTRL = "/run/wpa_supplicant_cascade"


def _connect_wifi_wpa(iface_name: str, ssid: str, password: str) -> bool:
    """Connect via wpa_supplicant + dhcpcd for NM-unmanaged adapters."""
    import tempfile, os

    # Kill any existing wpa_supplicant and dhcpcd forcefully
    subprocess.call(["killall", "wpa_supplicant"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call(["killall", "-9", "dhcpcd"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # Write wpa_supplicant config (with ctrl_interface so we can poll status)
    conf = tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                       delete=False, prefix="cascade_wpa_")
    try:
        psk_block = ""
        if password:
            result = subprocess.run(
                ["wpa_passphrase", ssid, password],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                tui.error("wpa_passphrase failed.")
                return False
            psk_block = result.stdout.strip()
        else:
            psk_block = f'network={{\n  ssid="{ssid}"\n  key_mgmt=NONE\n}}'

        conf.write(f"ctrl_interface={_WPA_CTRL}\n\n" + psk_block + "\n")
        conf.close()

        os.makedirs(_WPA_CTRL, exist_ok=True)
        subprocess.call(["ip", "link", "set", iface_name, "up"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        r = subprocess.run(
            ["wpa_supplicant", "-B", "-i", iface_name,
             "-c", conf.name, "-D", "nl80211,wext"],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            tui.error(f"wpa_supplicant failed: {r.stderr.strip()}")
            return False

        # Poll for COMPLETED association (up to 15s)
        tui.info("Waiting for association ...")
        ctrl_sock = f"{_WPA_CTRL}/{iface_name}"
        for _ in range(15):
            time.sleep(1)
            try:
                out = subprocess.check_output(
                    ["wpa_cli", "-p", _WPA_CTRL, "-i", iface_name, "status"],
                    text=True, stderr=subprocess.DEVNULL
                )
                if "wpa_state=COMPLETED" in out:
                    break
            except Exception:
                pass
        else:
            tui.error("Association timed out — wrong password or AP out of range.")
            return False

        # Get IP via dhcpcd (runs blocking until lease is obtained)
        try:
            subprocess.run(["dhcpcd", iface_name],
                           capture_output=True, timeout=20)
        except subprocess.TimeoutExpired:
            pass
        if has_ip(iface_name):
            tui.success(f"Connected to '{ssid}'")
            return True

        tui.error("Associated but couldn't get an IP address.")
        return False

    except FileNotFoundError as e:
        tui.error(f"Missing tool: {e}")
        return False
    finally:
        os.unlink(conf.name)


# ── connection status ─────────────────────────────────────────────────────────

def has_ip(name: str) -> bool:
    return any(i["name"] == name and i["ip"] for i in list_interfaces())


def get_subnet(name: str):
    for i in list_interfaces():
        if i["name"] == name and i["subnet"]:
            return i["subnet"]
    return None


def launch_nmtui():
    if not shutil.which("nmtui"):
        tui.error("nmtui not found — sudo apt install network-manager")
        return
    subprocess.call(["nmtui"])


# ── dependency check ──────────────────────────────────────────────────────────

_REQUIRED_TOOLS = [
    ("nmap",             "sudo apt install nmap",                 "recon"),
    ("responder",        "sudo apt install responder",            "hash harvest"),
    ("hashcat",          "sudo apt install hashcat",              "cracking"),
    ("crackmapexec",     "sudo apt install crackmapexec",         "lateral movement"),
    ("impacket-psexec",  "sudo apt install python3-impacket",     "psexec shells"),
    ("evil-winrm",       "sudo gem install evil-winrm",           "winrm shells"),
    ("sshpass",          "sudo apt install sshpass",              "ssh shells"),
    ("smbclient",        "sudo apt install smbclient",            "smb browse"),
]

def check_tools() -> list[dict]:
    return [
        {"tool": t, "install": i, "used_for": u, "found": bool(shutil.which(t))}
        for t, i, u in _REQUIRED_TOOLS
    ]

def print_tool_status():
    for t in check_tools():
        icon = f"{tui.GRN}✓{tui.R}" if t["found"] else f"{tui.RED}✗{tui.R}"
        row  = f"  {icon}  {tui.WH}{t['tool']:<22}{tui.R}  {tui.DIM}{t['used_for']:<20}{tui.R}"
        if not t["found"]:
            row += f"  {tui.YLW}{t['install']}{tui.R}"
        print(row)
    print()
