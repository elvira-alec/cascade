"""
tui.py — Terminal UI for Cascade
All output functions also write to ~/.cascade/cascade.log via logger.
"""

import sys, time
from . import logger as _log

# ── colours ───────────────────────────────────────────────────────────────────
R   = "\033[0m";   B   = "\033[1m";   DIM = "\033[2m"
RED = "\033[91m";  GRN = "\033[92m";  YLW = "\033[93m"
BLU = "\033[94m";  MAG = "\033[95m";  CYN = "\033[96m"
WH  = "\033[97m"

W = 68

BANNER = f"""
{RED}{B}
   ██████╗ █████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
  ██║     ███████║███████╗██║     ███████║██║  ██║█████╗
  ██║     ██╔══██║╚════██║██║     ██╔══██║██║  ██║██╔══╝
  ╚██████╗██║  ██║███████║╚██████╗██║  ██║██████╔╝███████╗
   ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
{R}{DIM}  Post-Exploitation Orchestrator  ·  Automated Kill Chain{R}
{DIM}  For authorized testing only{R}
"""

def clear():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

def print_banner():
    print(BANNER)

def _strip(msg: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", msg)

def info(msg):
    print(f"  {BLU}{B}[*]{R} {msg}")
    _log.info(_strip(msg))

def success(msg):
    print(f"  {GRN}{B}[+]{R} {msg}")
    _log.success(_strip(msg))

def warn(msg):
    print(f"  {YLW}{B}[!]{R} {msg}")
    _log.warn(_strip(msg))

def error(msg):
    print(f"  {RED}{B}[-]{R} {msg}")
    _log.error(_strip(msg))

def phase(title):
    pad = W - len(title) - 4
    print(f"\n  {RED}{B}┌{'─' * (W)}┐{R}")
    print(f"  {RED}{B}│  {WH}{B}{title}{R}{RED}{B}{'─' * pad}  │{R}")
    print(f"  {RED}{B}└{'─' * (W)}┘{R}\n")
    _log.info(f"=== {title} ===")

def divider():
    print(f"  {DIM}{'─' * W}{R}")

def stage_result(label, ok, detail=""):
    icon = f"{GRN}{B}[+]{R}" if ok else f"{RED}{B}[-]{R}"
    print(f"  {icon}  {WH}{B}{label}{R}  {DIM}{detail}{R}")

def host_table(hosts):
    print(f"\n  {WH}{B}  #   IP ADDRESS       HOSTNAME                   OS / OPEN PORTS{R}")
    divider()
    for i, h in enumerate(hosts, 1):
        os_str   = (h.get("os") or "unknown")[:18]
        ports    = ", ".join(str(p) for p in (h.get("ports") or [])[:6])
        hostname = (h.get("hostname") or "")[:24]
        print(
            f"  {DIM}{i:>2}{R}   "
            f"{WH}{h['ip']:<16}{R}  "
            f"{WH}{hostname:<26}{R}  "
            f"{DIM}{os_str}  {YLW}{ports}{R}"
        )
    divider()

def cred_table(creds):
    print(f"\n  {WH}{B}  #   TARGET           SERVICE   USERNAME           PASSWORD / HASH{R}")
    divider()
    for i, c in enumerate(creds, 1):
        print(
            f"  {DIM}{i:>2}{R}   "
            f"{WH}{c.get('target',''):<16}{R}  "
            f"{YLW}{c.get('service',''):<9}{R}  "
            f"{WH}{c.get('user',''):<18}{R}  "
            f"{GRN}{c.get('secret','')}{R}"
        )
    divider()

def pick(prompt, choices):
    while True:
        try:
            raw = input(f"\n  {WH}{prompt}{R} ").strip()
            if raw in choices:
                return raw
        except KeyboardInterrupt:
            raise
