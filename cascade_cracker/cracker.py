"""
cracker.py — GPU hash cracker and Pi sync logic for CascadeCracker.
"""

import json, os, sys, subprocess, argparse, time
from pathlib import Path
from datetime import datetime
from . import config as cfg_mod

RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
WH  = "\033[97m"; DIM = "\033[2m";  B   = "\033[1m"; R = "\033[0m"


# ── vault (local mirror of Pi vault) ─────────────────────────────────────────

def _load_vault() -> list[dict]:
    if cfg_mod.VAULT_FILE.exists():
        try:
            return json.loads(cfg_mod.VAULT_FILE.read_text())
        except Exception:
            pass
    return []


def _save_vault(entries: list[dict]):
    cfg_mod.CASCADE_DIR.mkdir(parents=True, exist_ok=True)
    cfg_mod.VAULT_FILE.write_text(json.dumps(entries, indent=2))


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Pi sync ───────────────────────────────────────────────────────────────────

def pull_from_pi(cfg: dict) -> int:
    """SCP vault.json from Pi. Returns count of pending hashes."""
    host     = cfg["pi_host"]
    user     = cfg["pi_user"]
    vault    = cfg.get("pi_vault_path", "/root/.cascade/vault.json")
    key      = cfg.get("pi_ssh_key", "")

    print(f"  {DIM}Pulling vault from {user}@{host} ...{R}")
    scp = ["scp", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if key and Path(key).exists():
        scp += ["-i", key]
    scp += [f"{user}@{host}:{vault}", str(cfg_mod.VAULT_FILE)]

    r = subprocess.run(scp, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  {RED}Pull failed: {r.stderr.strip() or 'check Pi is reachable'}{R}")
        print(f"  {DIM}Tip: run cascade-doctor to diagnose connection issues.{R}")
        return 0

    entries = _load_vault()
    pending = sum(1 for e in entries if e.get("status") == "pending")
    print(f"  {GRN}Pulled {len(entries)} entries — {pending} pending{R}")
    return pending


def push_to_pi(cfg: dict) -> bool:
    """SCP local vault back to Pi."""
    host  = cfg["pi_host"]
    user  = cfg["pi_user"]
    vault = cfg.get("pi_vault_path", "/root/.cascade/vault.json")  # cascade runs as root
    key   = cfg.get("pi_ssh_key", "")

    if not cfg_mod.VAULT_FILE.exists():
        print(f"  {YLW}No local vault to push.{R}")
        return False

    print(f"  {DIM}Pushing results to {user}@{host} ...{R}")
    scp = ["scp", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if key and Path(key).exists():
        scp += ["-i", key]
    scp += [str(cfg_mod.VAULT_FILE), f"{user}@{host}:{vault}"]

    r = subprocess.run(scp, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  {RED}Push failed: {r.stderr.strip()}{R}")
        return False
    print(f"  {GRN}Vault synced to Pi.{R}")
    return True


# ── cracking ──────────────────────────────────────────────────────────────────

def _read_pot(pot_path: str) -> dict[str, str]:
    """Read hashcat pot file → { hash_fragment: password }."""
    result = {}
    p = Path(pot_path)
    if not p.exists():
        return result
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        idx = line.rfind(":")
        if idx < 0:
            continue
        result[line[:idx].upper()] = line[idx+1:]
    return result


def crack_pending(cfg: dict) -> int:
    """
    Crack all pending hashes in the local vault.
    Pipeline: plain rockyou → best64 → d3ad0ne → dive (stops early on full crack).
    Returns count of newly cracked passwords.
    """
    entries = _load_vault()
    pending = [e for e in entries if e.get("status") == "pending"]
    if not pending:
        print(f"  {YLW}No pending hashes to crack.{R}")
        return 0

    hashcat = cfg_mod.discover_hashcat(cfg)
    if not hashcat:
        print(f"  {RED}hashcat not found. Run cascade-doctor for setup instructions.{R}")
        return 0

    wordlist = cfg_mod.get_wordlist(cfg)
    if not wordlist:
        print(f"  {RED}No wordlist found. Run cascade-doctor for setup instructions.{R}")
        return 0

    hc_dir    = str(Path(hashcat).parent)
    rules_dir = cfg_mod.discover_rules_dir(hashcat) or cfg.get("rules_dir", "")
    timeout   = cfg.get("gpu_timeout", 600)
    rules     = cfg.get("rules_progression", ["best64.rule", "d3ad0ne.rule", "dive.rule"])

    # Group by hashcat mode
    by_mode: dict[int, list[dict]] = {}
    for e in pending:
        mode = e.get("hc_mode", 5600)
        by_mode.setdefault(mode, []).append(e)

    total_cracked = 0

    for mode, group in by_mode.items():
        print(f"\n  {WH}{B}Mode {mode} — {len(group)} hash(es){R}")

        tmp_dir    = cfg_mod.CASCADE_DIR
        tmp_hashes = tmp_dir / f"crack_{mode}.hashes"
        tmp_pot    = tmp_dir / f"crack_{mode}.pot"
        tmp_pot.unlink(missing_ok=True)
        tmp_hashes.write_text("\n".join(e["hash"] for e in group))

        base = [hashcat, "-m", str(mode), "--potfile-path", str(tmp_pot),
                "--quiet", str(tmp_hashes), wordlist, "--force", "-O"]

        def _pass(extra: list[str], label: str) -> int:
            print(f"    {DIM}{label:<40}{R}", end="", flush=True)
            try:
                subprocess.run(base + extra, timeout=timeout,
                               cwd=hc_dir, capture_output=True)
            except subprocess.TimeoutExpired:
                print(f" {YLW}timeout{R}", end="")
            pot = _read_pot(str(tmp_pot))
            n = len(pot)
            print(f" → {GRN}{n} cracked{R}" if n else f" → {DIM}0{R}")
            return n

        # Pass 1: plain dictionary
        n = _pass([], "plain dictionary")

        # Pass 2+: rules escalation (stop when all cracked)
        if n < len(group) and rules_dir:
            for rule_file in rules:
                rp = Path(rules_dir) / rule_file
                if not rp.exists():
                    continue
                n = _pass(["-r", str(rp)], f"rules: {rule_file}")
                pot = _read_pot(str(tmp_pot))
                if len(pot) >= len(group):
                    break

        # Update vault from pot
        pot = _read_pot(str(tmp_pot))
        for e in group:
            h_upper = e["hash"].upper()
            for pot_key, password in pot.items():
                if pot_key in h_upper or h_upper.startswith(pot_key):
                    e["status"]     = "cracked"
                    e["password"]   = password
                    e["cracked_ts"] = _ts()
                    total_cracked  += 1
                    user_str = f"{e.get('domain','?')}\\{e.get('username','?')}"
                    print(f"  {GRN}CRACKED:{R} {YLW}{user_str}{R} → {GRN}{B}{password}{R}")
                    break

        tmp_hashes.unlink(missing_ok=True)

    _save_vault(entries)
    return total_cracked


# ── display ───────────────────────────────────────────────────────────────────

def print_hashes():
    rows = _load_vault()
    if not rows:
        print(f"  {YLW}No hashes in vault.{R}")
        return
    print(f"\n  {WH}{B}{'#':<4}{'CAPTURED':<20}{'IP':<16}{'USER':<32}{'TYPE':<9}STATUS{R}")
    print("  " + "─" * 88)
    for i, e in enumerate(rows, 1):
        st = (f"{GRN}CRACKED{R}"    if e.get("status") == "cracked"   else
              f"{YLW}pending{R}"    if e.get("status") == "pending"   else
              f"{DIM}exhausted{R}")
        user = f"{e.get('domain','?')}\\{e.get('username','?')}"
        print(f"  {DIM}{i:<4}{R}{DIM}{e.get('ts',''):<20}{R}"
              f"{WH}{e.get('target_ip',''):<16}{R}"
              f"{YLW}{user:<32}{R}"
              f"{DIM}{e.get('hash_type',''):<9}{R}{st}")
    print()


def print_cracked():
    rows = [e for e in _load_vault() if e.get("status") == "cracked"]
    if not rows:
        print(f"  {YLW}No cracked passwords yet.{R}")
        return
    print(f"\n  {WH}{B}{'#':<4}{'CRACKED AT':<20}{'IP':<16}{'USER':<32}{'PASSWORD'}{R}")
    print("  " + "─" * 88)
    for i, e in enumerate(rows, 1):
        user = f"{e.get('domain','?')}\\{e.get('username','?')}"
        print(f"  {DIM}{i:<4}{R}{DIM}{e.get('cracked_ts',''):<20}{R}"
              f"{WH}{e.get('target_ip',''):<16}{R}"
              f"{YLW}{user:<32}{R}"
              f"{GRN}{B}{e.get('password','')}{R}")
    print()


# ── config menu ───────────────────────────────────────────────────────────────

def config_menu(cfg: dict) -> dict:
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(f"\n  {WH}{B}CONFIGURATION{R}  {DIM}(saved to {cfg_mod.CONFIG_FILE}){R}\n")
        wl = cfg_mod.get_wordlist(cfg) or f"{RED}NOT FOUND{R}"
        hc = cfg_mod.discover_hashcat(cfg) or f"{RED}NOT FOUND{R}"
        key = cfg.get("pi_ssh_key") or f"{YLW}auto-detect{R}"
        print(f"  {RED}{B}1{R}  Pi host        {WH}{cfg.get('pi_host','')}{R}")
        print(f"  {RED}{B}2{R}  Pi user        {WH}{cfg.get('pi_user','kali')}{R}")
        print(f"  {RED}{B}3{R}  Pi SSH key     {WH}{key}{R}")
        print(f"  {RED}{B}4{R}  Pi vault path  {WH}{cfg.get('pi_vault_path','')}{R}")
        print(f"  {RED}{B}5{R}  hashcat        {WH}{hc}{R}")
        print(f"  {RED}{B}6{R}  Wordlist       {WH}{wl}{R}")
        print(f"  {RED}{B}7{R}  GPU timeout    {WH}{cfg.get('gpu_timeout',600)}s per pass{R}")
        print(f"\n  {DIM}0 / Enter → back{R}\n")
        raw = input(f"  {WH}{B}→ {R}").strip()
        if raw in ("0", ""):
            break
        elif raw == "1":
            v = input("  Pi Tailscale IP: ").strip()
            if v: cfg["pi_host"] = v
        elif raw == "2":
            v = input("  Pi username: ").strip()
            if v: cfg["pi_user"] = v
        elif raw == "3":
            v = input("  SSH key path (blank = auto): ").strip()
            cfg["pi_ssh_key"] = v
        elif raw == "4":
            v = input("  Pi vault.json path: ").strip()
            if v: cfg["pi_vault_path"] = v
        elif raw == "5":
            v = input("  hashcat.exe path: ").strip()
            if v: cfg["hashcat_path"] = v
        elif raw == "6":
            v = input("  Wordlist path: ").strip()
            if v: cfg["wordlists"] = [v] + cfg.get("wordlists", [])
        elif raw == "7":
            try: cfg["gpu_timeout"] = int(input("  Seconds: ").strip())
            except ValueError: pass
        cfg_mod.save(cfg)
    return cfg


# ── self-update ───────────────────────────────────────────────────────────────

def _self_update():
    """git pull + pip install -e . from the repo root."""
    repo = Path(__file__).resolve().parent.parent
    print(f"\n  {DIM}Repo: {repo}{R}")

    print(f"  {WH}Pulling latest from GitHub...{R}")
    r = subprocess.run(["git", "pull"], cwd=str(repo), capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  {RED}git pull failed:{R}\n  {r.stderr.strip()}")
        return
    print(f"  {GRN}{r.stdout.strip() or 'Already up to date.'}{R}")

    print(f"  {WH}Reinstalling package...{R}")
    r2 = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", str(repo), "-q"],
        capture_output=True, text=True
    )
    if r2.returncode != 0:
        print(f"  {RED}pip install failed:{R}\n  {r2.stderr.strip()}")
        return
    print(f"  {GRN}Updated. Restart cascade to use the new version.{R}")


# ── main menu ─────────────────────────────────────────────────────────────────

def _banner(cfg: dict):
    os.system("cls" if os.name == "nt" else "clear")
    entries = _load_vault()
    nc = sum(1 for e in entries if e.get("status") == "cracked")
    np = sum(1 for e in entries if e.get("status") == "pending")
    ts_ip = cfg_mod.windows_tailscale_ip()
    ts_str = f"{GRN}{ts_ip}{R}" if ts_ip else f"{RED}not connected{R}"
    print(f"""
  {RED}{B}╔═══════════════════════════════════════════╗
  ║   CASCADE CRACKER  —  GPU Edition  v1.0   ║
  ╚═══════════════════════════════════════════╝{R}
  {DIM}Pi:{R} {WH}{cfg.get('pi_host','?')}{R}   {DIM}Tailscale:{R} {ts_str}   {GRN}{B}{nc} cracked{R}   {YLW}{np} pending{R}
""")


def main():
    ap = argparse.ArgumentParser(description="CascadeCracker — GPU hash cracker for Cascade")
    ap.add_argument("--pull-and-crack", action="store_true",
                    help="Headless: pull → crack → push, then exit")
    ap.add_argument("--pi-host", help="Override Pi Tailscale IP")
    args = ap.parse_args()

    cfg = cfg_mod.load()
    cfg = cfg_mod.auto_populate(cfg)
    cfg_mod.save(cfg)

    if args.pi_host:
        cfg["pi_host"] = args.pi_host

    if args.pull_and_crack:
        print("CascadeCracker — headless mode")
        n = pull_from_pi(cfg)
        if n:
            nc = crack_pending(cfg)
            if nc:
                push_to_pi(cfg)
                print(f"Done. {nc} password(s) cracked and synced.")
            else:
                print("Hashes pulled but none cracked.")
        else:
            print("Nothing to pull.")
        return

    while True:
        _banner(cfg)
        print(f"  {'─' * 50}")
        print(f"  {RED}{B}1{R}  Pull hashes from Pi        {DIM}sync vault via SSH{R}")
        print(f"  {RED}{B}2{R}  Crack pending hashes       {DIM}GPU: rockyou → rules escalation{R}")
        print(f"  {RED}{B}3{R}  Push results to Pi         {DIM}sync cracked passwords back{R}")
        print(f"  {RED}{B}4{R}  Pull + crack + push        {DIM}full automated cycle{R}")
        print()
        print(f"  {RED}{B}5{R}  View all hashes")
        print(f"  {RED}{B}6{R}  View cracked passwords")
        print()
        print(f"  {RED}{B}d{R}  Doctor / diagnostics       {DIM}check everything, fix setup issues{R}")
        print(f"  {RED}{B}u{R}  Update                     {DIM}git pull + reinstall latest version{R}")
        print(f"  {RED}{B}c{R}  Configure")
        print(f"  {RED}{B}q{R}  Quit")
        print(f"  {'─' * 50}\n")

        raw = input(f"  {WH}{B}→ {R}").strip().lower()

        if raw == "q":
            print(f"\n  {DIM}bye.{R}\n")
            sys.exit(0)

        elif raw == "1":
            pull_from_pi(cfg)
            input(f"\n  {DIM}[ press Enter ]{R}")

        elif raw == "2":
            n = crack_pending(cfg)
            msg = f"Cracked {n} password(s)." if n else "Nothing cracked."
            print(f"\n  {(GRN if n else YLW)}{msg}{R}")
            input(f"  {DIM}[ press Enter ]{R}")

        elif raw == "3":
            push_to_pi(cfg)
            input(f"\n  {DIM}[ press Enter ]{R}")

        elif raw == "4":
            print()
            np = pull_from_pi(cfg)
            if np:
                nc = crack_pending(cfg)
                if nc:
                    push_to_pi(cfg)
                    print(f"\n  {GRN}{B}Done. {nc} password(s) cracked and synced to Pi.{R}")
                else:
                    print(f"\n  {YLW}Hashes pulled but none cracked.{R}")
            else:
                print(f"\n  {YLW}No pending hashes to crack.{R}")
            input(f"\n  {DIM}[ press Enter ]{R}")

        elif raw == "5":
            os.system("cls" if os.name == "nt" else "clear")
            print_hashes()
            input(f"  {DIM}[ press Enter ]{R}")

        elif raw == "6":
            os.system("cls" if os.name == "nt" else "clear")
            print_cracked()
            input(f"  {DIM}[ press Enter ]{R}")

        elif raw == "d":
            from .doctor import run_full_check
            run_full_check(cfg)
            input(f"\n  {DIM}[ press Enter ]{R}")

        elif raw == "u":
            _self_update()
            input(f"\n  {DIM}[ press Enter — cascade will restart on next launch ]{R}")

        elif raw == "c":
            cfg = config_menu(cfg)
