"""
doctor.py — Full diagnostic for CascadeCracker + Cascade Pi setup.

Checks every dependency, connection, and configuration item.
Tells you exactly what's broken and how to fix it.
Run standalone: python -m cascade_cracker.doctor
"""

import os, sys, shutil, subprocess, platform
from pathlib import Path
from . import config as cfg_mod

# ANSI
RED  = "\033[91m"; GRN  = "\033[92m"; YLW  = "\033[93m"
WH   = "\033[97m"; DIM  = "\033[2m";  B    = "\033[1m"; R = "\033[0m"

PASS = f"{GRN}{B}[PASS]{R}"
FAIL = f"{RED}{B}[FAIL]{R}"
WARN = f"{YLW}{B}[WARN]{R}"
INFO = f"{DIM}[INFO]{R}"


def _check(label: str, ok: bool, fail_msg: str = "", fix: str = "", warn: bool = False):
    icon = WARN if (warn and not ok) else (PASS if ok else FAIL)
    print(f"  {icon}  {label}")
    if not ok and fail_msg:
        print(f"         {RED}{fail_msg}{R}")
    if not ok and fix:
        print(f"         {DIM}Fix: {fix}{R}")
    return ok


def _section(title: str):
    print(f"\n  {WH}{B}── {title} {'─' * (44 - len(title))}{R}")


# ── individual checks ─────────────────────────────────────────────────────────

def check_python() -> bool:
    v = sys.version_info
    ok = v >= (3, 9)
    _check(f"Python {v.major}.{v.minor}.{v.micro}", ok,
           "Python 3.9+ required.",
           "Download from https://python.org")
    return ok


def check_tailscale_local() -> tuple[bool, str | None]:
    """Check Tailscale is running and get local IP."""
    ts = shutil.which("tailscale")
    if not ts:
        _check("Tailscale installed", False,
               "tailscale command not found.",
               "Download from https://tailscale.com/download and install.")
        return False, None
    _check("Tailscale installed", True)

    ip = cfg_mod.windows_tailscale_ip()
    ok = bool(ip)
    _check(f"Tailscale connected (this machine)", ok,
           "Not connected to Tailscale network.",
           "Run: tailscale up")
    if ok:
        print(f"         {DIM}This machine's Tailscale IP: {WH}{ip}{R}")
    return ok, ip


def check_windows_ssh_server() -> bool:
    """Check OpenSSH Server is installed and running on Windows."""
    if platform.system() != "Windows":
        return True  # not relevant on Linux/Mac

    try:
        result = subprocess.run(
            ["sc", "query", "sshd"],
            capture_output=True, text=True, timeout=5
        )
        running = "RUNNING" in result.stdout
        installed = result.returncode == 0

        _check("OpenSSH Server installed", installed,
               "OpenSSH Server feature not installed.",
               "Settings → Apps → Optional Features → Add: OpenSSH Server\n"
               "         Or run (Admin PowerShell): "
               "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")
        if installed:
            _check("OpenSSH Server running", running,
                   "Service installed but not running.",
                   "Run (Admin PowerShell):\n"
                   "         Start-Service sshd\n"
                   "         Set-Service -Name sshd -StartupType Automatic")
        return installed and running
    except Exception as e:
        _check("OpenSSH Server", False, str(e),
               "Run (Admin PowerShell): Get-Service sshd")
        return False


def check_windows_ssh_firewall() -> bool:
    """Check firewall allows inbound SSH."""
    if platform.system() != "Windows":
        return True
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=OpenSSH-Server-In-TCP"],
            capture_output=True, text=True, timeout=5
        )
        ok = result.returncode == 0 and "Enabled" in result.stdout and "Yes" in result.stdout
        _check("Firewall allows inbound SSH (port 22)", ok,
               "No firewall rule found for SSH.",
               "Run (Admin PowerShell):\n"
               "         New-NetFirewallRule -Name OpenSSH-Server-In-TCP "
               "-DisplayName 'OpenSSH Server' -Enabled True "
               "-Direction Inbound -Protocol TCP -Action Allow -LocalPort 22")
        return ok
    except Exception:
        _check("Firewall SSH rule", False, warn=True,
               fix="Verify manually in Windows Defender Firewall")
        return False


def check_pi_reachable(cfg: dict) -> bool:
    """Ping Pi via SSH and check it responds."""
    host = cfg.get("pi_host", "")
    key  = cfg.get("pi_ssh_key", "")
    user = cfg.get("pi_user", "kali")

    if not host:
        _check("Pi host configured", False,
               "pi_host is blank in config.",
               "Run cascade-crack → Configure to set the Pi's Tailscale IP.")
        return False
    _check(f"Pi host configured ({host})", True)

    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8",
           "-o", "BatchMode=yes"]
    if key and Path(key).exists():
        cmd += ["-i", key]
    cmd += [f"{user}@{host}", "echo ok"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        ok = result.returncode == 0 and "ok" in result.stdout
        _check(f"Pi SSH reachable ({host})", ok,
               f"Cannot connect: {result.stderr.strip() or 'timeout'}",
               "Ensure Pi is on and Tailscale is running on it: tailscale status")
        return ok
    except subprocess.TimeoutExpired:
        _check(f"Pi SSH reachable ({host})", False,
               "Connection timed out.",
               "Check Pi is powered on and connected to Tailscale.")
        return False
    except FileNotFoundError:
        _check(f"Pi SSH reachable", False,
               "ssh command not found.",
               "Install OpenSSH client: Settings → Apps → Optional Features → OpenSSH Client")
        return False


def check_pi_ssh_key(cfg: dict) -> bool:
    key = cfg.get("pi_ssh_key", "")
    if not key:
        discovered = cfg_mod.discover_ssh_key(cfg.get("pi_host", ""))
        if discovered:
            ok = True
            print(f"  {WARN}  SSH key not set in config — found: {WH}{discovered}{R}")
            print(f"         {DIM}Run cascade-crack → Configure to save this.{R}")
        else:
            _check("Pi SSH key", False,
                   "No SSH key found in ~/.ssh/",
                   "Generate one: ssh-keygen -t ed25519\n"
                   "         Then copy to Pi: ssh-copy-id kali@<pi-ip>")
        return bool(discovered)

    exists = Path(key).exists()
    _check(f"SSH key exists ({Path(key).name})", exists,
           f"Key file not found: {key}",
           "Check path or regenerate: ssh-keygen -t ed25519")
    return exists


def check_pi_tools(cfg: dict) -> dict[str, bool]:
    """SSH into Pi and check all required tools are installed."""
    ssh = cfg_mod.get_ssh_cmd(cfg)
    results = {}

    tools = {
        "nmap":                "sudo apt install nmap",
        "python3":             "sudo apt install python3",
        "hashcat":             "sudo apt install hashcat",
        "responder":           "sudo apt install responder  (or pip3 install responder)",
        "crackmapexec":        "sudo apt install crackmapexec  OR  pip3 install crackmapexec",
        "impacket-psexec":     "sudo apt install python3-impacket",
        "impacket-ntlmrelayx": "sudo apt install python3-impacket",
        "smbclient":           "sudo apt install smbclient",
        "sshpass":             "sudo apt install sshpass",
    }

    check_cmd = " && ".join(
        f"which {t} >/dev/null 2>&1 && echo '{t}:ok' || echo '{t}:missing'"
        for t in tools
    )

    try:
        result = subprocess.run(
            ssh + [check_cmd],
            capture_output=True, text=True, timeout=20
        )
        output = result.stdout
        for tool, fix in tools.items():
            ok = f"{tool}:ok" in output
            _check(f"Pi: {tool}", ok,
                   f"Not installed on Pi.",
                   f"On Pi: {fix}")
            results[tool] = ok
    except Exception as e:
        print(f"  {FAIL}  Pi tool check failed: {e}")
        results = {t: False for t in tools}

    return results


def check_pi_vault_path(cfg: dict) -> bool:
    """Check Pi vault directory exists and is writable."""
    ssh  = cfg_mod.get_ssh_cmd(cfg)
    path = cfg.get("pi_vault_path", "/root/.cascade/vault.json")
    parent = str(Path(path).parent)
    try:
        result = subprocess.run(
            ssh + [f"mkdir -p {parent} && test -w {parent} && echo ok || echo fail"],
            capture_output=True, text=True, timeout=10
        )
        ok = "ok" in result.stdout
        _check(f"Pi vault directory writable ({parent})", ok,
               "Directory not writable.",
               f"On Pi: sudo mkdir -p {parent} && sudo chown $USER {parent}")
        return ok
    except Exception:
        _check("Pi vault directory", False, warn=True)
        return False


def check_hashcat_local(cfg: dict) -> tuple[bool, str | None]:
    hc = cfg_mod.discover_hashcat(cfg)
    ok = bool(hc)
    _check("hashcat found", ok,
           "hashcat.exe not found.",
           "Download from https://hashcat.net/hashcat/ and extract anywhere.\n"
           "         Then run cascade-crack → Configure to set the path.")
    if ok:
        print(f"         {DIM}Found: {WH}{hc}{R}")

        # Test it actually runs
        try:
            result = subprocess.run(
                [hc, "--version"], capture_output=True, text=True, timeout=10,
                cwd=str(Path(hc).parent)
            )
            version = result.stdout.strip() or result.stderr.strip()
            print(f"         {DIM}Version: {version}{R}")
        except Exception:
            pass

        # Check GPU
        try:
            result = subprocess.run(
                [hc, "-I"], capture_output=True, text=True, timeout=15,
                cwd=str(Path(hc).parent)
            )
            has_gpu = "Device Type" in result.stdout and "GPU" in result.stdout
            _check("hashcat GPU detected", has_gpu,
                   "No GPU found — hashcat will run on CPU only (very slow).",
                   "Install GPU drivers and OpenCL runtime.",
                   warn=True)
        except Exception:
            pass

    return ok, hc


def check_rules_dir(cfg: dict) -> bool:
    hc   = cfg_mod.discover_hashcat(cfg)
    rdir = cfg_mod.discover_rules_dir(hc) or cfg.get("rules_dir", "")
    ok   = bool(rdir) and Path(rdir).is_dir()
    _check("hashcat rules directory", ok,
           "Rules dir not found — rules-based cracking disabled.",
           "Rules should be in the same folder as hashcat.exe (rules/ subfolder).",
           warn=True)
    if ok:
        best64 = Path(rdir) / "best64.rule"
        _check("best64.rule present", best64.exists(),
               "best64.rule missing — most important rule file.",
               "Re-download hashcat archive (rules/ folder should be included).",
               warn=True)
    return ok


def check_wordlist(cfg: dict) -> tuple[bool, str | None]:
    wl = cfg_mod.get_wordlist(cfg)
    ok = bool(wl)
    _check("rockyou.txt / wordlist found", ok,
           "No wordlist found in common locations.",
           "Download rockyou: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt\n"
           "         Save to: " + str(Path.home() / "wordlists" / "rockyou.txt"))
    if ok:
        size_mb = Path(wl).stat().st_size // (1024 * 1024)
        print(f"         {DIM}Found: {WH}{wl}{DIM}  ({size_mb} MB){R}")
    return ok, wl


def check_vault_sync(cfg: dict) -> bool:
    """Test pulling vault from Pi (non-destructive)."""
    ssh  = cfg_mod.get_ssh_cmd(cfg)
    path = cfg.get("pi_vault_path", "/root/.cascade/vault.json")
    try:
        result = subprocess.run(
            ssh + [f"test -f {path} && echo exists || echo missing"],
            capture_output=True, text=True, timeout=10
        )
        exists = "exists" in result.stdout
        _check(f"Pi vault file exists ({path})", exists,
               "Vault file not found on Pi — will be created on first Cascade run.",
               warn=not exists,
               fix="Run Cascade on Pi first to capture some hashes.")
        return True  # connectivity works even if vault doesn't exist yet
    except Exception as e:
        _check("Pi vault sync", False, str(e))
        return False


# ── main report ───────────────────────────────────────────────────────────────

def run_full_check(cfg: dict) -> dict[str, bool]:
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""
  {RED}{B}╔══════════════════════════════════════════╗
  ║   CASCADE DOCTOR — System Diagnostics    ║
  ╚══════════════════════════════════════════╝{R}
""")

    results = {}

    _section("LOCAL ENVIRONMENT")
    results["python"]         = check_python()
    results["tailscale"]      = check_tailscale_local()[0]
    results["openssh_server"] = check_windows_ssh_server()
    results["ssh_firewall"]   = check_windows_ssh_firewall()

    _section("HASHCAT (GPU CRACKING)")
    hc_ok, _                 = check_hashcat_local(cfg)
    results["hashcat"]        = hc_ok
    results["rules"]          = check_rules_dir(cfg)
    results["wordlist"]       = check_wordlist(cfg)[0]

    _section("PI CONNECTION")
    results["ssh_key"]        = check_pi_ssh_key(cfg)
    pi_ok                     = check_pi_reachable(cfg)
    results["pi_reachable"]   = pi_ok

    if pi_ok:
        _section("PI TOOLS (checking remotely)")
        tool_results           = check_pi_tools(cfg)
        results["pi_tools"]    = all(tool_results.values())
        results["pi_vault"]    = check_pi_vault_path(cfg)
        results["vault_sync"]  = check_vault_sync(cfg)

    # ── summary ───────────────────────────────────────────────────────────────
    total   = len(results)
    passing = sum(results.values())
    failing = total - passing

    print(f"\n  {'─' * 50}")
    if failing == 0:
        print(f"\n  {GRN}{B}All checks passed! ({total}/{total}){R}")
        print(f"\n  {DIM}Cascade + CascadeCracker are fully configured.{R}")
        print(f"  {DIM}Run {WH}cascade-crack{DIM} to start cracking.{R}")
    else:
        print(f"\n  {YLW}{B}{passing}/{total} checks passed — {failing} issue(s) need attention.{R}")
        print(f"\n  {DIM}Fix the items marked {R}{RED}{B}[FAIL]{R}{DIM} above and re-run: "
              f"{WH}cascade-doctor{R}")

    # Quick-fix hints
    if not results.get("openssh_server") and platform.system() == "Windows":
        print(f"""
  {WH}{B}Quick-fix: Enable SSH server on this PC (run in Admin PowerShell):{R}
  {DIM}Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Start-Service sshd
  Set-Service -Name sshd -StartupType Automatic
  New-NetFirewallRule -Name OpenSSH-Server-In-TCP -DisplayName 'OpenSSH Server' \\
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22{R}""")

    if not results.get("tailscale"):
        print(f"\n  {WH}{B}Quick-fix: Install Tailscale{R}")
        print(f"  {DIM}https://tailscale.com/download  →  install  →  tailscale up{R}")
        print(f"  {DIM}Also install on Pi: curl -fsSL https://tailscale.com/install.sh | sh{R}")

    if not results.get("hashcat"):
        print(f"\n  {WH}{B}Quick-fix: Get hashcat{R}")
        print(f"  {DIM}https://hashcat.net/hashcat/  →  extract to ~/Downloads/hashcat-*/  →  re-run doctor{R}")

    if not results.get("wordlist"):
        print(f"\n  {WH}{B}Quick-fix: Download rockyou.txt{R}")
        wordlist_dir = Path.home() / "wordlists"
        print(f"  {DIM}mkdir {wordlist_dir}{R}")
        print(f"  {DIM}Download rockyou.txt and place it there.{R}")
        print(f"  {DIM}Direct link: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt{R}")

    print()
    return results


def main():
    cfg = cfg_mod.load()
    cfg = cfg_mod.auto_populate(cfg)
    cfg_mod.save(cfg)
    run_full_check(cfg)
    input(f"  {DIM}[ press Enter to exit ]{R}")


if __name__ == "__main__":
    main()
