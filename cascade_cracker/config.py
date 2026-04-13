"""
config.py — All path discovery and configuration for CascadeCracker.

No hardcoded user-specific paths anywhere. Everything is either:
  - discovered from PATH / common system locations
  - stored in ~/.cascade/config.json (created on first run)
  - prompted from the user via the doctor/setup flow
"""

import json, os, shutil, subprocess
from pathlib import Path

# ── storage root ──────────────────────────────────────────────────────────────
# ~/.cascade/ on all platforms (Windows: C:\Users\<user>\.cascade\)

CASCADE_DIR  = Path.home() / ".cascade"
CONFIG_FILE  = CASCADE_DIR / "config.json"
VAULT_FILE   = CASCADE_DIR / "vault.json"
EXPORT_FILE  = CASCADE_DIR / "export_hashes.txt"

# ── defaults ──────────────────────────────────────────────────────────────────

DEFAULTS = {
    # Pi connection
    "pi_host":       "100.119.123.7",
    "pi_user":       "kali",
    "pi_ssh_key":    "",          # auto-discovered if blank
    "pi_vault_path": "/root/.cascade/vault.json",

    # Windows SSH (for Pi → Windows)
    "windows_ssh_user": "",       # auto = current user
    "windows_ssh_port": 22,

    # hashcat
    "hashcat_path":  "",          # auto-discovered if blank
    "rules_dir":     "",          # auto-discovered from hashcat location

    # wordlists (checked in order)
    "wordlists": [],              # populated by discover_wordlists()

    # crack settings
    "rules_progression": ["best64.rule", "d3ad0ne.rule", "dive.rule"],
    "gpu_timeout":       600,
}

# Common wordlist search paths (cross-platform)
_WORDLIST_SEARCH = [
    Path.home() / "wordlists" / "rockyou.txt",
    Path.home() / "Downloads" / "rockyou.txt",
    Path.home() / "Documents" / "rockyou.txt",
    Path("C:/tools/wordlists/rockyou.txt"),
    Path("C:/wordlists/rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt"),
]

# Common hashcat search paths on Windows
_HASHCAT_SEARCH = [
    Path.home() / "Downloads",
    Path.home() / "tools",
    Path("C:/tools"),
    Path("C:/hashcat"),
    Path("C:/Program Files/hashcat"),
]


# ── load / save ───────────────────────────────────────────────────────────────

def load() -> dict:
    CASCADE_DIR.mkdir(parents=True, exist_ok=True)
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            saved = json.loads(CONFIG_FILE.read_text())
            cfg.update(saved)
        except Exception:
            pass
    return cfg


def save(cfg: dict):
    CASCADE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ── auto-discovery ────────────────────────────────────────────────────────────

def discover_hashcat(cfg: dict) -> str | None:
    """Find hashcat executable. Returns path or None."""
    # 1. Stored in config
    if cfg.get("hashcat_path") and Path(cfg["hashcat_path"]).exists():
        return cfg["hashcat_path"]

    # 2. In PATH
    found = shutil.which("hashcat") or shutil.which("hashcat.exe")
    if found:
        return found

    # 3. Search common dirs for hashcat.exe or hashcat-*/hashcat.exe
    for base in _HASHCAT_SEARCH:
        if not base.exists():
            continue
        # Direct
        for name in ("hashcat.exe", "hashcat"):
            p = base / name
            if p.exists():
                return str(p)
        # Subdirs named hashcat-*
        for sub in sorted(base.glob("hashcat-*"), reverse=True):
            for name in ("hashcat.exe", "hashcat"):
                p = sub / name
                if p.exists():
                    return str(p)

    return None


def discover_rules_dir(hashcat_path: str | None) -> str | None:
    """Find hashcat rules directory from the hashcat binary location."""
    if not hashcat_path:
        return None
    candidates = [
        Path(hashcat_path).parent / "rules",
        Path(hashcat_path).parent.parent / "rules",
        Path("/usr/share/hashcat/rules"),
    ]
    for c in candidates:
        if c.is_dir():
            return str(c)
    return None


def discover_wordlists() -> list[str]:
    """Return all existing wordlist paths from search list."""
    return [str(p) for p in _WORDLIST_SEARCH if p.exists()]


def discover_ssh_key(pi_host: str) -> str | None:
    """Find best SSH key for connecting to Pi."""
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return None

    # Check ~/.ssh/config for a matching host entry
    config_file = ssh_dir / "config"
    if config_file.exists():
        content = config_file.read_text()
        # Find IdentityFile for pi host
        in_pi_block = False
        for line in content.splitlines():
            l = line.strip()
            if l.lower().startswith("host "):
                in_pi_block = pi_host in l or "pi" in l.lower()
            elif in_pi_block and l.lower().startswith("identityfile"):
                key = l.split(None, 1)[1].replace("~", str(Path.home()))
                if Path(key).exists():
                    return key

    # Fallback: try common key names
    for name in ("pi_zero", "id_rsa", "id_ed25519", "id_ecdsa"):
        key = ssh_dir / name
        if key.exists():
            return str(key)

    return None


def auto_populate(cfg: dict) -> dict:
    """Fill in any blank auto-discoverable fields. Does not overwrite user-set values."""
    if not cfg.get("hashcat_path"):
        cfg["hashcat_path"] = discover_hashcat(cfg) or ""

    if not cfg.get("rules_dir"):
        cfg["rules_dir"] = discover_rules_dir(cfg.get("hashcat_path")) or ""

    if not cfg.get("wordlists"):
        cfg["wordlists"] = discover_wordlists()

    if not cfg.get("pi_ssh_key"):
        cfg["pi_ssh_key"] = discover_ssh_key(cfg.get("pi_host", "")) or ""

    if not cfg.get("windows_ssh_user"):
        cfg["windows_ssh_user"] = os.environ.get("USERNAME") or os.environ.get("USER") or ""

    return cfg


def get_wordlist(cfg: dict) -> str | None:
    """Return first existing wordlist path."""
    for wl in cfg.get("wordlists", []):
        if Path(wl).exists():
            return wl
    return None


def get_ssh_cmd(cfg: dict) -> list[str]:
    """Build base SSH command list for connecting to Pi."""
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
           "-o", "BatchMode=yes"]
    key = cfg.get("pi_ssh_key", "")
    if key and Path(key).exists():
        cmd += ["-i", key]
    cmd.append(f"{cfg['pi_user']}@{cfg['pi_host']}")
    return cmd


def windows_tailscale_ip() -> str | None:
    """Get this machine's Tailscale IP."""
    try:
        out = subprocess.check_output(
            ["tailscale", "ip", "--4"], text=True,
            stderr=subprocess.DEVNULL, timeout=5
        ).strip()
        return out if out else None
    except Exception:
        return None
