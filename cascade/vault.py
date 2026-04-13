"""
vault.py — Persistent store for captured hashes and cracked credentials.

Stored at ~/.cascade/vault.json
Schema per entry:
  {
    "id":        str  (uuid4 short),
    "ts":        str  (ISO timestamp),
    "target_ip": str,
    "username":  str,
    "domain":    str,
    "hash":      str  (full hash line, ready for hashcat),
    "hash_type": str  ("NTLMv2", "NTLMv1", "NTLM", ...),
    "hc_mode":   int  (hashcat -m value),
    "status":    str  ("pending" | "cracked" | "exhausted"),
    "password":  str | None,
    "cracked_ts": str | None,
  }
"""

import json, os, uuid, time
from . import tui

VAULT_DIR  = os.path.expanduser("~/.cascade")
VAULT_FILE = os.path.join(VAULT_DIR, "vault.json")

# Map hash type label → hashcat mode
HC_MODES = {
    "NTLMv2": 5600,
    "NTLMv1": 5500,
    "NTLM":   1000,
    "WPA":    2500,
    "WPA2":   22000,
    "MD5":    0,
    "SHA1":   100,
}


def _ensure_dir():
    os.makedirs(VAULT_DIR, exist_ok=True)


def _load() -> list[dict]:
    _ensure_dir()
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save(entries: list[dict]):
    _ensure_dir()
    with open(VAULT_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ── write ─────────────────────────────────────────────────────────────────────

def add_hash(target_ip: str, username: str, domain: str,
             hash_line: str, hash_type: str = "NTLMv2") -> str:
    """
    Add a new captured hash to the vault.
    Returns the entry id.
    Deduplicates by username+domain+target (keeps latest).
    """
    entries = _load()
    # Remove stale duplicate
    entries = [e for e in entries
               if not (e["username"] == username and
                       e["domain"]   == domain   and
                       e["target_ip"] == target_ip)]
    entry_id = uuid.uuid4().hex[:8]
    entries.append({
        "id":         entry_id,
        "ts":         _ts(),
        "target_ip":  target_ip,
        "username":   username,
        "domain":     domain,
        "hash":       hash_line,
        "hash_type":  hash_type,
        "hc_mode":    HC_MODES.get(hash_type, 5600),
        "status":     "pending",
        "password":   None,
        "cracked_ts": None,
    })
    _save(entries)
    return entry_id


def mark_cracked(entry_id: str, password: str):
    """Record a successfully cracked password."""
    entries = _load()
    for e in entries:
        if e["id"] == entry_id:
            e["status"]     = "cracked"
            e["password"]   = password
            e["cracked_ts"] = _ts()
            break
    _save(entries)


def mark_exhausted(entry_id: str):
    entries = _load()
    for e in entries:
        if e["id"] == entry_id:
            e["status"] = "exhausted"
            break
    _save(entries)


def add_hash_list(hashes: list[str], target_ip: str = "unknown") -> list[str]:
    """
    Bulk-add a list of raw NTLMv2 hash strings (Responder format).
    Returns list of entry ids.
    """
    ids = []
    for h in hashes:
        # NTLMv2 format: USER::DOMAIN:challenge:response:blob
        parts = h.split("::")
        if len(parts) >= 2:
            username = parts[0]
            rest     = parts[1].split(":", 1)
            domain   = rest[0] if rest else "unknown"
        else:
            username = "unknown"
            domain   = "unknown"
        eid = add_hash(target_ip, username, domain, h, "NTLMv2")
        ids.append(eid)
    return ids


# ── read ──────────────────────────────────────────────────────────────────────

def all_entries() -> list[dict]:
    return _load()


def pending_hashes() -> list[dict]:
    return [e for e in _load() if e["status"] == "pending"]


def cracked_entries() -> list[dict]:
    return [e for e in _load() if e["status"] == "cracked"]


def export_hash_file(path: str = None, status_filter: str = "pending") -> str:
    """
    Write hash lines to a file for external cracking (e.g. CascadeCracker).
    Returns the file path written.
    """
    entries = [e for e in _load() if e["status"] == status_filter]
    if not entries:
        return None
    out_path = path or os.path.join(VAULT_DIR, "export_hashes.txt")
    with open(out_path, "w") as f:
        for e in entries:
            f.write(e["hash"] + "\n")
    return out_path


def import_cracked_file(path: str) -> int:
    """
    Read a hashcat potfile or cracked output and update vault.
    Hashcat pot format:  HASH:PASSWORD  (last colon is separator)
    Returns number of entries updated.
    """
    if not os.path.exists(path):
        return 0
    entries  = _load()
    updated  = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Last colon separates hash from password
            idx = line.rfind(":")
            if idx < 0:
                continue
            hash_part = line[:idx].upper()
            password  = line[idx+1:]
            for e in entries:
                if e["hash"].upper() in hash_part or hash_part in e["hash"].upper():
                    e["status"]     = "cracked"
                    e["password"]   = password
                    e["cracked_ts"] = _ts()
                    updated += 1
                    break
    if updated:
        _save(entries)
    return updated


# ── display ───────────────────────────────────────────────────────────────────

def print_hashes(entries: list[dict] = None):
    rows = entries if entries is not None else _load()
    if not rows:
        tui.warn("No hashes in vault.")
        return
    print(f"\n  {tui.WH}{tui.B}{'#':<4} {'TIME':<20} {'IP':<16} {'USER':<30} {'TYPE':<8} STATUS{tui.R}")
    tui.divider()
    for i, e in enumerate(rows, 1):
        status_col = (tui.GRN + "CRACKED"  + tui.R if e["status"] == "cracked"  else
                      tui.RED + "pending"  + tui.R if e["status"] == "pending"  else
                      tui.DIM + "exhausted"+ tui.R)
        user_str = f"{e['domain']}\\{e['username']}" if e["domain"] else e["username"]
        print(
            f"  {tui.DIM}{i:<4}{tui.R}"
            f"{tui.DIM}{e['ts']:<20}{tui.R}"
            f"{tui.WH}{e['target_ip']:<16}{tui.R}"
            f"{tui.YLW}{user_str:<30}{tui.R}"
            f"{tui.DIM}{e['hash_type']:<8}{tui.R}"
            f"{status_col}"
        )
    print()


def print_cracked(entries: list[dict] = None):
    rows = entries if entries is not None else cracked_entries()
    if not rows:
        tui.warn("No cracked passwords yet.")
        return
    print(f"\n  {tui.WH}{tui.B}{'#':<4} {'CRACKED AT':<20} {'IP':<16} {'USER':<30} {'PASSWORD'}{tui.R}")
    tui.divider()
    for i, e in enumerate(rows, 1):
        user_str = f"{e['domain']}\\{e['username']}" if e["domain"] else e["username"]
        print(
            f"  {tui.DIM}{i:<4}{tui.R}"
            f"{tui.DIM}{e.get('cracked_ts',''):<20}{tui.R}"
            f"{tui.WH}{e['target_ip']:<16}{tui.R}"
            f"{tui.YLW}{user_str:<30}{tui.R}"
            f"{tui.GRN}{tui.B}{e['password']}{tui.R}"
        )
    print()
