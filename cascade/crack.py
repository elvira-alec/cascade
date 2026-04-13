"""
crack.py — Hash cracking via hashcat / john

On the Pi (CPU only): attempts plain rockyou with a time cap.
Uncracked hashes are saved to vault with status=pending for GPU offload.
Full rules-based escalation (best64 → d3ad0ne → dive) runs on CascadeCracker (GPU).
"""

import subprocess, os, tempfile
from . import tui, vault as _vault

WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/wordlists/fasttrack.txt",
]

# Rules applied in order after plain dictionary — stops as soon as any hash cracks.
# best64 covers ~90% of real-world passwords (append numbers, leet, capitalize, etc.)
# d3ad0ne goes deeper (~50 k rules); dive is near-exhaustive but slow.
_RULES_PROGRESSION = [
    "best64.rule",
    "d3ad0ne.rule",
    "dive.rule",
]

def _find_wordlist() -> str:
    for w in WORDLISTS:
        if os.path.exists(w):
            return w
    return None


def _hashcat_rules_dir() -> str:
    """Return the hashcat rules directory, or None if not found."""
    import shutil
    exe = shutil.which("hashcat")
    if not exe:
        return None
    # Common locations
    candidates = [
        os.path.join(os.path.dirname(exe), "rules"),
        "/usr/share/hashcat/rules",
        "/usr/lib/hashcat/rules",
        os.path.expanduser("~/.hashcat/rules"),
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return None


def crack_ntlmv2(hashes: list[str], wordlist: str = None) -> list[dict]:
    """
    Crack NTLMv2 hashes with hashcat (mode 5600).
    First tries plain dictionary attack; if no passwords found, automatically
    escalates through rules-based attacks (best64 → d3ad0ne → dive).
    Returns list of { hash, user, password }.
    """
    if not hashes:
        return []

    wl = wordlist or _find_wordlist()
    if not wl:
        tui.warn("No wordlist found. Install rockyou: sudo gunzip /usr/share/wordlists/rockyou.txt.gz")
        return []

    # Write hashes to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hashes", delete=False) as f:
        f.write("\n".join(hashes))
        hash_file = f.name

    pot_file = hash_file + ".pot"

    tui.info(f"Cracking {len(hashes)} NTLMv2 hash(es) with hashcat ...")

    # ── Pass 1: plain dictionary ──────────────────────────────────────────────
    cmd = [
        "hashcat", "-m", "5600",
        "-a", "0",
        "--potfile-path", pot_file,
        "--quiet",
        "--status", "--status-timer=5",
        hash_file, wl,
        "--force",
    ]

    try:
        subprocess.run(cmd, timeout=600)
    except FileNotFoundError:
        tui.warn("hashcat not found — trying john ...")
        return _crack_john(hashes, wl, hash_file, pot_file)
    except subprocess.TimeoutExpired:
        tui.warn("hashcat timed out — partial results may exist")

    cracked = _read_pot(pot_file, hashes)
    if cracked:
        return cracked

    # ── Pass 2+: rules-based escalation ──────────────────────────────────────
    rules_dir = _hashcat_rules_dir()
    if not rules_dir:
        tui.warn("hashcat rules directory not found — skipping rules-based attack")
        return cracked

    for rule_file in _RULES_PROGRESSION:
        rule_path = os.path.join(rules_dir, rule_file)
        if not os.path.exists(rule_path):
            continue
        tui.info(f"Dictionary exhausted — trying rules: {rule_file} ...")
        cmd_rules = [
            "hashcat", "-m", "5600",
            "-a", "0",
            "--potfile-path", pot_file,
            "--quiet",
            "--status", "--status-timer=5",
            hash_file, wl,
            "-r", rule_path,
            "--force", "-O",
        ]
        try:
            subprocess.run(cmd_rules, timeout=600)
        except subprocess.TimeoutExpired:
            tui.warn(f"{rule_file} timed out — partial results may exist")

        cracked = _read_pot(pot_file, hashes)
        if cracked:
            tui.success(f"Cracked with {rule_file}!")
            return cracked

    return cracked


def crack_ntlmv2_quick(hashes: list[str], target_ip: str = "unknown",
                       cpu_timeout: int = 90) -> list[dict]:
    """
    Pi-friendly crack: plain rockyou only, hard CPU timeout.
    Saves ALL hashes to vault (cracked or pending for GPU export).
    Returns cracked entries.
    """
    if not hashes:
        return []

    # Register all hashes in vault first
    entry_ids = _vault.add_hash_list(hashes, target_ip)

    wl = _find_wordlist()
    if not wl:
        tui.warn("No wordlist — hashes saved to vault for GPU cracking.")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".hashes", delete=False) as f:
        f.write("\n".join(hashes))
        hash_file = f.name
    pot_file = hash_file + ".pot"

    tui.info(f"Quick CPU crack ({cpu_timeout}s limit) — {len(hashes)} hash(es) ...")

    cmd = ["hashcat", "-m", "5600", "-a", "0",
           "--potfile-path", pot_file, "--quiet",
           hash_file, wl, "--force"]
    try:
        subprocess.run(cmd, timeout=cpu_timeout)
    except FileNotFoundError:
        tui.warn("hashcat not found — hashes queued for GPU cracking.")
        return []
    except subprocess.TimeoutExpired:
        tui.warn(f"CPU timeout ({cpu_timeout}s) — uncracked hashes queued for GPU.")

    cracked = _read_pot(pot_file, hashes)

    # Update vault with results
    for c in cracked:
        for eid, h in zip(entry_ids, hashes):
            if h.upper().startswith(c["user"].upper() + "::"):
                _vault.mark_cracked(eid, c["password"])
                break

    uncracked = len(hashes) - len(cracked)
    if uncracked:
        tui.info(f"  {uncracked} hash(es) not cracked — saved as pending for GPU export")

    return cracked


def _crack_john(hashes, wordlist, hash_file, pot_file):
    cmd = ["john", "--format=netntlmv2", f"--wordlist={wordlist}", hash_file]
    try:
        subprocess.run(cmd, timeout=600)
    except FileNotFoundError:
        tui.error("Neither hashcat nor john found — cannot crack hashes.")
        tui.info("Install: sudo apt install hashcat john")
        return []
    except subprocess.TimeoutExpired:
        pass

    # john --show
    try:
        out = subprocess.check_output(
            ["john", "--show", "--format=netntlmv2", hash_file], text=True
        )
        results = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                results.append({"user": parts[0], "password": parts[1], "hash": line})
        return results
    except Exception:
        return []


def _read_pot(pot_file: str, original_hashes: list[str]) -> list[dict]:
    if not os.path.exists(pot_file):
        return []
    cracked = []
    with open(pot_file) as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                parts  = line.rsplit(":", 1)
                hash_  = parts[0]
                passwd = parts[1]
                # Extract user from hash (NTLMv2 format: USER::DOMAIN:...)
                user   = hash_.split("::")[0] if "::" in hash_ else "?"
                cracked.append({"hash": hash_, "user": user, "password": passwd})
                tui.success(f"Cracked: {tui.YLW}{user}{tui.R} → {tui.GRN}{passwd}{tui.R}")
    return cracked
