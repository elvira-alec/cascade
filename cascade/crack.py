"""
crack.py — Hash cracking via hashcat / john
"""

import subprocess, os, tempfile
from . import tui

WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/wordlists/fasttrack.txt",
]

def _find_wordlist() -> str:
    for w in WORDLISTS:
        if os.path.exists(w):
            return w
    return None


def crack_ntlmv2(hashes: list[str], wordlist: str = None) -> list[dict]:
    """
    Crack NTLMv2 hashes with hashcat (mode 5600).
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

    cmd = [
        "hashcat", "-m", "5600",
        "-a", "0",                      # dictionary
        "--potfile-path", pot_file,
        "--quiet",
        "--status", "--status-timer=5",
        hash_file, wl,
        "--force",                       # ignore CUDA warnings on Pi
    ]

    try:
        subprocess.run(cmd, timeout=600)
    except FileNotFoundError:
        tui.warn("hashcat not found — trying john ...")
        return _crack_john(hashes, wl, hash_file, pot_file)
    except subprocess.TimeoutExpired:
        tui.warn("hashcat timed out — partial results may exist")

    return _read_pot(pot_file, hashes)


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
