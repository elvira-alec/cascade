"""
logger.py — File-based logging for Cascade.

All tui.info/warn/error/success calls automatically write here.
Subprocess output logged separately for debugging silent failures.

Log location: ~/.cascade/cascade.log
"""

import os, time
from pathlib import Path

LOG_DIR  = Path.home() / ".cascade"
LOG_FILE = LOG_DIR / "cascade.log"
_MAX_BYTES = 5 * 1024 * 1024  # 5 MB — rotate when exceeded


def _write(level: str, msg: str):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # Rotate if too large
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > _MAX_BYTES:
            LOG_FILE.rename(LOG_FILE.with_suffix(".log.1"))
    except Exception:
        pass
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level:<8}] {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass  # never crash the main program due to logging


def info(msg: str):    _write("INFO",    msg)
def success(msg: str): _write("SUCCESS", msg)
def warn(msg: str):    _write("WARN",    msg)
def error(msg: str):   _write("ERROR",   msg)


def subprocess_output(tool: str, cmd_args: list, returncode: int, output: str):
    """Log full subprocess invocation + output. Use for any tool that might fail silently."""
    header = f"{tool}  rc={returncode}  cmd={' '.join(str(a) for a in cmd_args)}"
    _write("PROC", f"{header}\n{output[:3000]}")


def tail(n: int = 60) -> list[str]:
    """Return last n lines of the log file."""
    if not LOG_FILE.exists():
        return ["(log is empty)"]
    lines = LOG_FILE.read_text(errors="replace").splitlines()
    return lines[-n:]


def path() -> str:
    return str(LOG_FILE)
