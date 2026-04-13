"""
Cascade — unified launcher.
Run on any machine: chooses Attack mode (Pi/Linux) or Crack mode (Windows/GPU).
"""

import os, sys, platform

RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
WH  = "\033[97m"; DIM = "\033[2m";  B   = "\033[1m"; R = "\033[0m"

_BANNER = f"""
  {RED}{B}╔══════════════════════════════════════════════╗
  ║   CASCADE  —  Network Attack Toolkit  v1.0  ║
  ╚══════════════════════════════════════════════╝{R}
"""

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(_BANNER)

    is_windows = platform.system() == "Windows"
    default    = "2" if is_windows else "1"

    print(f"  {WH}{B}Select mode:{R}\n")
    print(f"  {RED}{B}1{R}  {WH}Attack mode{R}   {DIM}Raspberry Pi / Linux — recon, harvest hashes, crack, shells{R}")
    print(f"  {RED}{B}2{R}  {WH}Crack mode{R}    {DIM}Windows / GPU machine — GPU hash cracking, vault sync{R}")
    print()
    if is_windows:
        print(f"  {DIM}(Windows detected — defaulting to Crack mode){R}")
    else:
        print(f"  {DIM}(Linux detected — defaulting to Attack mode){R}")
    print()

    try:
        raw = input(f"  {WH}{B}→ [{default}]: {R}").strip() or default
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {DIM}bye.{R}\n")
        sys.exit(0)

    if raw == "1":
        # Attack mode — requires Linux/root; warn if on Windows
        if is_windows:
            print(f"\n  {YLW}Warning: Attack mode is designed for Linux (Raspberry Pi / Kali).{R}")
            print(f"  {DIM}Tools like Responder and nmap need root on Linux.{R}")
            c = input(f"  Continue anyway? [y/N]: ").strip().lower()
            if c != "y":
                sys.exit(0)
        from cascade._attack_main import main as _attack
        _attack()

    elif raw == "2":
        # Crack mode — works on any OS but GPU acceleration best on Windows
        if not is_windows:
            print(f"\n  {YLW}Note: Crack mode works on Linux but GPU acceleration is faster on Windows.{R}")
            c = input(f"  Continue? [Y/n]: ").strip().lower()
            if c == "n":
                sys.exit(0)
        try:
            from cascade_cracker.cracker import main as _crack
        except ImportError:
            print(f"\n  {RED}cascade_cracker package not found.{R}")
            print(f"  {DIM}Make sure you installed from the repo root:{R}")
            print(f"  {WH}    pip install -e .\n{R}")
            sys.exit(1)
        _crack()

    else:
        print(f"\n  {YLW}Invalid choice.{R}")
        sys.exit(1)


if __name__ == "__main__":
    main()
