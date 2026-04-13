# Cascade

**Automated network attack toolkit — two programs, two machines.**

| Program | Machine | Install |
|---------|---------|---------|
| `cascade` | Raspberry Pi (Kali) | `pip install -e .` |
| `cascade-crack` | Windows PC (GPU) | `pip install -e ./cracker` |

```bash
# On Pi:
git clone https://github.com/elvira-alec/cascade
cd cascade
sudo pip3 install -e .
sudo cascade

# On Windows PC:
git clone https://github.com/elvira-alec/cascade
cd cascade
pip install -e ./cracker
cascade-crack
cascade-doctor   # check dependencies + Tailscale setup
```

> For authorized penetration testing only. Only run against networks and systems you own or have explicit written permission to test.

---

## What it does

Cascade automates the internal network kill chain — guided, menu-driven, with confirmation at every stage so you control the noise level. It chains five stages from subnet discovery to live shells.

```
CASCADE v1.0.0

  Interface : eth0    IP: 192.168.1.50    Subnet: 192.168.1.0/24
  Adapter   : wlan1   Mode: MANAGED       Target: all hosts

   1  Full kill chain    guided: recon → harvest → spray → crack → lateral → shells
   2  Recon              nmap scan — find hosts, ports, services
   3  Hash harvest       Responder — capture NTLMv2 hashes passively
   4  Cred spray         SSH / SMB / HTTP default credential spray
   5  Crack hashes       hashcat NTLMv2 against wordlist
   6  Lateral movement   CrackMapExec + SSH with found credentials

   7  Shell manager      connect to compromised hosts
   8  Saved sessions     reconnect to saved sessions

   s  Setup    f  Free commands (bash)    h  Help    q  Quit
```

---

## The kill chain

| Stage | Name | Noise | What it does |
|-------|------|-------|-------------|
| 1 | **Recon** | LOW | nmap sweeps subnet — hosts, ports, services, OS |
| 2 | **Hash Harvest** | MEDIUM | Responder poisons LLMNR/NBT-NS — Windows machines hand over NTLMv2 hashes |
| 3 | **Cred Spray** | MEDIUM | Default credentials (admin/admin, root/root...) vs SSH, SMB, HTTP |
| 4 | **Hash Cracking** | ZERO | hashcat locally against rockyou.txt — no network traffic |
| 5 | **Lateral Movement** | HIGH | CrackMapExec + SSH pivoting with every valid credential |

Each stage shows what it will do and asks for confirmation. You can skip any stage or stop the chain early.

---

## Adapter state

Cascade uses a LAN interface in **MANAGED** mode — normal operation. Do not put your interface in monitor mode, as Responder and nmap both need standard managed networking. Monitor mode is for WiFi capture tools (Fracture, wifite, airgeddon).

Your interface must have an IP on the target LAN before running. If it doesn't:

- **Ethernet** — plug into any switch port, DHCP assigns an IP automatically
- **WiFi** — Setup → option 9 launches `nmtui` for interactive WiFi connection
- **Evil twin first** — use airgeddon/portal_cloner to get the WiFi password, then connect

---

## Shell manager

After lateral movement, Cascade opens a shell manager. It only shows connection methods that are available based on open ports and installed tools:

| Method | Requires |
|--------|---------|
| CMD shell (psexec / SYSTEM) | port 445 + `impacket-psexec` |
| CMD shell (wmiexec / user) | port 445 + `impacket-wmiexec` |
| PowerShell (evil-winrm) | port 5985 + `evil-winrm` |
| SSH shell | port 22 + `sshpass` |
| Browse SMB files | port 445 + `smbclient` |

Sessions are saved to `~/.cascade_sessions.json`. Reconnect anytime with `sudo cascade` → option 8.

---

## Setup menu

Press `s` from the main menu:

| Option | What it does |
|--------|-------------|
| 1 | Change adapter (re-runs startup wizard — auto-fixes modes) |
| 2 | Scan WiFi + connect (scan nearby networks, pick, enter password) |
| 3 | Connect via nmtui (full interactive network manager) |
| 4 | Set subnet manually (default: auto-detect) |
| 5 | Set specific target host (default: whole subnet) |
| 6 | Set Responder window in seconds (default: 120) |
| 7 | Custom wordlist for cracking |
| 8 | Toggle skip-harvest (quiet mode) |
| 9 | Toggle verbose output |
| 10 | Show which required tools are installed |

---

## Install

```bash
git clone https://github.com/your-username/Cascade
cd Cascade
sudo pip3 install -e .
```

Required tools (Kali / Debian):
```bash
sudo apt install nmap responder hashcat crackmapexec sshpass smbclient python3-impacket
sudo gem install evil-winrm
# mitm6 (optional — requires IPv6 on the network):
sudo pip3 install mitm6 --break-system-packages
```

`sudo cascade` — root is required for Responder and raw sockets.

---

## Vault & GPU offload

All captured hashes and cracked passwords live in `~/.cascade/vault.json` (root: `/root/.cascade/vault.json`).

From the main menu, press `v` to open the vault:

```
[1] View hashes        — all captured, with timestamp and target IP
[2] View cracked       — cracked creds ready to use
[3] Export for GPU     — writes pending hashes to ~/.cascade/export_hashes.txt
[4] Import cracked     — reads results back from CascadeCracker on Windows
[5] Shell from vault   — connect to any host with cracked creds
```

**[CascadeCracker](https://github.com/your-username/CascadeCracker)** runs on your Windows GPU machine and automates the pull → crack → push cycle over Tailscale.

---

## Remote use (phone → Pi → Windows)

1. Install [Tailscale](https://tailscale.com) on Pi and Windows, log into same account.
2. Enable Windows OpenSSH Server (`cascade-doctor` on Windows walks you through it).
3. From Pi: `ssh <windows-user>@<windows-tailscale-ip>`
4. In Termius on phone: add Pi as SSH host, use it as jump host to reach Windows.

This gives you full GPU cracking power from anywhere via phone.

---

## Project structure

```
cascade/
├── __main__.py   # entry point, main menu, kill chain orchestration
├── tui.py        # terminal UI — red banner, status functions
├── iface.py      # interface detection, adapter mode switching, nmtui
├── recon.py      # nmap subnet scanner
├── harvest.py    # Responder wrapper + NTLMv2 hash capture
├── spray.py      # default credential spray (SSH, SMB, HTTP)
├── crack.py      # hashcat / john NTLMv2 cracker
├── lateral.py    # CrackMapExec + SSH lateral movement
└── shells.py     # interactive shell manager + session persistence
```

---

## Legal

This tool is for **authorized security testing only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author accepts no liability for misuse.
