# Cascade

**Menu-driven post-exploitation kill chain orchestrator.**  
Run it once you're on the LAN. It guides you through everything.

```
sudo cascade
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
| 1 | Select LAN interface (eth0, wlan0, etc.) |
| 2 | Switch adapter mode (managed ↔ monitor) |
| 3 | Set subnet manually (default: auto-detect) |
| 4 | Set specific target host (default: whole subnet) |
| 5 | Set Responder window in seconds (default: 120) |
| 6 | Custom wordlist for cracking |
| 7 | Toggle skip-harvest (quiet mode) |
| 8 | Toggle verbose output |
| 9 | Connect to network (launches nmtui) |
| 10 | Show which required tools are installed |

---

## Install

```bash
git clone https://github.com/elvira-alec/cascade
cd cascade
sudo pip3 install -e .
```

Required tools:
```bash
sudo apt install nmap responder hashcat crackmapexec sshpass smbclient python3-impacket
sudo gem install evil-winrm
```

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
