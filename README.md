# Cascade

**Automated post-exploitation kill chain orchestrator.**  
One command. Five stages. From blank LAN to live shell.

```
sudo cascade
```

> For authorized penetration testing only. Only run against networks and systems you own or have explicit written permission to test.

---

## What it does

Cascade automates the internal network kill chain — everything after you have a foothold on a LAN segment (via ethernet, evil twin, or any other initial access). It chains five stages into a single red TUI:

| Stage | Name | What it does |
|-------|------|-------------|
| 1 | **Recon** | nmap sweeps the subnet — finds hosts, ports, OS, services |
| 2 | **Hash Harvest** | Responder poisons LLMNR/NBT-NS/WPAD — Windows machines hand over NTLMv2 hashes automatically |
| 3 | **Cred Spray** | Tries default/common credentials (admin/admin, root/root, etc.) against SSH, SMB, and HTTP admin panels on every host — threaded |
| 4 | **Hash Cracking** | Feeds captured NTLMv2 hashes into hashcat (mode 5600) against rockyou.txt |
| 5 | **Lateral Movement** | CrackMapExec over SMB/WinRM + paramiko over SSH using every valid credential |

After the kill chain, a **shell manager** lets you connect directly to compromised hosts — no manual commands needed.

---

## Shell manager

After stage 5, Cascade shows every compromised host and the connection methods available for each one (based on open ports and installed tools):

- **CMD shell (psexec / SYSTEM)** — port 445 + impacket-psexec  
- **CMD shell (wmiexec / user)** — port 445 + impacket-wmiexec  
- **PowerShell (evil-winrm)** — port 5985 + evil-winrm  
- **SSH shell** — port 22 + ssh/sshpass  
- **Browse SMB files** — port 445 + smbclient  

Sessions are saved to `~/.cascade_sessions.json`. Reconnect anytime:

```
sudo cascade --shells
```

---

## Install

```bash
git clone https://github.com/elvira-alec/cascade
cd cascade
sudo pip3 install -e .
```

Required tools:
```bash
sudo apt install nmap responder hashcat crackmapexec sshpass python3-impacket
sudo gem install evil-winrm
```

---

## Usage

```bash
sudo cascade                              # full auto, detect subnet from interface
sudo cascade -i eth0                      # specify interface
sudo cascade --subnet 192.168.1.0/24      # specify subnet manually
sudo cascade --no-harvest                 # skip Responder (quiet/passive mode)
sudo cascade --harvest-time 300           # longer hash capture window (seconds)
sudo cascade --full-scan                  # full port scan instead of fast top-100
sudo cascade --wordlist /path/to/list.txt # custom wordlist for cracking
sudo cascade --stage 3                    # run only one stage (1-5)
sudo cascade --shells                     # jump straight to saved session manager
sudo cascade --about                      # full description of all stages
sudo cascade -v                           # verbose output
```

---

## Project structure

```
cascade/
├── __main__.py   # entry point, kill chain orchestration
├── tui.py        # terminal UI — red banner, phase/info/success/warn/error
├── recon.py      # nmap subnet scanner
├── harvest.py    # Responder wrapper + hash capture
├── spray.py      # default credential spray (SSH, SMB, HTTP)
├── crack.py      # hashcat / john NTLMv2 cracker
├── lateral.py    # CrackMapExec + SSH lateral movement
└── shells.py     # interactive shell manager + session store
```

---

## Legal

This tool is for **authorized security testing only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author accepts no liability for misuse.
