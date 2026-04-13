# CascadeCracker

GPU hash-cracking companion for [Cascade](https://github.com/your-username/Cascade).

Runs on your **Windows PC** (or any machine with a GPU). Pulls captured hashes from the Pi, cracks them with hashcat through a full rules escalation, then pushes the results back.

## How it fits together

```
Phone (Termius)
    └─ SSH → Raspberry Pi  (runs Cascade: recon / harvest / crack-light)
                └─ SCP vault.json ↔ Windows PC (runs CascadeCracker: GPU crack)
```

## Install

```bash
git clone https://github.com/your-username/CascadeCracker
cd CascadeCracker
pip install -e .
```

Two commands are now available:

| Command          | Purpose                              |
|------------------|--------------------------------------|
| `cascade-crack`  | Main cracker menu                    |
| `cascade-doctor` | Diagnostics — checks every dependency|

## Prerequisites

| Dependency        | Notes                                                        |
|-------------------|--------------------------------------------------------------|
| Python 3.10+      | Windows/Linux/Mac                                            |
| hashcat           | [hashcat.net](https://hashcat.net) — auto-discovered         |
| rockyou.txt       | Place anywhere; auto-discovered in common locations          |
| Tailscale         | For Pi ↔ Windows VPN tunnel — [tailscale.com](https://tailscale.com) |
| Windows OpenSSH   | So Pi can SSH back to Windows (optional, for remote compute) |

Run `cascade-doctor` for a full check with exact fix commands.

## First run

```bash
cascade-crack
```

On first run, auto-discovery finds hashcat, wordlists, and your SSH key. You'll be prompted for anything it can't find, and config is saved to `~/.cascade/config.json`.

## Remote use (Termius on phone → Pi → Windows)

1. Install Tailscale on both Pi and Windows PC and log in with the same account.
2. Enable Windows OpenSSH Server (doctor will tell you how if it's missing).
3. On Pi, add to `~/.ssh/config`:
   ```
   Host windows
       HostName <windows-tailscale-ip>
       User <your-windows-username>
       IdentityFile ~/.ssh/id_ed25519
   ```
4. From Pi: `ssh windows` — done.
5. In Termius: add Pi as jump host, then add Windows pointing through Pi.

## Crack flow

```
pull          — SCP vault.json from Pi to ~/.cascade/vault.json
crack         — hashcat: rockyou plain → best64.rule → d3ad0ne.rule → dive.rule
push          — SCP cracked vault.json back to Pi
full cycle    — all three in one shot (cascade-crack --pull-and-crack for headless)
```

## Headless / scripted

```bash
# Run from Pi over SSH to trigger a full crack cycle on Windows:
ssh windows "cascade-crack --pull-and-crack"
```

## Config

Stored at `~/.cascade/config.json`. Edit manually or use the `c` option in the menu.

```json
{
  "pi_host":       "100.x.x.x",
  "pi_user":       "kali",
  "pi_ssh_key":    "",
  "hashcat_path":  "",
  "rules_dir":     "",
  "wordlists":     []
}
```

Blank fields are auto-discovered at startup.
