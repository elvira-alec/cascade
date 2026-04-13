#!/usr/bin/env bash
# install.sh — Cascade installer for Raspberry Pi / Kali Linux
# Run with: sudo bash install.sh

set -e

RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'; WH='\033[97m'; R='\033[0m'; B='\033[1m'

echo -e "${RED}${B}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   CASCADE  —  Pi Installer                  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${R}"

# ── check root ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "  ${RED}Run with sudo: sudo bash install.sh${R}"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"

# ── system packages ───────────────────────────────────────────────────────────
echo -e "  ${WH}[1/4] Installing system packages...${R}"
apt-get update -qq
apt-get install -y -qq \
    nmap \
    responder \
    crackmapexec \
    sshpass \
    smbclient \
    python3-impacket \
    python3-pip \
    git \
    2>/dev/null || true

# impacket scripts (psexec, wmiexec, etc.)
if ! command -v impacket-psexec &>/dev/null; then
    pip3 install impacket --break-system-packages -q 2>/dev/null || true
fi

# evil-winrm (optional)
if command -v gem &>/dev/null; then
    gem install evil-winrm --no-document -q 2>/dev/null || true
fi

# mitm6 (optional — only useful if network has IPv6)
pip3 install mitm6 --break-system-packages -q 2>/dev/null || true

echo -e "  ${GRN}Done.${R}"

# ── pip install cascade ───────────────────────────────────────────────────────
echo -e "  ${WH}[2/4] Installing Cascade Python package...${R}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pip3 install -e "$SCRIPT_DIR" --break-system-packages -q
echo -e "  ${GRN}Done.${R}"

# ── create ~/.cascade dir for root (vault lives here) ────────────────────────
echo -e "  ${WH}[3/4] Setting up config directory...${R}"
mkdir -p /root/.cascade
echo -e "  ${GRN}Created /root/.cascade${R}"

# ── Tailscale ─────────────────────────────────────────────────────────────────
echo -e "  ${WH}[4/4] Tailscale check...${R}"
if command -v tailscale &>/dev/null; then
    TS_IP=$(tailscale ip --4 2>/dev/null || true)
    if [ -n "$TS_IP" ]; then
        echo -e "  ${GRN}Tailscale connected: $TS_IP${R}"
    else
        echo -e "  ${YLW}Tailscale installed but not logged in.${R}"
        read -rp "  Connect to Tailscale now? [Y/n]: " yn
        if [[ "$yn" != "n" && "$yn" != "N" ]]; then
            tailscale up
            TS_IP=$(tailscale ip --4 2>/dev/null || true)
            [ -n "$TS_IP" ] && echo -e "  ${GRN}Connected: $TS_IP${R}" || echo -e "  ${YLW}Not connected yet — run 'tailscale up' later.${R}"
        fi
    fi
else
    echo -e "  ${YLW}Tailscale not installed.${R}"
    echo -e "  ${DIM}Needed so your Windows PC can SSH into the Pi to sync hashes.${R}"
    read -rp "  Install Tailscale now? [Y/n]: " yn
    if [[ "$yn" != "n" && "$yn" != "N" ]]; then
        curl -fsSL https://tailscale.com/install.sh | sh
        echo -e "  ${GRN}Installed.${R}"
        read -rp "  Connect to Tailscale now? [Y/n]: " yn2
        if [[ "$yn2" != "n" && "$yn2" != "N" ]]; then
            tailscale up
            TS_IP=$(tailscale ip --4 2>/dev/null || true)
            [ -n "$TS_IP" ] && echo -e "  ${GRN}Connected: $TS_IP${R}" || echo -e "  ${YLW}Not connected yet — run 'tailscale up' later.${R}"
        fi
    else
        echo -e "  ${DIM}Skipped. Run later: curl -fsSL https://tailscale.com/install.sh | sh && tailscale up${R}"
    fi
fi

echo ""
echo -e "  ${GRN}${B}Install complete!${R}"
echo ""
echo -e "  Run Cascade:  ${WH}sudo cascade${R}"
echo ""
