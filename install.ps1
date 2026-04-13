# install.ps1 — Cascade installer for Windows (GPU Crack mode)
# Run in PowerShell as Administrator:
#   Set-ExecutionPolicy Bypass -Scope Process; .\install.ps1

$ErrorActionPreference = "Continue"

$RED  = "`e[91m"; $GRN  = "`e[92m"; $YLW  = "`e[93m"
$WH   = "`e[97m"; $DIM  = "`e[2m";  $B    = "`e[1m";  $R = "`e[0m"

Write-Host ""
Write-Host "  ${RED}${B}╔══════════════════════════════════════════════╗"
Write-Host "  ║   CASCADE  —  Windows Installer             ║"
Write-Host "  ╚══════════════════════════════════════════════╝${R}"
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Python check ──────────────────────────────────────────────────────────────
Write-Host "  ${WH}[1/5] Checking Python...${R}"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $py) {
    Write-Host "  ${RED}Python not found!${R}"
    Write-Host "  ${YLW}Download Python 3.10+ from https://python.org/downloads${R}"
    Write-Host "  ${DIM}Make sure to check 'Add Python to PATH' during install.${R}"
    Read-Host "  Press Enter to exit"
    exit 1
}
$pyver = & $py.Source --version 2>&1
Write-Host "  ${GRN}Found: $pyver${R}"

# ── pip install cascade ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${WH}[2/5] Installing Cascade...${R}"
& $py.Source -m pip install -e $ScriptDir -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ${RED}pip install failed. Check Python/pip are working.${R}"
    Read-Host "  Press Enter to exit"
    exit 1
}
Write-Host "  ${GRN}Done.${R}"

# ── hashcat check ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${WH}[3/5] Checking hashcat...${R}"
$hc = Get-Command hashcat -ErrorAction SilentlyContinue
if (-not $hc) {
    $hc = Get-Command hashcat.exe -ErrorAction SilentlyContinue
}
# Search common dirs
$hcDirs = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\tools",
    "C:\tools",
    "C:\hashcat",
    "C:\Program Files\hashcat"
)
$hcPath = $null
foreach ($d in $hcDirs) {
    if (Test-Path "$d\hashcat.exe") { $hcPath = "$d\hashcat.exe"; break }
    $sub = Get-ChildItem $d -Filter "hashcat-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($sub -and (Test-Path "$($sub.FullName)\hashcat.exe")) {
        $hcPath = "$($sub.FullName)\hashcat.exe"; break
    }
}

if ($hcPath) {
    Write-Host "  ${GRN}Found: $hcPath${R}"
} elseif ($hc) {
    Write-Host "  ${GRN}Found in PATH: $($hc.Source)${R}"
} else {
    Write-Host "  ${YLW}hashcat not found.${R}"
    Write-Host "  ${DIM}Download from https://hashcat.net/hashcat/${R}"
    Write-Host "  ${DIM}Extract anywhere (e.g. C:\tools\hashcat-6.x.x\)${R}"
    Write-Host "  ${DIM}cascade-crack auto-discovers it — no need to add to PATH.${R}"
}

# ── rockyou check ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${WH}[4/5] Checking wordlist (rockyou.txt)...${R}"
$wlPaths = @(
    "$env:USERPROFILE\wordlists\rockyou.txt",
    "$env:USERPROFILE\Downloads\rockyou.txt",
    "$env:USERPROFILE\Documents\rockyou.txt",
    "C:\tools\wordlists\rockyou.txt",
    "C:\wordlists\rockyou.txt"
)
$wlFound = $wlPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($wlFound) {
    Write-Host "  ${GRN}Found: $wlFound${R}"
} else {
    Write-Host "  ${YLW}rockyou.txt not found.${R}"
    Write-Host "  ${DIM}Download: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt${R}"
    Write-Host "  ${DIM}Place it in: $env:USERPROFILE\Downloads\rockyou.txt${R}"
    Write-Host "  ${DIM}(or anywhere — cascade-crack finds it automatically)${R}"
}

# ── Tailscale ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${WH}[5/5] Checking Tailscale...${R}"
$ts = Get-Command tailscale -ErrorAction SilentlyContinue
if ($ts) {
    $tsip = & tailscale ip --4 2>$null
    if ($tsip) {
        Write-Host "  ${GRN}Tailscale connected: $tsip${R}"
    } else {
        Write-Host "  ${YLW}Tailscale installed but not logged in.${R}"
        $yn = Read-Host "  Open Tailscale login now? [Y/n]"
        if ($yn -ne 'n' -and $yn -ne 'N') {
            Start-Process "tailscale" -ArgumentList "up" -NoNewWindow -Wait 2>$null
            Write-Host "  ${DIM}A browser window should have opened — log in with your Tailscale account.${R}"
            Write-Host "  ${DIM}Both Pi and Windows must use the same Tailscale account.${R}"
        }
    }
} else {
    Write-Host "  ${YLW}Tailscale not installed (needed for Pi <-> Windows hash sync).${R}"
    $yn = Read-Host "  Install Tailscale now via winget? [Y/n]"
    if ($yn -ne 'n' -and $yn -ne 'N') {
        $wg = Get-Command winget -ErrorAction SilentlyContinue
        if ($wg) {
            Write-Host "  Installing..."
            winget install --id tailscale.tailscale --silent --accept-package-agreements --accept-source-agreements
            # Refresh PATH so tailscale is findable
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Host "  ${GRN}Installed. Opening login...${R}"
            Start-Process "tailscale" -ArgumentList "up" -NoNewWindow -Wait 2>$null
            Write-Host "  ${DIM}A browser window should have opened — log in with your Tailscale account.${R}"
            Write-Host "  ${DIM}Both Pi and Windows must use the same Tailscale account.${R}"
        } else {
            Write-Host "  ${YLW}winget not available. Download manually:${R}"
            Write-Host "  ${DIM}https://tailscale.com/download/windows${R}"
            Write-Host "  ${DIM}Install it, then open the Tailscale tray icon and log in.${R}"
            Start-Process "https://tailscale.com/download/windows"
        }
    } else {
        Write-Host "  ${DIM}Skipped. Without Tailscale the Pi<->Windows sync won't work.${R}"
    }
}

# ── done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${GRN}${B}Install complete!${R}"
Write-Host ""
Write-Host "  Run Cascade:      ${WH}cascade${R}"
Write-Host "  Run diagnostics:  ${WH}cascade-doctor${R}"
Write-Host ""
Write-Host "  ${DIM}On first run, select [2] Crack mode.${R}"
Write-Host ""
Read-Host "  Press Enter to exit"
