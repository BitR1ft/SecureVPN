# SecureVPN Client Launcher (Administrator)
# ==========================================
# Run with: Right-click -> Run as Administrator
#           OR: powershell -ExecutionPolicy Bypass -File SecureVPN.ps1

$host.ui.RawUI.WindowTitle = "SecureVPN Client (Admin)"

Write-Host ""
Write-Host "  SecureVPN - Post-Quantum WireGuard VPN" -ForegroundColor Cyan
Write-Host "  Air University - NCSA - CS325" -ForegroundColor DarkGray
Write-Host ""

# Check admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "WireGuard tunnel operations require admin privileges." -ForegroundColor Yellow
    Write-Host "Consider running as Administrator for full functionality." -ForegroundColor Yellow
    Write-Host ""
}

# Check Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "  Python: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Python not found" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check WireGuard
$wgPath = "C:\Program Files\WireGuard\wireguard.exe"
if (Test-Path $wgPath) {
    Write-Host "  WireGuard: Found" -ForegroundColor Green
} else {
    Write-Host "  WARNING: WireGuard not found at $wgPath" -ForegroundColor Yellow
    Write-Host "  Install from: https://www.wireguard.com/install/" -ForegroundColor Yellow
}

Write-Host ""

# Install dependencies if needed
$depsFlag = "$env:APPDATA\SecureVPN\.deps_installed"
$requirementsPath = Join-Path $PSScriptRoot "requirements.txt"
if ((Test-Path $requirementsPath) -and -NOT (Test-Path $depsFlag)) {
    Write-Host "  Installing dependencies..." -ForegroundColor Cyan
    pip install -r $requirementsPath 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        New-Item -ItemType File -Path $depsFlag -Force | Out-Null
        Write-Host "  Dependencies installed successfully" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Some dependencies may not have installed" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Set PYTHONPATH
$env:PYTHONPATH = "$PSScriptRoot;$env:PYTHONPATH"

# Launch GUI
Write-Host "  Launching SecureVPN GUI..." -ForegroundColor Green
Write-Host ""

# DPI awareness is handled inside app.py via ctypes
python -m securevpn.gui.app

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  GUI exited with error. Try CLI mode:" -ForegroundColor Yellow
    Write-Host "  python securevpn_cli.py status" -ForegroundColor Gray
    Write-Host ""
}

Read-Host "Press Enter to exit"
