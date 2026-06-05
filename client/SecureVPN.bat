@echo off
REM SecureVPN Client Launcher
REM =========================
REM Usage:
REM   SecureVPN.bat          - Launch GUI
REM   SecureVPN.bat cli      - Launch CLI
REM   SecureVPN.bat keygen   - Quick keygen via CLI

setlocal EnableDelayedExpansion

REM Get script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

REM Add current dir to PYTHONPATH
set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"

REM Launch mode
if "%1"=="cli" (
    echo Launching SecureVPN CLI...
    python securevpn_cli.py %2 %3 %4 %5 %6 %7 %8 %9
) else if "%1"=="keygen" (
    echo Launching SecureVPN Keygen...
    python securevpn_cli.py keygen %2 %3 %4 %5
) else (
    echo Launching SecureVPN GUI...
    start "" pythonw -c "import sys; sys.path.insert(0, r'%SCRIPT_DIR%'); from securevpn.gui.app import main; main()"
)
