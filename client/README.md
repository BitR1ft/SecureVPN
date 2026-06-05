# SecureVPN Client
================
Post-Quantum WireGuard VPN Client for Windows

## Overview

This is the client component of SecureVPN, featuring a modern Tkinter GUI, comprehensive CLI, post-quantum cryptography, OS-level kill switch, traffic analysis, and multi-server failover.

## Features

- **Post-Quantum Crypto**: Hybrid X25519 + Kyber KEM
- **OS-Level Kill Switch**: Windows Firewall rules that survive crashes
- **Trust On First Use (TOFU)**: Server key pinning for MITM detection
- **Traffic Analyzer**: scapy-based packet capture showing encryption
- **Multi-Server Failover**: Auto-select lowest latency server
- **Bandwidth Monitor**: Real-time chart with history
- **Leak Dashboard**: Live IP/DNS verification
- **System Tray**: Minimize to tray without disconnecting
- **Anomaly Logging**: Security event detection and logging

## Prerequisites

- Windows 10/11 (64-bit)
- Python 3.10+
- WireGuard for Windows
- Administrator privileges (for kill switch and traffic analyzer)

## Installation

### 1. Install WireGuard for Windows

Download and install from: https://wireguard.com/install

Verify installation:
```
C:\Program Files\WireGuard\wireguard.exe
C:\Program Files\WireGuard\wg.exe
```

### 2. Install Python 3.10+

Download from: https://python.org/downloads

**IMPORTANT**: Check "Add Python to PATH" during installation.

Verify:
```cmd
python --version
```

### 3. Install SecureVPN Client

Extract `securevpn-client.zip` to `C:\SecureVPN\`

Open Command Prompt as Administrator:
```cmd
cd C:\SecureVPN
pip install -r requirements.txt
```

### 4. Launch SecureVPN

#### GUI Mode (Recommended)

Double-click `SecureVPN.bat` or run:
```cmd
python -m securevpn.gui.app
```

#### CLI Mode

```cmd
python -m securevpn.cli --help
```

#### PowerShell (Admin) - Full Features

```powershell
powershell -ExecutionPolicy Bypass -File SecureVPN.ps1
```

## Quick Start

### Generate Profile via API

```cmd
python -m securevpn.cli keygen myprofile ^
  --server https://YOUR_SERVER_IP ^
  --api-key YOUR_API_KEY
```

### Connect

```cmd
python -m securevpn.cli up --profile myprofile
```

### Verify Connection

```cmd
python -m securevpn.cli verify
```

### Disconnect

```cmd
python -m securevpn.cli down
```

## CLI Commands

### Profile Management
```cmd
# List profiles
python -m securevpn.cli list

# Import existing .conf file
python -m securevpn.cli import laptop.conf --name laptop

# Delete profile
# (Delete .conf file from %APPDATA%\SecureVPN\profiles\)
```

### Connection Control
```cmd
# Connect
python -m securevpn.cli up --profile myprofile

# Disconnect
python -m securevpn.cli down

# Show status
python -m securevpn.cli status
```

### Security Features
```cmd
# Run leak test
python -m securevpn.cli verify

# Rotate PSK
python -m securevpn.cli rotate-psk --profile myprofile

# Run traffic analyzer (requires Admin)
python -m securevpn.cli analyze
```

### Server Management
```cmd
# List configured servers
python -m securevpn.cli servers list

# Add server
python -m securevpn.cli servers add --name eu --endpoint 203.0.113.1:51820 --api-url https://203.0.113.1 --api-key KEY

# Test latencies
python -m securevpn.cli servers test
```

### Configuration
```cmd
# View config
python -m securevpn.cli config

# Edit config
python -m securevpn.cli config --set kill_switch=false
python -m securevpn.cli config --set auto_failover=true
```

### Logs
```cmd
# View connection logs
python -m securevpn.cli logs

# View anomaly logs
python -m securevpn.cli logs --type anomaly

# View last 20 lines
python -m securevpn.cli logs --tail 20
```

## GUI Guide

### Main Window

1. **Profile List** (left): Select a profile to connect
2. **Status Panel** (top-right): Shows connection details
3. **Leak Dashboard** (middle-right): Real-time IP/DNS verification
4. **Bandwidth Monitor** (bottom-right): Live traffic chart
5. **Connection Log** (bottom): Event history

### Connecting

1. Select a profile from the list
2. Click the green "Connect" button
3. Wait for status indicators to turn green
4. Verify leak dashboard shows "PASS"

### Kill Switch

The kill switch is enabled by default. It creates Windows Firewall rules that:
- Block ALL outbound traffic when connected
- Allow only VPN server and loopback traffic
- Survive application crashes and reboots

To disable: Uncheck "Kill Switch" in the status panel.

### System Tray

Click the X button to minimize to system tray. The VPN stays connected.
Right-click the tray icon to show/hide or exit.

## Security Features

### Trust On First Use (TOFU)

On first connection, the client's server public key is "pinned." If the key changes on subsequent connections, a security alert is shown. This detects MITM attacks.

Options when alert appears:
- **Trust New Key**: Update pin (if server legitimately rotated keys)
- **Keep Old Key**: Block connection (safe default)
- **Cancel**: Abort connection

### Kill Switch

The kill switch uses `netsh advfirewall` to create persistent rules:

```
SecureVPN-KillSwitch-Block      (block all outbound)
SecureVPN-KillSwitch-Allow-VPN  (allow server IP)
SecureVPN-KillSwitch-Allow-Loopback (allow 127.0.0.1)
SecureVPN-KillSwitch-Allow-DHCP (allow DHCP)
```

These rules persist even if:
- Python crashes
- You force-close the app
- Windows reboots (until explicitly disabled)

### Post-Quantum Cryptography

The client implements a CRYSTALS-Kyber-inspired KEM with full IND-CCA2 security:
- Ring-LWE with n=256, q=3329
- **Fujisaki-Okamoto (FO) transform**: encapsulation is deterministic from (m, pk)
- **Re-encapsulation check**: decaps verifies ciphertext integrity via constant-time comparison
- **Implicit rejection**: invalid ciphertexts return SHA3-256(z || ct), not an error
- Hybrid with X25519 ECDH (defense in depth)
- PSK derived via HKDF-SHA3-256 — never transmitted over the network
- Classical fallback uses honest SHA3-256(CSPRNG) — no fake CBD entropy

### Anomaly Detection

The client monitors for:
- Handshake timeouts (>60s)
- Rapid reconnect attempts (>3/min)
- IP/DNS leaks
- Server key changes

Events are logged to `%APPDATA%\SecureVPNnomaly.log`

## Traffic Analyzer

The traffic analyzer demonstrates that WireGuard encryption is actually working:

1. **Before VPN**: Capture shows readable HTTP headers, plaintext data
2. **After VPN**: Capture shows unreadable binary UDP packets (ChaCha20-Poly1305)

**Requirements**: Administrator privileges, scapy installed

Run from GUI: Tools -> Traffic Analyzer
Run from CLI: `python -m securevpn.cli analyze`

## Multi-Server Failover

Configure multiple servers in the GUI (Servers -> Add Server) or CLI:

```cmd
python -m securevpn.cli servers add --name eu --endpoint 203.0.113.1:51820 ...
python -m securevpn.cli servers add --name sg --endpoint 198.51.100.1:51820 ...
```

The client will:
1. Test latency to all servers
2. Auto-connect to the fastest
3. Failover to next server if current drops

## File Locations

| File | Location |
|------|----------|
| Profiles | `%APPDATA%\SecureVPN\profiles\` |
| Config | `%APPDATA%\SecureVPN\config.json` |
| Connection Log | `%APPDATA%\SecureVPN\connection.log` |
| Anomaly Log | `%APPDATA%\SecureVPNnomaly.log` |
| Session Stats | `%APPDATA%\SecureVPN\session_stats.json` |
| Pinned Keys | `%APPDATA%\SecureVPN\pinned_keys.json` |
| Secure Storage | `%APPDATA%\SecureVPN\secure_storage.enc` |

## Troubleshooting

### "WireGuard not found"
Install WireGuard from https://wireguard.com/install

### "Administrator required"
Run as Administrator for kill switch and traffic analyzer.

### "API key invalid"
Check the API key on the server:
```bash
sudo cat /opt/wg-api/config/api_key.secret
```

### "Connection failed"
1. Check server is running: `curl -k https://SERVER_IP/api/v1/health`
2. Check firewall allows UDP/51820
3. Check WireGuard service: `sc query WireGuardTunnel$`

### "Kill switch stuck"
If internet is blocked after disconnect:
```cmd
netsh advfirewall firewall delete rule name="SecureVPN-KillSwitch-Block"
netsh advfirewall firewall delete rule name="SecureVPN-KillSwitch-Allow-VPN"
netsh advfirewall firewall delete rule name="SecureVPN-KillSwitch-Allow-Loopback"
netsh advfirewall firewall delete rule name="SecureVPN-KillSwitch-Allow-DHCP"
```

### "scapy not found"
```cmd
pip install scapy
```

## Architecture

```
SecureVPN Client
├── GUI (Tkinter)
│   ├── Profile Manager
│   ├── Status Panel
│   ├── Leak Dashboard
│   ├── Bandwidth Chart
│   └── System Tray
├── CLI (argparse)
│   └── All GUI features accessible
├── Core Engine
│   ├── WireGuard Control
│   ├── Kill Switch (netsh)
│   ├── Multi-Server Logic
│   └── Bandwidth Monitor
├── Crypto Engine
│   ├── X25519 ECDH
│   ├── KyberKEM (FO transform + re-encapsulation)
│   ├── Hybrid KDF (HKDF-SHA3-256)
│   └── Secure Storage (DPAPI / Keyring / AES-256-GCM)
└── Tools
    ├── Traffic Analyzer (scapy)
    └── Leak Tester
```

## Secure Development Principles

1. **Fail-Safe Defaults**: Kill switch ON by default
2. **Least Privilege**: Minimal permissions where possible
3. **Defense in Depth**: Multiple security layers
4. **Secure by Design**: No hardcoded secrets, input validation
5. **Audit Logging**: All security events logged
6. **Memory Safety**: Secure wiping of sensitive data
7. **Constant-Time**: Cryptographic comparisons

## License

Academic Project - Air University NCSA - CS325 Network Security
