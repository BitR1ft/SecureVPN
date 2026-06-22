# SecureVPN

**Post-Quantum WireGuard VPN — CS325 Network Security Project**  
Air University · National Centre for Cyber Security (NCSA)  
By: Muhammad Adeel Haider (BitR1ft)

---

## What is this?

SecureVPN is a full-stack VPN system built on top of WireGuard. It extends classical WireGuard with a **post-quantum hybrid key exchange** — combining Kyber-512 (a lattice-based KEM selected by NIST for standardization) with X25519, using HKDF-SHA3-256 to derive the WireGuard Pre-Shared Key. This means the tunnel is protected against both classical and quantum adversaries.

The system has two main components:

- **Client** — Windows GUI + CLI application that manages the WireGuard tunnel
- **Server** — Linux Flask API that provisions and manages WireGuard peers

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  WINDOWS CLIENT                     │
│                                                     │
│  GUI (tkinter)  ──►  VPN Core  ──►  WireGuard       │
│                          │                          │
│                    Crypto Engine                    │
│               (Kyber-512 + X25519 + HKDF)          │
└────────────────────────┬────────────────────────────┘
                         │ HTTPS (signed requests)
                         ▼
┌─────────────────────────────────────────────────────┐
│                  LINUX SERVER                       │
│                                                     │
│  Nginx (TLS) ──► Gunicorn ──► Flask API             │
│                                  │                  │
│                            WG Manager               │
│                         (wg0 peer lifecycle)        │
│                                  │                  │
│                            WireGuard (wg0)          │
└─────────────────────────────────────────────────────┘
```

---

## Post-Quantum Key Exchange Protocol

```
Client                                          Server
──────                                          ──────
1. Generate WireGuard keypair (classical)
2. Generate Kyber-512 keypair (PQ)
3. POST /api/v1/add-peer
   { public_key, kyber_public_key }
                    ─────────────────────────►
                                          4. Encapsulate to client's Kyber PK:
                                             ciphertext, shared_secret = KEM.encaps(pk)
                                          5. Derive PSK:
                                             PSK = HKDF-SHA3-256(shared_secret)
                                          6. Add peer to wg0 with PSK
                    ◄─────────────────────────
                    { kem_ciphertext, server_pub, ... }

7. Decapsulate:
   shared_secret = KEM.decaps(ciphertext, sk)
8. Derive same PSK:
   PSK = HKDF-SHA3-256(shared_secret)
9. Write WireGuard .conf and connect
```

The PSK never crosses the network. Both sides independently derive the same key from the KEM shared secret. This provides **IND-CCA2** security against quantum adversaries.

---

## Features

### Security
- **Kyber-512 KEM** — Post-quantum key encapsulation (NIST PQC Round 4 selection)
- **Hybrid key exchange** — X25519 + Kyber-512, fail-safe against both classical and quantum attacks
- **HKDF-SHA3-256** — Key derivation with domain-separated info string
- **WireGuard PSK** — Per-tunnel pre-shared key for layered encryption
- **HMAC-SHA256 request signing** — All mutating API calls are signed with timestamp and body hash
- **Replay attack protection** — ±300 second timestamp window enforced server-side
- **TOFU key pinning** — Server public key is pinned on first use; mismatch raises a `SecurityError`
- **Kill switch** — Windows Firewall rules block all traffic if the tunnel drops
- **IND-CCA2 decapsulation** — Re-encapsulation integrity check prevents reaction attacks

### Client
- Simple, clean GUI built with standard tkinter (no external UI frameworks)
- CLI with full command coverage
- Profile import and generation
- Bandwidth monitoring (RX/TX rates and totals)
- Leak test (IP + DNS verification)
- PSK rotation
- Connection logging and anomaly log

### Server
- Flask REST API with Gunicorn + Nginx in production
- Redis-backed rate limiting (shared across Gunicorn workers)
- Atomic peer provisioning with `fcntl.flock` (no duplicate IP assignment)
- Live peer removal without interface restart (`wg set ... peer <pk> remove`)
- Peer lifecycle audit with configurable TTL
- Systemd service with `ProtectSystem=strict`
- Docker support

---

## Project Structure

```
SecureVPN/
├── client/
│   ├── securevpn/
│   │   ├── gui/
│   │   │   └── app.py              # tkinter GUI application
│   │   ├── core/
│   │   │   ├── vpn_engine.py       # Tunnel management, kill switch, bandwidth
│   │   │   └── crypto_engine.py    # Kyber-512 KEM, X25519, HKDF, DPAPI storage
│   │   ├── tools/
│   │   │   └── traffic_analyzer.py # Scapy-based traffic analysis
│   │   └── cli.py                  # CLI entry point
│   ├── requirements.txt
│   └── SecureVPN_GUI.spec          # PyInstaller build spec
│
└── server/
    ├── wg-api/
    │   ├── app.py                  # Flask application
    │   ├── config.py               # Server configuration
    │   ├── services/
    │   │   ├── wg_manager.py       # WireGuard peer lifecycle
    │   │   ├── auth.py             # API key + HMAC-SHA256 auth decorators
    │   │   └── monitor.py          # Anomaly detection
    │   ├── crypto/
    │   │   └── pq_crypto.py        # Server-side Kyber KEM
    │   └── utils/
    │       ├── validators.py       # Input validation
    │       └── logger.py           # Structured JSON logging
    ├── scripts/                    # WireGuard sudoers wrapper scripts
    ├── systemd/                    # wg-api systemd service unit
    ├── Dockerfile
    ├── docker-compose.yml
    └── install.sh                  # Automated server setup script
```

---

## Quick Start

### Prerequisites

**Client (Windows)**
- Windows 10/11 64-bit
- [WireGuard for Windows](https://www.wireguard.com/install/) installed
- Python 3.10+ (or use the prebuilt `SecureVPN.exe`)
- Run as **Administrator** (required for WireGuard tunnel service and firewall rules)

**Server (Linux — Ubuntu 22.04/24.04)**
- WireGuard (`apt install wireguard`)
- Python 3.10+
- Redis (`apt install redis-server`)
- Nginx (optional, recommended for production)

---

### Server Setup

```bash
# Clone the repo
git clone https://github.com/BitR1ft/SecureVPN.git
cd SecureVPN/server

# Run the automated installer (sets up WireGuard, API, systemd, firewall)
sudo bash install.sh IP
```

The installer will:
1. Install WireGuard and generate server keys
2. Create `wg0` interface with the VPN subnet
3. Install the Flask API as a systemd service (`wg-api`)
4. Configure Nginx reverse proxy with TLS
5. Set up Redis for rate limiting
6. Configure UFW firewall rules

**Manual configuration** — edit `/opt/wg-api/config.py`:
```python
API_KEY        = "your-secret-api-key-here"
SERVER_ENDPOINT = "your.server.ip.or.domain"
LISTEN_PORT    = 51820
VPN_SUBNET     = "10.77.0.0/24"
SERVER_IP      = "10.77.0.1"
PQ_ENABLED     = True
```

---

### Client Setup (Python)

```bash
cd SecureVPN/client

# Create virtualenv and install dependencies
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

# Launch GUI (run as Administrator)
python securevpn_gui.py

# Or use the CLI
python securevpn_cli.py --help
```

### Client Setup (Prebuilt EXE)

Right-click `client/dist/SecureVPN.exe` → **Run as administrator**

---

### Generating a Profile (GUI)

1. Launch SecureVPN as Administrator
2. Click **Profiles** in the sidebar
3. Click **Generate Keys**
4. Fill in:
   - Profile Name (e.g. `home`)
   - Server URL (e.g. `https://20.29.133.180`)
   - API Key (from your server's `config.py`)
5. Click **Generate Keys** — the client performs the full PQ KEM handshake
6. Switch to **Connect**, select the profile, click **Connect**

---

### CLI Usage

```bash
# List profiles
python securevpn_cli.py list

# Generate post-quantum profile
python securevpn_cli.py keygen myprofile \
  --server https://your-server:443 \
  --api-key YOUR_API_KEY

# Connect
python securevpn_cli.py up --profile myprofile

# Status
python securevpn_cli.py status

# Leak test
python securevpn_cli.py verify

# Disconnect
python securevpn_cli.py down

# Rotate PSK
python securevpn_cli.py rotate-psk --profile myprofile

# View logs
python securevpn_cli.py logs --tail 50
```

---

## API Reference

All mutating endpoints require HMAC-SHA256 signed requests.

**Signature scheme:**
```
canonical  = f"{METHOD}:{path}:{timestamp}:{hex(sha256(body))}"
signature  = HMAC-SHA256(api_key, canonical)

Headers:
  X-API-Key:   <api_key>
  X-Timestamp: <unix_epoch_seconds>
  X-Signature: <hex_signature>
```

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/v1/health` | GET | None | Health check |
| `/api/v1/status` | GET | API Key | WireGuard interface status |
| `/api/v1/server-stats` | GET | API Key | Peer count, uptime, memory |
| `/api/v1/add-peer` | POST | Signed | Provision new peer (PQ KEM) |
| `/api/v1/revoke-peer` | POST | Signed | Remove peer (live, no restart) |
| `/api/v1/rotate-psk` | POST | Signed | Rotate pre-shared key |
| `/api/v1/audit-peers` | GET | API Key | Peer lifecycle audit report |
| `/api/v1/pq-keygen` | POST | API Key | Standalone KEM encapsulation |
| `/api/v1/anomalies` | GET | API Key | Security anomaly log |

---

## Kill Switch

When enabled, the kill switch installs Windows Firewall rules that block **all outbound traffic** except:
- Traffic through the WireGuard tunnel adapter
- UDP to the VPN server's endpoint IP (for handshake)
- Loopback (127.0.0.1)
- DHCP (UDP 68→67)
- VPN subnet (10.77.0.0/24)

If the tunnel drops, all internet traffic is blocked until the VPN reconnects. Rules are automatically removed on disconnect.

---

## Building the EXE

```bash
cd client

# Install PyInstaller
pip install pyinstaller

# Build
pyinstaller SecureVPN_GUI.spec --noconfirm

# Output: client/dist/SecureVPN.exe
```

---

## Docker (Server)

```bash
cd server
docker-compose up -d
```

The compose file runs the Flask API + Redis. Configure `server/wg-api/config.py` before building.

---

## Security Notes

- **WireGuard `.conf` files are excluded from git** (they contain private keys). See `.gitignore`.
- The server API key is in `config.py` — never commit it. Use environment variables in production.
- The kill switch is enabled by default. Disable in Settings if you have issues.
- TOFU key pinning means if the server rotates its WireGuard keypair, the client will raise a `SecurityError`. Use `update_pinned_key()` in `vpn_engine.py` after verifying the new key out-of-band.

---

## Tech Stack

| Layer | Technology |
|---|---|
| VPN Protocol | WireGuard |
| PQ KEM | Kyber-512 (custom numpy implementation) |
| Classical KE | X25519 |
| KDF | HKDF-SHA3-256 |
| API | Flask 3.0 + Gunicorn + Nginx |
| Rate Limiting | Flask-Limiter + Redis |
| Auth | HMAC-SHA256 + API key |
| GUI | Python tkinter |
| Key Storage | Windows DPAPI / AES-GCM fallback |
| OS Keyring | python-keyring |
| Build | PyInstaller 6.x |

---

## Academic Context

> **Course:** CS325 — Network Security  
> **Institution:** Air University, Islamabad, Pakistan  
> **Lab:** National Centre for Cyber Security (NCSA)  

This project demonstrates:
- WireGuard tunnel management at the OS level (Windows service API)
- Post-quantum cryptography integration into an existing classical protocol
- Hybrid forward-secrecy key exchange
- Secure API design (HMAC signing, replay protection, rate limiting)
- OS-level network security controls (Windows Firewall kill switch)

---

## License

This project is for academic purposes. All rights reserved.
