# SecureVPN

Post-Quantum WireGuard VPN Client & Server.

Implements a hybrid Kyber-512 + X25519 key exchange with HKDF-SHA3-256 PSK derivation over the WireGuard protocol.

## Features
- Post-quantum key encapsulation (Kyber-512 KEM)
- WireGuard tunnel management on Windows
- Kill switch via Windows Firewall
- HMAC-SHA256 signed API requests with replay protection
- Bandwidth monitoring and connection logging
- CLI and GUI clients

## Structure
```
client/     — Windows VPN client (GUI + CLI)
server/     — Linux Flask API + WireGuard management
```

## Requirements
- WireGuard for Windows
- Python 3.10+
- See `client/requirements.txt` and `server/requirements.txt`

## Air University — NCSA — CS325 Network Security
