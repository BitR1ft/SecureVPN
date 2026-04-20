# SecureVPN Server
> **Post-Quantum WireGuard VPN** — Hybrid Kyber-512 + X25519 · Gunicorn + Nginx · Defense-in-Depth

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Windows)                         │
│                                                                 │
│  VPNCore.generate_keys()                                        │
│    1. wg genkey  →  (wg_priv, wg_pub)                          │
│    2. KyberKEM.keygen()  →  (kyber_pk, kyber_sk)               │
│    3. POST /api/v1/add-peer  {wg_pub, kyber_pk}  ──────────────┼──┐
│    6. kyber_decaps(ct, kyber_sk)  →  shared_secret             │  │
│    7. HKDF(shared_secret)  →  PSK  (same as server)            │  │
│    8. Build .conf  →  WireGuard tunnel UP  ◀────────────────────┼──┘
└─────────────────────────────────────────────────────────────────┘
              │ WireGuard UDP :51820 (encrypted)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SERVER (Linux VM)                        │
│                                                                 │
│  Internet ──▶ UFW (443, 51820, 22 only)                        │
│               ──▶ Nginx :443 (TLS 1.3, ECDHE, HSTS)           │
│                   ──▶ UNIX socket                              │
│                       ──▶ Gunicorn (wg-api user, non-root)     │
│                           ──▶ Flask API                        │
│                               ──▶ sudo wg set wg0 ...         │
│                                                                 │
│  On POST /add-peer:                                             │
│    4. KyberKEM.encaps(kyber_pk)  →  (ct, shared_secret)        │
│    5. HKDF(shared_secret)  →  PSK  →  wg0.conf                │
│    Return: {ct, server_wg_pub, endpoint, client_ip}  ─────────▶│
└─────────────────────────────────────────────────────────────────┘
```

### Security Model

| Layer | Mechanism | Protection |
|---|---|---|
| Transport | WireGuard (ChaCha20-Poly1305) | Encryption of all VPN traffic |
| Key Exchange | X25519 ECDH (classical) | Forward secrecy |
| Post-Quantum | Kyber-512 KEM (FIPS 203-inspired) | Harvest-now-decrypt-later resistance |
| PSK Derivation | HKDF-SHA3-256 | Domain-separated key derivation |
| API Auth | HMAC-SHA256 request signing | Replay prevention (±5 min window) |
| API Auth | hmac.compare\_digest API key | Timing-attack resistant |
| API Transport | TLS 1.3 + ECDHE | API confidentiality |
| Rate Limiting | Flask-Limiter + Redis | Global multi-worker enforcement |
| OS Isolation | Non-root systemd service | Privilege containment |
| OS Isolation | Sudoers bash wrappers | No wildcard flag injection |
| Network | UFW + Nginx rate limiting | DoS/brute-force mitigation |
| Intrusion | fail2ban | Automated IP banning |
| Peer Lifecycle | 90-day TTL audit | Stale credential cleanup |

---

## API Reference

All endpoints require `X-API-Key` header except `/health`.
Base URL: `https://<server-ip>/api/v1/`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health` | ❌ | Server health check |
| GET | `/status` | ✅ | WireGuard interface status |
| GET | `/server-stats` | ✅ | Peer count, uptime, memory |
| POST | `/add-peer` | ✅ | Register new peer (hybrid PQ flow) |
| POST | `/rotate-psk` | ✅ | Rotate pre-shared key |
| POST | `/revoke-peer` | ✅ | Immediately remove peer |
| GET | `/audit-peers` | ✅ | TTL audit report |
| POST | `/pq-keygen` | ✅ | KEM encapsulation exchange |
| GET | `/anomalies` | ✅ | Recent security anomalies |

### POST /add-peer

```json
// Request
{
  "name": "alice-laptop",
  "public_key": "<wg-public-key-base64>",
  "kyber_public_key": "<kyber-pk-base64>"
}

// Response
{
  "success": true,
  "data": {
    "name": "alice-laptop",
    "client_ip": "10.77.0.2",
    "server_public_key": "<server-wg-pub>",
    "preshared_key": "<psk-base64>",
    "endpoint": "1.2.3.4:51820",
    "pq_psk_method": "KEM-HKDF-SHA3-256",
    "kem_ciphertext": "<ct-base64>"
  }
}
```

---

## Installation

### VM Requirements
- Ubuntu 22.04 / Debian 12 / Kali Linux
- Root access
- Public IP address
- Ports open: 22/tcp, 443/tcp, 51820/udp

### Quick Install

```bash
git clone https://github.com/yourteam/securevpn
cd securevpn/securevpn-server
sudo bash install.sh <YOUR_SERVER_PUBLIC_IP>
```

### Docker Deploy

```bash
echo "SERVER_ENDPOINT=<YOUR_SERVER_PUBLIC_IP>" > .env
docker compose up -d
docker compose logs -f wg-api
```

---

## Security Hardening Checklist

- [x] Non-root service user (`wg-api`)
- [x] Gunicorn replaces Flask dev server
- [x] TLS 1.2/1.3 only via Nginx (ECDHE ciphers, HSTS)
- [x] UFW: deny-by-default, only 22/443/51820 open
- [x] Restricted sudoers: root-owned bash wrapper scripts (no wildcards)
- [x] Structured JSON logging with tamper-evidence hashes
- [x] fail2ban bans after 5 failed auth attempts
- [x] SHAKE-128 XOF for Kyber matrix generation (FIPS 203)
- [x] FO Transform for IND-CCA2 KEM security
- [x] Re-encapsulation check with implicit rejection (reaction attack prevention)
- [x] PSK never crosses the network (KEM-derived via HKDF-SHA3-256)
- [x] Peer TTL audit (90-day default, daily systemd timer)
- [x] `hmac.compare_digest` for API key comparison
- [x] HMAC-SHA256 request signing on mutating endpoints (±300s replay window)
- [x] Input validation on all endpoints
- [x] Flask-Limiter + Redis rate limiting (global across all Gunicorn workers)
- [x] `fcntl.LOCK_EX` for atomic concurrent config writes

---

## Testing

```bash
cd securevpn-server
pip install pytest pytest-mock
pytest tests/ -v --tb=short
```

Expected output:
```
tests/test_pq_crypto.py::TestMatrixGeneration::test_no_numpy_random_usage PASSED
tests/test_pq_crypto.py::TestKyberKEM::test_encaps_decaps_round_trip PASSED
tests/test_pq_crypto.py::TestPSKDerivation::test_full_kem_psk_flow PASSED
tests/test_wg_manager.py::TestAddPeer::test_add_peer_uses_client_public_key PASSED
tests/test_wg_manager.py::TestPSKRotationRegex::test_no_soh_byte_in_regex_replacement PASSED
tests/test_auth.py::TestTimingSafeComparison::test_hmac_compare_digest_used PASSED
```

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Passive network eavesdropping | WireGuard ChaCha20 + HKDF-derived PSK |
| Harvest-now-decrypt-later (HNDL) | Kyber-512 KEM — quantum-resistant PSK |
| API brute force | fail2ban + rate limiting + timing-safe comparison |
| Compromised API process | Non-root user, sudoers scope, ProtectSystem |
| Config file tampering | Anomaly log SHA-256 hashes, backup-before-write |
| Stale peer credentials | 90-day TTL audit + peer revocation endpoint |
| MITM on API | TLS 1.3 + cert pinning in client |
| SQL injection | No database (WireGuard conf files only) |
| Command injection | Subprocess list-form only (no shell=True) |

---

## Directory Structure

```
securevpn-server/
├── install.sh                  # One-command installer
├── docker-compose.yml          # Container deployment
├── Dockerfile                  # wg-api container image
├── nginx/
│   └── wg-api.conf             # Nginx TLS reverse proxy
├── systemd/
│   ├── wg-api.service          # Gunicorn service (non-root)
│   ├── wg-api-cleanup.service  # Daily peer audit (oneshot)
│   └── wg-api-cleanup.timer    # 03:00 UTC trigger
├── sudoers/
│   └── wg-api                  # Least-privilege wg commands
├── fail2ban/
│   ├── wg-api.conf             # Auth failure filter
│   └── wg-api-jail.conf        # 5-strike ban rule
├── tests/
│   ├── conftest.py             # Shared fixtures
│   ├── test_pq_crypto.py       # KEM + SHAKE-128 tests
│   ├── test_wg_manager.py      # Key consistency + regex tests
│   └── test_auth.py            # Auth + rate limit tests
├── docs/
│   └── azure-deployment.md     # Azure deployment guide
└── wg-api/
    ├── app.py                  # Flask routes
    ├── wsgi.py                 # Gunicorn entry point
    ├── gunicorn.conf.py        # Gunicorn configuration
    ├── config.py               # Server configuration
    ├── requirements.txt
    ├── crypto/
    │   └── pq_crypto.py        # KyberKEM (FO transform, re-encaps, SHAKE-128)
    ├── services/
    │   ├── auth.py             # HMAC signing + API key validation
    │   ├── wg_manager.py       # Peer lifecycle + fcntl.LOCK_EX
    │   └── monitor.py          # Anomaly detection
    └── utils/
        ├── logger.py           # Structured JSON logging
        └── validators.py       # Input validation
```
