"""
SecureVPN Server Configuration
==============================
Centralized configuration with secure defaults.
"""

import os
import json
import secrets
from pathlib import Path

# Base paths
BASE_DIR = Path('/opt/wg-api')
CONFIG_DIR = BASE_DIR / 'config'
LOG_DIR = BASE_DIR / 'logs'
PEER_DIR = Path('/etc/wireguard/peers')
WG_CONF = Path('/etc/wireguard/wg0.conf')

# Ensure directories exist (only those writable by wg-api user)
# PEER_DIR (/etc/wireguard/peers) is created by install.sh as root.
# Do NOT try to mkdir /etc paths — ProtectSystem=strict blocks it.
for d in [CONFIG_DIR, LOG_DIR]:
    try:
        d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass  # Directory may already exist with root ownership

# Network configuration
VPN_SUBNET = "10.77.0.0/24"
SERVER_IP = "10.77.0.1/24"
LISTEN_PORT = 51820
WAN_INTERFACE = "eth0"

# API Security - BIND TO 0.0.0.0 TO ACCEPT EXTERNAL CONNECTIONS
API_HOST = "0.0.0.0"
API_PORT = 5000
API_KEY_FILE = CONFIG_DIR / 'api_key.secret'

# Post-Quantum settings
PQ_ENABLED = True
PQ_KEM_K = 2

# Rate limiting
RATE_LIMIT_PEER_ADD = "10 per hour"
RATE_LIMIT_STATUS = "100 per minute"
RATE_LIMIT_PSK_ROTATE = "5 per hour"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = LOG_DIR / 'wg-api.log'
ANOMALY_LOG = LOG_DIR / 'anomaly.log'
ROTATION_LOG = LOG_DIR / 'psk-rotations.log'

# Monitoring
ANOMALY_THRESHOLD_HANDSHAKE = 60
ANOMALY_THRESHOLD_RECONNECT = 3
BRUTE_FORCE_THRESHOLD = 10


def load_or_create_api_key() -> str:
    """Load existing API key or generate cryptographically secure one."""
    if API_KEY_FILE.exists():
        return API_KEY_FILE.read_text().strip()

    api_key = secrets.token_urlsafe(32)
    API_KEY_FILE.write_text(api_key)
    os.chmod(API_KEY_FILE, 0o600)
    return api_key


def get_server_public_key() -> str:
    """Read server WireGuard public key."""
    pub_key_file = Path('/etc/wireguard/server_public.key')
    if pub_key_file.exists():
        return pub_key_file.read_text().strip()
    return ""


def get_server_private_key() -> str:
    """Read server WireGuard private key."""
    priv_key_file = Path('/etc/wireguard/server_private.key')
    if priv_key_file.exists():
        return priv_key_file.read_text().strip()
    return ""


# Load configuration
API_KEY = load_or_create_api_key()
SERVER_PUBLIC_KEY = get_server_public_key()
SERVER_ENDPOINT = os.environ.get('SERVER_ENDPOINT', 'your-server-ip')
