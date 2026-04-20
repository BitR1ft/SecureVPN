"""
Input Validation & Security Utilities
=====================================
Principles: Whitelist validation, fail securely, sanitize all inputs.
"""

import re
import ipaddress
from typing import Optional, Tuple

# Validation patterns
PEER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,32}$')
API_KEY_PATTERN = re.compile(r'^[A-Za-z0-9_-]{40,50}$')
PUBLIC_KEY_PATTERN = re.compile(r'^[A-Za-z0-9+/]{43}=$')
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_peer_name(name: str) -> str:
    """
    Validate peer name.
    Rules: alphanumeric, hyphens, underscores; 1-32 chars.
    """
    if not name or not isinstance(name, str):
        raise ValidationError("Peer name must be a non-empty string")

    if not PEER_NAME_PATTERN.match(name):
        raise ValidationError(
            "Peer name must be 1-32 chars, alphanumeric/hyphen/underscore only"
        )

    return name


def validate_public_key(key: str) -> str:
    """Validate WireGuard public key format."""
    if not key or not isinstance(key, str):
        raise ValidationError("Public key must be a non-empty string")

    if not PUBLIC_KEY_PATTERN.match(key):
        raise ValidationError("Invalid WireGuard public key format")

    return key


def validate_api_key(key: str) -> bool:
    """Validate API key format."""
    if not key or not isinstance(key, str):
        return False
    return bool(API_KEY_PATTERN.match(key))


def validate_ip_address(ip: str) -> str:
    """Validate IP address is within VPN subnet."""
    try:
        addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network("10.77.0.0/24")
        if addr not in network:
            raise ValidationError(f"IP {ip} not in VPN subnet")
        return str(addr)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {e}")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    # Remove path separators and null bytes
    sanitized = filename.replace('/', '').replace('\\', '').replace('\x00', '')
    sanitized = sanitized.replace('..', '')

    if not sanitized or sanitized.startswith('.'):
        raise ValidationError("Invalid filename")

    return sanitized


def get_next_ip(existing_ips: list) -> str:
    """
    Get next available IP in subnet.
    Principle: Fail-safe - don't reuse IPs.
    """
    used = set()
    for ip in existing_ips:
        try:
            addr = int(ipaddress.ip_address(ip.split('/')[0]))
            used.add(addr)
        except (ValueError, AttributeError):
            continue

    # Start from .2 (server is .1)
    base = int(ipaddress.ip_address("10.77.0.1"))
    for i in range(2, 254):
        candidate = str(ipaddress.ip_address(base + i))
        if candidate not in used:
            return candidate + "/32"

    raise ValidationError("No available IPs in subnet")


def check_rate_limit(client_ip: str, 
                     action: str, 
                     limit: int, 
                     window: int,
                     store: dict) -> Tuple[bool, int]:
    """
    Simple in-memory rate limiter.
    Returns (allowed, remaining).
    """
    import time
    key = f"{client_ip}:{action}"
    now = time.time()

    if key not in store:
        store[key] = []

    # Clean old entries
    store[key] = [t for t in store[key] if now - t < window]

    if len(store[key]) >= limit:
        return False, 0

    store[key].append(now)
    remaining = limit - len(store[key])
    return True, remaining
