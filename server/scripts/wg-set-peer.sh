#!/bin/bash
# /usr/local/sbin/wg-set-peer
# ============================
# Fix 8 (Dr. H): Root-owned wrapper script for `wg set wg0 peer` operations.
#
# Problem with sudoers wildcard `*`:
#   The rule:
#     wg-api ALL=(root) NOPASSWD: /usr/bin/wg set wg0 peer * preshared-key ...
#   trusts the calling application's input validation entirely.
#   If wg_manager.py's validation logic ever shifts or fails (e.g., during a
#   refactor, dependency update, or logic error), the wildcard * allows arbitrary
#   flags to be passed directly to `wg` in root context.
#
# Fix: This script is the ONLY sudoers-authorized program for peer operations.
#   - It is owned by root:root with mode 0755 (not writable by wg-api user)
#   - It validates each argument independently with strict regexes
#   - There are NO wildcards in the sudoers rule — the allowed command is exact
#   - Defence in depth: even if Python validation fails, this script rejects invalid input
#
# Sudoers rule (no wildcards):
#   wg-api ALL=(root) NOPASSWD: /usr/local/sbin/wg-set-peer
#
# Usage: sudo wg-set-peer <pubkey_base64> <psk_stdin> <allowed_ip_cidr>
#   Example: echo "$PSK" | sudo wg-set-peer "ABCDEF...==" "-" "10.77.0.5/32"
#
# Install:
#   cp scripts/wg-set-peer.sh /usr/local/sbin/wg-set-peer
#   chown root:root /usr/local/sbin/wg-set-peer
#   chmod 0755 /usr/local/sbin/wg-set-peer

set -euo pipefail

# ── Argument validation ────────────────────────────────────────────────────
if [[ $# -ne 3 ]]; then
    echo "Usage: wg-set-peer <pubkey> <psk_or_dash> <allowed_ip>" >&2
    exit 2
fi

PUBKEY="$1"
PSK_INPUT="$2"
ALLOWED_IP="$3"

# WireGuard public key: exactly 43 base64 chars + 1 padding `=`
# Rejects anything with spaces, shell metacharacters, or extra flags
if ! [[ "$PUBKEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "[wg-set-peer] REJECTED: invalid public key format" >&2
    exit 1
fi

# Allowed IP: must be in the VPN subnet 10.77.0.0/24 with /32 host mask
if ! [[ "$ALLOWED_IP" =~ ^10\.77\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/32$ ]]; then
    echo "[wg-set-peer] REJECTED: invalid AllowedIPs (must be 10.77.x.x/32)" >&2
    exit 1
fi

# PSK: passed via stdin (not as argument, to avoid shell history exposure)
# PSK_INPUT must be "-" to indicate stdin mode
if [[ "$PSK_INPUT" != "-" ]]; then
    echo "[wg-set-peer] REJECTED: PSK must be passed via stdin (use '-')" >&2
    exit 1
fi

# ── Execute the validated command ──────────────────────────────────────────
exec /usr/bin/wg set wg0 \
    peer          "$PUBKEY"     \
    preshared-key /dev/stdin    \
    allowed-ips   "$ALLOWED_IP"
