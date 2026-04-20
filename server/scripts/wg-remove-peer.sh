#!/bin/bash
# /usr/local/sbin/wg-remove-peer
# ================================
# Fix 8 (Dr. H): Root-owned wrapper for removing a WireGuard peer.
# See wg-set-peer.sh for detailed rationale.
#
# Sudoers rule: wg-api ALL=(root) NOPASSWD: /usr/local/sbin/wg-remove-peer
# Usage: sudo wg-remove-peer <pubkey_base64>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: wg-remove-peer <pubkey>" >&2
    exit 2
fi

PUBKEY="$1"

if ! [[ "$PUBKEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "[wg-remove-peer] REJECTED: invalid public key format" >&2
    exit 1
fi

exec /usr/bin/wg set wg0 peer "$PUBKEY" remove
