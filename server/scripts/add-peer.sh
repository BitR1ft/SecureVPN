#!/bin/bash
# Add Peer Script
# Usage: sudo bash scripts/add-peer.sh <peer_name>

set -euo pipefail

PEER_NAME="${1:-}"

if [ -z "$PEER_NAME" ]; then
    echo "Usage: sudo bash add-peer.sh <peer_name>"
    exit 1
fi

# Validate name
if ! echo "$PEER_NAME" | grep -qE '^[a-zA-Z0-9_-]{1,32}$'; then
    echo "Error: Peer name must be 1-32 chars, alphanumeric/hyphen/underscore"
    exit 1
fi

cd /etc/wireguard

# Generate keys
PEER_PRIV=$(wg genkey)
PEER_PUB=$(echo "$PEER_PRIV" | wg pubkey)
PSK=$(wg genpsk)

# Find next IP
LAST_IP=$(grep -oP 'AllowedIPs = \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' wg0.conf | tail -1 | cut -d. -f4)
if [ -z "$LAST_IP" ]; then
    NEXT_IP="2"
else
    NEXT_IP=$((LAST_IP + 1))
fi

PEER_IP="10.77.0.$NEXT_IP"
SERVER_PUB=$(cat server_public.key)
SERVER_ENDPOINT=$(cat /opt/wg-api/config/env | cut -d= -f2)

# Add to wg0.conf
cat >> wg0.conf <<EOF

# Peer: $PEER_NAME
# Created: $(date -Iseconds)
[Peer]
PublicKey = $PEER_PUB
PresharedKey = $PSK
AllowedIPs = $PEER_IP/32
PersistentKeepalive = 25
EOF

# Apply live
wg set wg0 peer "$PEER_PUB" preshared-key <(echo "$PSK") allowed-ips "$PEER_IP/32"

# Create client config
mkdir -p "/etc/wireguard/peers/$PEER_NAME"
cat > "/etc/wireguard/peers/$PEER_NAME/$PEER_NAME.conf" <<EOF
[Interface]
PrivateKey = $PEER_PRIV
Address = $PEER_IP/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PSK
Endpoint = $SERVER_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 "/etc/wireguard/peers/$PEER_NAME/$PEER_NAME.conf"

# Generate QR
qrencode -t ansiutf8 < "/etc/wireguard/peers/$PEER_NAME/$PEER_NAME.conf"

echo ""
echo "Peer '$PEER_NAME' added successfully!"
echo "IP: $PEER_IP"
echo "Config: /etc/wireguard/peers/$PEER_NAME/$PEER_NAME.conf"
