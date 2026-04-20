#!/bin/bash
# Rotate PSK Script
# Usage: sudo bash scripts/rotate-psk.sh <peer_name>

set -euo pipefail

PEER_NAME="${1:-}"

if [ -z "$PEER_NAME" ]; then
    echo "Usage: sudo bash rotate-psk.sh <peer_name>"
    exit 1
fi

# Find peer public key
PEER_PUB=$(grep -A5 "# Peer: $PEER_NAME" /etc/wireguard/wg0.conf | grep "PublicKey" | awk '{print $3}')

if [ -z "$PEER_PUB" ]; then
    echo "Error: Peer '$PEER_NAME' not found"
    exit 1
fi

# Generate new PSK
NEW_PSK=$(wg genpsk)

# Backup config
cp /etc/wireguard/wg0.conf "/etc/wireguard/wg0.conf.backup.$(date +%Y%m%d_%H%M%S)"

# Update PSK in config
sed -i "/# Peer: $PEER_NAME/,/\[Peer\]/{s/PresharedKey = .*/PresharedKey = $NEW_PSK/}" /etc/wireguard/wg0.conf

# Apply live
wg set wg0 peer "$PEER_PUB" preshared-key <(echo "$NEW_PSK")

# Update client config
CONF_PATH="/etc/wireguard/peers/$PEER_NAME/$PEER_NAME.conf"
if [ -f "$CONF_PATH" ]; then
    sed -i "s/PresharedKey = .*/PresharedKey = $NEW_PSK/" "$CONF_PATH"
fi

echo "PSK rotated for peer '$PEER_NAME'"
echo "New PSK: $NEW_PSK"
echo "Client must reconnect to apply new PSK"
