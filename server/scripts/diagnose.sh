#!/bin/bash
# SecureVPN Server Diagnostic Script
# Run this to find out why the API is not working

set -e

echo "========================================"
echo "  SecureVPN Server Diagnostics"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

echo "[1] Checking WireGuard status..."
if systemctl is-active --quiet wg-quick@wg0; then
    echo "  ✓ WireGuard is running"
    wg show wg0 2>/dev/null | head -5 || echo "  ✗ wg show failed"
else
    echo "  ✗ WireGuard is NOT running"
    echo "  Fix: sudo systemctl start wg-quick@wg0"
fi
echo ""

echo "[2] Checking API service status..."
if systemctl is-active --quiet wg-api; then
    echo "  ✓ API service is running"
else
    echo "  ✗ API service is NOT running"
    echo "  Checking last error..."
    journalctl -u wg-api --no-pager -n 20 || true
fi
echo ""

echo "[3] Testing API manually..."
cd /opt/wg-api
export PYTHONPATH=/opt/wg-api/wg-api
export SERVER_ENDPOINT=$(cat /opt/wg-api/config/env 2>/dev/null | cut -d= -f2 || echo "127.0.0.1")

echo "  Running app.py directly for 3 seconds..."
timeout 3 /opt/wg-api/venv/bin/python /opt/wg-api/wg-api/app.py &
PID=$!
sleep 2

# Test health endpoint
echo "  Testing health endpoint..."
if curl -s http://127.0.0.1:5000/api/v1/health > /dev/null 2>&1; then
    echo "  ✓ API responds on localhost"
else
    echo "  ✗ API does NOT respond on localhost"
fi

kill $PID 2>/dev/null || true
echo ""

echo "[4] Checking network binding..."
if ss -tlnp | grep -q ":5000"; then
    echo "  ✓ Something is listening on port 5000"
    ss -tlnp | grep ":5000"
else
    echo "  ✗ Nothing listening on port 5000"
fi
echo ""

echo "[5] Checking firewall..."
if ufw status | grep -q "51820"; then
    echo "  ✓ UFW allows WireGuard port"
else
    echo "  ✗ UFW might block WireGuard"
fi

if ufw status | grep -q "5000"; then
    echo "  ✓ UFW allows API port 5000"
else
    echo "  ⚠ UFW does NOT allow API port 5000 (may be needed for external access)"
    echo "    Fix: sudo ufw allow 5000/tcp"
fi
echo ""

echo "[6] Checking VM network mode..."
IP=$(hostname -I | awk '{print $1}')
echo "  VM IP: $IP"
echo "  If your VM is on NAT, Windows host cannot reach this IP directly."
echo "  Solutions:"
echo "    A) Switch VM to Bridged mode in VM settings"
echo "    B) Set up port forwarding: Host 5000 -> Guest 5000, Host 51820/udp -> Guest 51820/udp"
echo ""

echo "[7] Checking API key..."
if [ -f /opt/wg-api/config/api_key.secret ]; then
    echo "  ✓ API key file exists"
    echo "  Key: $(cat /opt/wg-api/config/api_key.secret)"
else
    echo "  ✗ API key file missing"
fi
echo ""

echo "========================================"
echo "  Diagnostics Complete"
echo "========================================"
