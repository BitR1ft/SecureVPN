#!/bin/bash
# Quick Fix Script for SecureVPN Server
# Run this ON THE KALI VM to fix common issues

set -e

echo "========================================"
echo "  SecureVPN Server Quick Fix"
echo "========================================"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

cd /opt/wg-api/wg-api || {
    echo "ERROR: /opt/wg-api/wg-api not found. Did you run install.sh?"
    exit 1
}

echo "[1] Stopping API service..."
systemctl stop wg-api 2>/dev/null || true

echo "[2] Checking for syntax errors..."
/opt/wg-api/venv/bin/python -m py_compile app.py && echo "  ✓ app.py OK" || echo "  ✗ app.py has errors"
/opt/wg-api/venv/bin/python -m py_compile config.py && echo "  ✓ config.py OK" || echo "  ✗ config.py has errors"
/opt/wg-api/venv/bin/python -m py_compile services/wg_manager.py && echo "  ✓ wg_manager.py OK" || echo "  ✗ wg_manager.py has errors"
/opt/wg-api/venv/bin/python -m py_compile services/auth.py && echo "  ✓ auth.py OK" || echo "  ✗ auth.py has errors"
/opt/wg-api/venv/bin/python -m py_compile services/monitor.py && echo "  ✓ monitor.py OK" || echo "  ✗ monitor.py has errors"
/opt/wg-api/venv/bin/python -m py_compile utils/validators.py && echo "  ✓ validators.py OK" || echo "  ✗ validators.py has errors"
/opt/wg-api/venv/bin/python -m py_compile utils/logger.py && echo "  ✓ logger.py OK" || echo "  ✗ logger.py has errors"

echo ""
echo "[3] Testing API startup..."
export PYTHONPATH=/opt/wg-api/wg-api
export SERVER_ENDPOINT=$(cat /opt/wg-api/config/env 2>/dev/null | cut -d= -f2 || echo "127.0.0.1")

timeout 5 /opt/wg-api/venv/bin/python app.py &
PID=$!
sleep 3

if curl -s http://127.0.0.1:5000/api/v1/health > /dev/null 2>&1; then
    echo "  ✓ API starts successfully"
else
    echo "  ✗ API failed to start"
    echo "  Showing error log:"
    journalctl -u wg-api --no-pager -n 30 || true
fi

kill $PID 2>/dev/null || true

echo ""
echo "[4] Updating systemd service..."
cat > /etc/systemd/system/wg-api.service <<'EOF'
[Unit]
Description=SecureVPN WireGuard API Server
After=network-online.target wg-quick@wg0.service
Wants=network-online.target wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wg-api
Environment=SERVER_ENDPOINT=127.0.0.1
Environment=PYTHONPATH=/opt/wg-api/wg-api
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/wg-api/venv/bin/python /opt/wg-api/wg-api/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo ""
echo "[5] Opening API port in firewall..."
ufw allow 5000/tcp comment 'SecureVPN API' 2>/dev/null || true

echo ""
echo "[6] Starting API service..."
systemctl start wg-api
sleep 2

if systemctl is-active --quiet wg-api; then
    echo "  ✓ API service is now running"
    echo ""
    echo "========================================"
    echo "  FIX COMPLETE"
    echo "========================================"
    echo ""
    echo "API is running on port 5000"
    echo "Test: curl http://127.0.0.1:5000/api/v1/health"
    echo ""
    echo "IMPORTANT: If your VM is on NAT, you need to either:"
    echo "  A) Switch VM network to Bridged mode, OR"
    echo "  B) Set up port forwarding in VM settings:"
    echo "     - Host 5000 -> Guest 5000 (TCP)"
    echo "     - Host 51820 -> Guest 51820 (UDP)"
    echo ""
else
    echo "  ✗ API service still failing"
    echo "  Check logs: journalctl -u wg-api -f"
fi
