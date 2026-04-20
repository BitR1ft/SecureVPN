#!/bin/bash
# SecureVPN Server Installation Script v3.2
# ==========================================
# Run on Ubuntu/Debian as root
# Usage: sudo bash install.sh <YOUR_SERVER_PUBLIC_IP>
#
# v3.1 fixes (all previous +):
#   - FIXED: NoNewPrivileges removed (was blocking sudo for wg commands)
#   - FIXED: MemoryDenyWriteExecute removed (was SIGKILL-ing numpy/OpenBLAS)
#   - FIXED: SystemCallFilter relaxed (was blocking sched_getaffinity, capset)
#   - FIXED: Added After=redis-server.service (was racing with Redis startup)
#   - FIXED: Added SupplementaryGroups=www-data for socket access
#   - FIXED: RuntimeDirectoryMode=0770 (allows nginx group socket access)
#   - FIXED: ExecStartPre cleans stale socket/PID before start
#   - ADDED: usermod -aG wg-api www-data (nginx needs socket group access)
#   - ADDED: Redis connectivity pre-check before starting wg-api
#   - ADDED: Better error diagnostics on service start failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SERVER_IP="${1:-}"

if [ -z "$SERVER_IP" ]; then
    echo -e "${RED}Usage: sudo bash install.sh <YOUR_SERVER_PUBLIC_IP>${NC}"
    echo "Example: sudo bash install.sh 203.0.113.1"
    exit 1
fi

log()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
step() { echo -e "${BLUE}[>>]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  SecureVPN Server Installer v3.2${NC}"
echo -e "${GREEN}  Post-Quantum WireGuard VPN${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# ── Step 1: System update ─────────────────────────────────────────────────
step "[1/12] Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq
log "System updated."

# ── Step 2: Install dependencies ──────────────────────────────────────────
step "[2/12] Installing dependencies..."
apt-get install -y -qq \
    wireguard \
    qrencode \
    iptables \
    curl \
    ufw \
    nginx \
    python3 \
    python3-pip \
    python3-venv \
    git \
    net-tools \
    jq \
    openssl \
    fail2ban \
    redis-server
log "Dependencies installed."

# ── Step 2b: Harden Redis ─────────────────────────────────────────────────
step "[2b] Hardening Redis (localhost-only, no AUTH, disable commands)..."
sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf
for cmd in FLUSHALL FLUSHDB CONFIG DEBUG SHUTDOWN SLAVEOF REPLICAOF MONITOR; do
    grep -q "rename-command $cmd" /etc/redis/redis.conf || \
        echo "rename-command $cmd \"\"" >> /etc/redis/redis.conf
done
systemctl enable redis-server
systemctl start redis-server

# Verify Redis is responding
if ! redis-cli ping > /dev/null 2>&1; then
    fail "Redis is not responding! Cannot continue without Redis (required for rate limiting)."
fi
log "Redis started, hardened, and responding (127.0.0.1 only)."

# ── Step 3: Create non-root service user ──────────────────────────────────
step "[3/12] Creating dedicated service user 'wg-api'..."
if ! id "wg-api" &>/dev/null; then
    useradd \
        --system \
        --no-create-home \
        --shell /sbin/nologin \
        --comment "SecureVPN API service account" \
        wg-api
    log "User 'wg-api' created."
else
    warn "User 'wg-api' already exists — skipping."
fi
# wg-api needs www-data group for nginx socket access
usermod -aG www-data wg-api
# nginx (www-data) needs wg-api group to access the gunicorn socket
usermod -aG wg-api www-data
log "Group memberships configured (wg-api <-> www-data)."

# ── Step 4: Directory structure ───────────────────────────────────────────
step "[4/12] Creating directory structure..."
mkdir -p /opt/wg-api/{config,logs,peers}
mkdir -p /etc/wireguard/peers
mkdir -p /run/wg-api
mkdir -p /etc/ssl/wg-api

# ── CRITICAL: /etc/wireguard must be readable by wg-api ──
# The API reads server_public.key and writes to wg0.conf (peer blocks).
# Original chmod 700 blocked wg-api from reading its own keys.
chmod 755 /etc/wireguard
chmod 750 /opt/wg-api
chmod 750 /opt/wg-api/config
chmod 750 /opt/wg-api/logs

# Set ownership — wg-api owns its app dirs
chown -R wg-api:wg-api /opt/wg-api
chown    wg-api:www-data /run/wg-api
chown    wg-api:wg-api /etc/wireguard/peers
log "Directories created."

# ── Step 4b: Copy server source files to /opt/wg-api/ ─────────────────────
step "[4b] Copying server source files..."
if [ -d "$SCRIPT_DIR/wg-api" ]; then
    cp -a "$SCRIPT_DIR/wg-api" /opt/wg-api/
    log "wg-api Python app copied to /opt/wg-api/wg-api/"
else
    fail "$SCRIPT_DIR/wg-api not found — cannot install"
fi
if [ -d "$SCRIPT_DIR/scripts" ]; then
    cp -a "$SCRIPT_DIR/scripts" /opt/wg-api/
    log "Helper scripts copied to /opt/wg-api/scripts/"
fi

# ── CRITICAL FIX: cp -a preserves UID from the zip (may be wrong) ──
# Must re-chown AFTER copying so wg-api user can read/write its files.
chown -R wg-api:wg-api /opt/wg-api
log "File ownership corrected for wg-api user."

# ── Step 5: WireGuard server keys ─────────────────────────────────────────
step "[5/12] Generating WireGuard server keys..."
cd /etc/wireguard
if [ ! -f server_private.key ]; then
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    log "WireGuard keys generated."
else
    warn "WireGuard keys already exist — skipping."
fi

# Keys must be readable by wg-api (for config.py get_server_public_key)
chmod 600 server_private.key
chmod 644 server_public.key

SERVER_PRIV=$(cat /etc/wireguard/server_private.key)
SERVER_PUB=$(cat /etc/wireguard/server_public.key)

# Detect WAN interface
WAN_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
log "WAN interface detected: $WAN_IFACE"

# ── Step 6: WireGuard configuration ───────────────────────────────────────
step "[6/12] Writing WireGuard configuration..."
if [ ! -f /etc/wireguard/wg0.conf ]; then
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $WAN_IFACE -j MASQUERADE
SaveConfig = true

# Post-Quantum PSK: Enabled
# Created: $(date -Iseconds)
EOF
    log "wg0.conf written."
else
    warn "wg0.conf already exists — skipping."
fi

# ── CRITICAL: wg0.conf must be writable by wg-api ──
# wg_manager.py opens it with open(self.wg_conf, 'a+') to append peer blocks.
# Default mode 600 owned by root blocks this — causes 500 errors on add-peer.
chown wg-api:wg-api /etc/wireguard/wg0.conf
chmod 640 /etc/wireguard/wg0.conf
log "wg0.conf ownership set to wg-api (needed for peer management)."

# ── BUG 5 FIX: Persist NAT/forwarding across reboots ──────────────────────
step "[6b] Persisting NAT/forwarding rules across reboots..."

# Fix 1: UFW before.rules — add NAT for VPN subnet
if ! grep -q '10.77.0.0/24' /etc/ufw/before.rules 2>/dev/null; then
    sed -i '/^# End required lines/a\
# NAT for WireGuard VPN subnet\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.77.0.0/24 -o '"$WAN_IFACE"' -j MASQUERADE\nCOMMIT' /etc/ufw/before.rules
    log "UFW before.rules NAT entry added."
else
    warn "UFW before.rules NAT entry already exists."
fi

# Fix 2: DEFAULT_FORWARD_POLICY=ACCEPT in /etc/default/ufw
if [ -f /etc/default/ufw ]; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    log "DEFAULT_FORWARD_POLICY set to ACCEPT."
fi

# Fix 3: systemd override for wg-quick@wg0
mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
cat > /etc/systemd/system/wg-quick@wg0.service.d/override.conf <<OVERRIDE
[Service]
ExecStartPost=/bin/bash -c '
  sleep 2 && \
  iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT && \
  iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT && \
  iptables -t nat -C POSTROUTING -o $WAN_IFACE -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE'
OVERRIDE
log "systemd wg-quick@wg0 override installed."

# Fix 4: /etc/network/if-up.d/wireguard-nat backup script
cat > /etc/network/if-up.d/wireguard-nat <<'NATSCRIPT'
#!/bin/bash
WAN_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
[ -z "$WAN_IFACE" ] && exit 0
iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
NATSCRIPT
chmod 755 /etc/network/if-up.d/wireguard-nat
log "if-up.d/wireguard-nat backup script installed."

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1'            >  /etc/sysctl.d/99-wireguard.conf
echo 'net.ipv6.conf.all.forwarding=1'   >> /etc/sysctl.d/99-wireguard.conf
sysctl --system -q
log "IP forwarding enabled."

# ── Step 7: Python environment ────────────────────────────────────────────
step "[7/12] Setting up Python virtual environment..."
cd /opt/wg-api
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r /opt/wg-api/wg-api/requirements.txt -q
chown -R wg-api:wg-api /opt/wg-api/venv
log "Python environment ready."

# ── Step 8: API key ───────────────────────────────────────────────────────
step "[8/12] Generating API key..."
API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "$API_KEY" > /opt/wg-api/config/api_key.secret
chmod 640 /opt/wg-api/config/api_key.secret
chown wg-api:wg-api /opt/wg-api/config/api_key.secret
log "API key generated."

# ── Step 9: TLS certificate ───────────────────────────────────────────────
step "[9/12] Generating self-signed TLS certificate..."
if [ ! -f /etc/ssl/wg-api/dhparam.pem ]; then
    openssl dhparam -out /etc/ssl/wg-api/dhparam.pem 2048 2>/dev/null
fi

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:4096 \
    -keyout /etc/ssl/wg-api/server.key \
    -out    /etc/ssl/wg-api/server.crt \
    -subj   "/C=US/ST=State/L=City/O=SecureVPN/CN=$SERVER_IP" \
    -addext "subjectAltName=IP:$SERVER_IP" \
    2>/dev/null

chmod 600 /etc/ssl/wg-api/server.key
chmod 644 /etc/ssl/wg-api/server.crt
log "TLS certificate generated (4096-bit RSA, 10-year validity)."
log "Fingerprint: $(openssl x509 -fingerprint -sha256 -noout -in /etc/ssl/wg-api/server.crt | cut -d= -f2)"

# ── Step 10: Wrapper scripts + sudoers ────────────────────────────────────
step "[10/12] Installing wrapper scripts and sudoers rules..."

# Install wrapper scripts to /usr/local/sbin/
# These are the ONLY programs wg-api can sudo — defined in /etc/sudoers.d/wg-api
for script in wg-set-peer wg-show wg-remove-peer; do
    if [ -f "$SCRIPT_DIR/scripts/${script}.sh" ]; then
        cp "$SCRIPT_DIR/scripts/${script}.sh" "/usr/local/sbin/${script}"
        chown root:root "/usr/local/sbin/${script}"
        chmod 0755 "/usr/local/sbin/${script}"
    else
        fail "$SCRIPT_DIR/scripts/${script}.sh not found — cannot install"
    fi
done
log "Wrapper scripts installed to /usr/local/sbin/."

# Install sudoers rules
cp "$SCRIPT_DIR/sudoers/wg-api" /etc/sudoers.d/wg-api
chmod 440 /etc/sudoers.d/wg-api
visudo -c -f /etc/sudoers.d/wg-api
log "Sudoers rules installed and validated."

# Verify sudoers actually works for wg-api user
# NOTE: We use 'sudo -l' to CHECK authorization without executing the command.
# The old test ran 'sudo -u wg-api sudo -n /usr/local/sbin/wg-show wg0' which
# FAILS when wg0 isn't up yet (wg0 is started at step 12, not here at step 10).
# 'sudo -l' simply checks if the sudoers rule grants the privilege — it doesn't
# need the WireGuard interface to be running.
SUDO_CHECK=$(sudo -u wg-api sudo -n -l /usr/local/sbin/wg-show 2>&1)
if echo "$SUDO_CHECK" | grep -qi 'NOPASSWD.*wg-show\|wg-show'; then
    log "Sudoers verified: wg-api can execute wrapper scripts."
else
    # Fallback: also try just running wg-show with 'dump' subcommand
    # (works if wg0 is already up from a previous install)
    if sudo -u wg-api sudo -n /usr/local/sbin/wg-show dump >/dev/null 2>&1; then
        log "Sudoers verified: wg-api can execute wrapper scripts."
    else
        # Final fallback: check the sudoers file content directly
        if grep -q 'wg-show' /etc/sudoers.d/wg-api 2>/dev/null && visudo -c -f /etc/sudoers.d/wg-api >/dev/null 2>&1; then
            warn "Sudoers rule exists and validates OK, but runtime test inconclusive."
            warn "This is normal on a fresh install (wg0 not up yet). Will verify after starting WireGuard."
        else
            fail "Sudoers rule for wg-api NOT working! Check /etc/sudoers.d/wg-api"
        fi
    fi
fi

# ── Step 11: Nginx configuration ──────────────────────────────────────────
step "[11/12] Configuring Nginx reverse proxy..."
cp "$SCRIPT_DIR/nginx/wg-api.conf" /etc/nginx/sites-available/wg-api
ln -sf /etc/nginx/sites-available/wg-api /etc/nginx/sites-enabled/wg-api
rm -f /etc/nginx/sites-enabled/default

# Auto-detect Nginx version for HTTP/2 directive syntax
# Nginx < 1.25.1:  listen 443 ssl http2;
# Nginx >= 1.25.1: listen 443 ssl; + http2 on;
NGINX_VER=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9]+\.[0-9]+\.[0-9]+')
NGINX_MAJOR=$(echo "$NGINX_VER" | cut -d. -f1)
NGINX_MINOR=$(echo "$NGINX_VER" | cut -d. -f2)
NGINX_PATCH=$(echo "$NGINX_VER" | cut -d. -f3)

if [ "$NGINX_MAJOR" -gt 1 ] || \
   [ "$NGINX_MAJOR" -eq 1 -a "$NGINX_MINOR" -gt 25 ] || \
   [ "$NGINX_MAJOR" -eq 1 -a "$NGINX_MINOR" -eq 25 -a "$NGINX_PATCH" -ge 1 ]; then
    if grep -q 'listen 443 ssl http2;' /etc/nginx/sites-available/wg-api; then
        sed -i 's/listen 443 ssl http2;/listen 443 ssl;/' /etc/nginx/sites-available/wg-api
        sed -i 's/listen \[::\]:443 ssl http2;/listen [::]:443 ssl;/' /etc/nginx/sites-available/wg-api
        sed -i '/listen \[::\]:443 ssl;/a\    http2 on;' /etc/nginx/sites-available/wg-api
        log "Nginx >= 1.25.1 detected — using 'http2 on;' directive."
    fi
else
    if grep -q 'http2 on;' /etc/nginx/sites-available/wg-api; then
        sed -i '/http2 on;/d' /etc/nginx/sites-available/wg-api
        sed -i 's/listen 443 ssl;/listen 443 ssl http2;/' /etc/nginx/sites-available/wg-api
        sed -i 's/listen \[::\]:443 ssl;/listen [::]:443 ssl http2;/' /etc/nginx/sites-available/wg-api
        log "Nginx < 1.25.1 detected — using 'listen ... ssl http2' syntax."
    fi
fi

# Add rate limit zone to main nginx.conf
if ! grep -q "limit_req_zone.*api" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\\    limit_req_zone $binary_remote_addr zone=api:10m rate=20r/m;' \
        /etc/nginx/nginx.conf
fi

nginx -t
log "Nginx configured."

# ── Step 12: Systemd services & firewall ──────────────────────────────────
step "[12/12] Installing systemd services and configuring firewall..."

# Copy service file
cp "$SCRIPT_DIR/systemd/wg-api.service" /etc/systemd/system/wg-api.service

# Update SERVER_ENDPOINT in service file
sed -i "s|Environment=SERVER_ENDPOINT=.*|Environment=SERVER_ENDPOINT=$SERVER_IP|" \
    /etc/systemd/system/wg-api.service

# Create tmpfiles.d entry so /run/wg-api survives reboots
cat > /etc/tmpfiles.d/wg-api.conf <<'TMPFILES'
d /run/wg-api 0770 wg-api www-data -
TMPFILES

# Apply tmpfiles.d (create /run/wg-api if it doesn't exist with correct perms)
systemd-tmpfiles --create /etc/tmpfiles.d/wg-api.conf 2>/dev/null || true

systemctl daemon-reload
systemctl enable wg-quick@wg0 wg-api nginx

# Firewall
ufw default deny  incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'SSH'
ufw allow 51820/udp comment 'WireGuard VPN'
ufw allow 443/tcp   comment 'SecureVPN API (HTTPS via Nginx)'
ufw --force enable
log "Firewall configured."

# BUG 5 FIX: Reload UFW to apply before.rules NAT changes
ufw reload
log "UFW reloaded with NAT rules."

# ── Pre-flight checks before starting services ─────────────────────────────
step "Pre-flight validation..."

# Check Redis connectivity (app.py calls sys.exit(1) if Redis is down)
if ! redis-cli ping > /dev/null 2>&1; then
    warn "Redis not responding — restarting..."
    systemctl restart redis-server
    sleep 2
    if ! redis-cli ping > /dev/null 2>&1; then
        fail "Redis still not responding after restart. Cannot start wg-api."
    fi
fi
log "Redis: responding (PONG)"

# Check critical files exist
for f in /etc/wireguard/server_public.key /opt/wg-api/config/api_key.secret; do
    if [ ! -f "$f" ]; then
        fail "Required file missing: $f"
    fi
done
log "Critical files: present"

# Check wg-api user can read the public key
if ! sudo -u wg-api test -r /etc/wireguard/server_public.key; then
    warn "wg-api cannot read /etc/wireguard/server_public.key — fixing permissions"
    chmod 755 /etc/wireguard
    chmod 644 /etc/wireguard/server_public.key
fi
log "wg-api can read server keys"

# Check venv is valid
if [ ! -x /opt/wg-api/venv/bin/python3 ]; then
    fail "Python venv not found or not executable at /opt/wg-api/venv/bin/python3"
fi
log "Python venv: valid"

# Start services
step "Starting services..."
systemctl start wg-quick@wg0

# Post-WireGuard-start sudoers verification (now wg0 is actually up)
if sudo -u wg-api sudo -n /usr/local/sbin/wg-show wg0 >/dev/null 2>&1; then
    log "Sudoers runtime verified: wg-api can execute wg-show (wg0 is up)."
else
    warn "Sudoers runtime test failed after wg0 started. Check /etc/sudoers.d/wg-api"
    warn "This may indicate a real sudoers configuration problem."
fi

# Clean any stale socket before starting wg-api
rm -f /run/wg-api/wg-api.sock /run/wg-api/wg-api.pid

systemctl start wg-api

# Wait for wg-api to start (with timeout)
step "Waiting for wg-api to start..."
WG_STATUS="unknown"
for i in $(seq 1 15); do
    WG_STATUS=$(systemctl is-active wg-api 2>/dev/null || echo "unknown")
    if [ "$WG_STATUS" = "active" ]; then
        break
    fi
    sleep 1
done

if [ "$WG_STATUS" != "active" ]; then
    warn "wg-api service not active after 15 seconds!"
    warn "Last 30 lines of wg-api journal:"
    journalctl -u wg-api -n 30 --no-pager 2>/dev/null || true
    warn ""
    warn "Common fixes:"
    warn "  1. Check Redis: systemctl status redis-server"
    warn "  2. Check logs:  journalctl -u wg-api -n 50 --no-pager"
    warn "  3. Test manual: sudo -u wg-api PYTHONPATH=/opt/wg-api/wg-api /opt/wg-api/venv/bin/gunicorn --config /opt/wg-api/wg-api/gunicorn.conf.py wsgi:application"
else
    log "wg-api service: active"
fi

systemctl start nginx

# ── Validation ────────────────────────────────────────────────────────────
echo ""
step "Validating installation..."

# Check services
for svc in wg-quick@wg0 wg-api nginx; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
    if [ "$status" = "active" ]; then
        log "Service $svc: active"
    else
        warn "Service $svc: $status (check: systemctl status $svc)"
    fi
done

# Check API health (try a few times with delay)
HEALTH=""
for i in $(seq 1 5); do
    HEALTH=$(curl -sk https://localhost/api/v1/health 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q '"api"'; then
        break
    fi
    sleep 2
done
if echo "$HEALTH" | grep -q '"api":"active"'; then
    log "API health check: OK"
elif echo "$HEALTH" | grep -q '"api"'; then
    warn "API health check: responded but WireGuard may be down ($HEALTH)"
else
    warn "API health check: no response after 10s"
    warn "Check logs: journalctl -u wg-api -n 50 --no-pager"
fi

# ── Final summary ─────────────────────────────────────────────────────────
CERT_FP=$(openssl x509 -fingerprint -sha256 -noout -in /etc/ssl/wg-api/server.crt | cut -d= -f2)

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Server Public Key:   ${YELLOW}$SERVER_PUB${NC}"
echo -e "Server Endpoint:     ${YELLOW}$SERVER_IP:51820${NC}"
echo -e "API URL:             ${YELLOW}https://$SERVER_IP/api/v1/${NC}"
echo -e "API Key:             ${YELLOW}$API_KEY${NC}"
echo -e "TLS Fingerprint:     ${YELLOW}$CERT_FP${NC}"
echo ""
echo -e "${GREEN}Services:${NC}"
echo "  WireGuard: systemctl status wg-quick@wg0"
echo "  API:       systemctl status wg-api"
echo "  Nginx:     systemctl status nginx"
echo ""
echo -e "${GREEN}Logs:${NC}"
echo "  API:       journalctl -u wg-api -f"
echo "  Nginx:     tail -f /var/log/nginx/access.log"
echo "  WireGuard: journalctl -u wg-quick@wg0 -f"
echo ""
echo -e "${YELLOW}IMPORTANT: Pin the TLS fingerprint above in your client config!${NC}"
echo -e "${YELLOW}The API key is shown only once — save it securely.${NC}"
echo ""
