FROM python:3.11-slim-bookworm

LABEL maintainer="SecureVPN Team"
LABEL description="SecureVPN API Server — Post-Quantum WireGuard VPN"
LABEL version="2.0"

# ── Security: run as non-root ──────────────────────────────────────────────
# Create service user before installing anything
RUN groupadd -r wg-api && \
    useradd -r -g wg-api -s /sbin/nologin -c "SecureVPN API" wg-api

# ── System dependencies ────────────────────────────────────────────────────
# wireguard-tools provides 'wg' binary for key generation
# We do NOT install the kernel module here — WireGuard runs on the host
RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        iproute2 \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────
WORKDIR /app
COPY wg-api/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Application code ───────────────────────────────────────────────────────
COPY wg-api/ /app/wg-api/
COPY sudoers/wg-api /etc/sudoers.d/wg-api
RUN chmod 440 /etc/sudoers.d/wg-api && \
    visudo -c -f /etc/sudoers.d/wg-api

# ── Runtime directories ────────────────────────────────────────────────────
RUN mkdir -p /opt/wg-api/logs \
             /opt/wg-api/config \
             /run/wg-api && \
    chown -R wg-api:wg-api /opt/wg-api /run/wg-api

# Mount points (provided by docker-compose volumes):
#   /etc/wireguard   — WireGuard config (host-managed)
#   /opt/wg-api/config — API key, server endpoint
#   /opt/wg-api/logs   — persistent logs

# ── Healthcheck ────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/v1/health', timeout=3)" \
    || exit 1

# ── Switch to non-root user ────────────────────────────────────────────────
USER wg-api
WORKDIR /app/wg-api

EXPOSE 5000

# Gunicorn starts via docker-compose command (not CMD here) so
# environment variables from the compose file are available.
CMD ["gunicorn", "--config", "/app/wg-api/gunicorn.conf.py", "wsgi:application"]
