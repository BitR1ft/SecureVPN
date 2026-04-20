"""
Gunicorn Configuration File — SecureVPN API
=============================================
Loaded automatically by: gunicorn --config gunicorn.conf.py wsgi:application

Security decisions documented inline.
"""

import multiprocessing
import os

# ---------------------------------------------------------------------------
# Server socket — UNIX socket, not TCP.
# Nginx forwards to this socket; the socket is never exposed to the network.
# ---------------------------------------------------------------------------
bind = "unix:/run/wg-api/wg-api.sock"
umask = 0o007   # Socket readable only by wg-api user + nginx group (www-data)

# ---------------------------------------------------------------------------
# Worker processes
# Rule of thumb: 2 * CPU_count + 1  (but cap low for a VPN server)
# ---------------------------------------------------------------------------
workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
# BUG 7 FIX: When threads > 1, Gunicorn auto-upgrades to "gthread" worker
# class and prints a warning on every startup:
#   "Worker class 'sync' does not support threads, auto-upgrading to 'gthread'"
# This is confusing and suggests misconfiguration. Since we explicitly
# want threads=2 for burst handling, we set worker_class="gthread" to
# match the actual runtime behaviour and suppress the warning.
worker_class = "gthread"
threads = 2                     # Two threads per worker handles bursts cleanly
timeout = 30                    # Kill hung workers after 30 s
graceful_timeout = 20           # Wait 20 s for in-flight requests on reload
keepalive = 5

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
limit_request_line = 4096       # Max HTTP request line size (mitigate slowloris)
limit_request_fields = 50       # Max HTTP header fields
limit_request_field_size = 4096

# ---------------------------------------------------------------------------
# Process naming & PID
# ---------------------------------------------------------------------------
proc_name = "wg-api"
pidfile = "/run/wg-api/wg-api.pid"

# ---------------------------------------------------------------------------
# Logging — structured JSON to journal (captured by systemd)
# ---------------------------------------------------------------------------
accesslog = "-"   # stdout → journald
errorlog  = "-"   # stderr → journald
loglevel  = "info"
access_log_format = (
    '{"time":"%(t)s","remote":"%({X-Forwarded-For}i)s",'
    '"method":"%(m)s","path":"%(U)s","status":%(s)s,'
    '"bytes":%(B)s,"duration_ms":%(D)s}'
)

# ---------------------------------------------------------------------------
# Server hooks
# ---------------------------------------------------------------------------
def on_starting(server):
    """Validate critical files exist before accepting connections."""
    required = [
        "/etc/wireguard/server_public.key",
        "/opt/wg-api/config/api_key.secret",
    ]
    for path in required:
        if not os.path.exists(path):
            raise RuntimeError(
                f"[gunicorn] Required file missing: {path}. "
                "Run install.sh first."
            )


def worker_exit(server, worker):
    """Log worker exits for anomaly detection."""
    server.log.info(f"[gunicorn] Worker {worker.pid} exited")
