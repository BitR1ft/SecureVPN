"""
SecureVPN WSGI Entry Point
===========================
This file is the Gunicorn entry point.  Never run app.py directly in production.

Usage (systemd calls this):
    gunicorn --config /opt/wg-api/gunicorn.conf.py wsgi:application

Security rationale:
- Gunicorn is a battle-tested production WSGI server.
- Flask's built-in Werkzeug server is a *development* tool only — it is
  single-threaded, lacks graceful shutdown, has no request queuing, and
  the Flask docs explicitly warn against using it in production.
- Running as a non-root user (wg-api) with a UNIX socket means Nginx
  terminates TLS and forwards only validated HTTP to this process.
"""

import sys
from pathlib import Path

# Ensure the wg-api package directory is on the path
SCRIPT_DIR = Path(__file__).parent.resolve()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from app import app as application  # noqa: F401 — Gunicorn looks for `application`

__all__ = ['application']
