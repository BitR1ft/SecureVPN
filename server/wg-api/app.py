#!/usr/bin/env python3
"""
SecureVPN Flask API Server
"""

import os
import sys
import json
import base64
import traceback
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

SCRIPT_DIR = Path(__file__).parent.resolve()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from config import (
    API_HOST, API_PORT, API_KEY, SERVER_ENDPOINT,
    LISTEN_PORT, PQ_ENABLED, LOG_LEVEL
)
from services.wg_manager import WireGuardManager
from services.auth import require_api_key, require_signed_request
from services.monitor import AnomalyMonitor
from utils.validators import ValidationError
from utils.logger import setup_logger, log_anomaly

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type", "X-API-Key", "X-Timestamp", "X-Signature"]
    }
})

# Rate limiter — Redis-backed for shared state across Gunicorn workers.
# Fail-closed: if Redis is unreachable, requests are blocked.
try:
    import redis as _redis_module
    _redis_client = _redis_module.StrictRedis(
        host='localhost', port=6379, db=0,
        socket_connect_timeout=1, socket_timeout=1
    )
    _redis_client.ping()
    _RATE_LIMIT_STORAGE = "redis://localhost:6379"
except Exception as _redis_err:
    import sys
    print(
        f"[FATAL] Redis unavailable: {_redis_err}\n"
        "Rate limiting requires Redis. Start Redis: systemctl start redis\n"
        "Refusing to start without centralized rate limit storage.",
        file=sys.stderr
    )
    sys.exit(1)  # fail-closed: do NOT start without Redis

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=_RATE_LIMIT_STORAGE
)

wg_manager = WireGuardManager()
monitor = AnomalyMonitor()
logger = setup_logger('api', Path('/opt/wg-api/logs/api.log'), LOG_LEVEL)


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.errorhandler(ValidationError)
def handle_validation_error(e):
    logger.warning(f"Validation error: {e}")
    return jsonify({'error': 'Validation failed', 'message': str(e)}), 400


@app.errorhandler(Exception)
def handle_generic_error(e):
    error_id = datetime.now().strftime('%Y%m%d_%H%M%S_') + str(id(e))[:8]
    logger.error(f"Unhandled error [{error_id}]: {traceback.format_exc()}")
    return jsonify({
        'error': 'Internal server error',
        'error_id': error_id,
        'message': 'An unexpected error occurred. Contact administrator.'
    }), 500


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint — no auth required."""
    health = monitor.get_system_health()
    status = 200 if 'error' not in health else 503
    return jsonify(health), status


@app.route('/api/v1/status', methods=['GET'])
@require_api_key
def get_status():
    """Get WireGuard interface status."""
    try:
        status = wg_manager.get_status()
        return jsonify({
            'success': True,
            'data': status,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return jsonify({'error': 'Failed to get status'}), 500


@app.route('/api/v1/server-stats', methods=['GET'])
@require_api_key
def get_server_stats():
    """Get server statistics."""
    try:
        stats = wg_manager.get_server_stats()
        return jsonify({
            'success': True,
            'data': stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as e:
        logger.error(f"Stats check failed: {e}")
        return jsonify({'error': 'Failed to get stats'}), 500


@app.route('/api/v1/add-peer', methods=['POST'])
@require_signed_request
@limiter.limit("10 per hour")
def add_peer():
    """
    Add a new WireGuard peer.

    Required fields:
      name        (str) Peer identifier
      public_key  (str) Client's WireGuard public key (base64)

    Optional fields:
      kyber_public_key (str) Client's Kyber-512 public key (base64)

    When kyber_public_key is supplied the server runs the full hybrid PQ flow:
      - Server encapsulates to client's Kyber PK → gets (ciphertext, shared_secret)
      - PSK = HKDF-SHA3-256(shared_secret, info='SecureVPN-PQ-PSK-v1')
      - Response includes kem_ciphertext so the client can decapsulate and
        independently derive the same PSK
    """
    try:
        data = request.get_json(force=False, silent=False)

        if not data:
            return jsonify({'error': 'Missing request body'}), 400

        name = data.get('name')
        public_key = data.get('public_key')
        kyber_public_key = data.get('kyber_public_key')

        if not name or not public_key:
            return jsonify({'error': 'Missing required fields: name, public_key'}), 400

        if monitor.check_brute_force(request.remote_addr):
            return jsonify({'error': 'Too many requests'}), 429

        result = wg_manager.add_peer(name, public_key, kyber_public_key)

        result['endpoint'] = result['endpoint'].replace(
            '<SERVER_ENDPOINT>', SERVER_ENDPOINT
        )

        logger.info(f"Peer added via API: {name} from {request.remote_addr} "
                    f"(PQ method: {result.get('pq_psk_method', 'unknown')})")

        return jsonify({
            'success': True,
            'data': result,
            'post_quantum': PQ_ENABLED,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })

    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Add peer failed: {e}")
        return jsonify({'error': 'Failed to add peer'}), 500


@app.route('/api/v1/rotate-psk', methods=['POST'])
@require_signed_request
@limiter.limit("5 per hour")
def rotate_psk():
    """Rotate pre-shared key for existing peer."""
    try:
        data = request.get_json(force=False, silent=False)

        if not data:
            return jsonify({'error': 'Missing request body'}), 400

        name = data.get('name')
        if not name:
            return jsonify({'error': 'Missing required field: name'}), 400

        new_psk = wg_manager.rotate_psk(name)

        logger.info(f"PSK rotated via API: {name} from {request.remote_addr}")

        return jsonify({
            'success': True,
            'data': {
                'new_psk': new_psk,
                'message': 'PSK rotated successfully. Reconnect to apply.'
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })

    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"PSK rotation failed: {e}")
        return jsonify({'error': 'Failed to rotate PSK'}), 500


@app.route('/api/v1/revoke-peer', methods=['POST'])
@require_signed_request
@limiter.limit("20 per hour")
def revoke_peer():
    """
    Revoke (immediately remove) a WireGuard peer.

    Required fields:
      name (str) — peer to revoke

    Removes peer from live wg0 kernel state immediately (no interface restart),
    removes peer block from wg0.conf, and logs the event for audit.
    """
    try:
        data = request.get_json(force=False, silent=False)
        if not data or not data.get('name'):
            return jsonify({'error': 'Missing required field: name'}), 400

        name = data['name']
        result = wg_manager.revoke_peer(name)

        logger.info(f"Peer revoked via API: {name} by {request.remote_addr}")

        return jsonify({
            'success': True,
            'data': result,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })

    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Peer revocation failed: {e}")
        return jsonify({'error': 'Failed to revoke peer'}), 500


@app.route('/api/v1/audit-peers', methods=['GET'])
@require_api_key
def audit_peers():
    """
    Audit peer lifecycle and flag expired/expiring peers.

    Query params:
      max_age_days (int, default 90) — peers older than this are flagged as expired

    Returns a report with: active, expiring_soon, expired, unknown_age, summary.
    """
    try:
        max_age_days = request.args.get('max_age_days', 90, type=int)
        if max_age_days < 1 or max_age_days > 3650:
            return jsonify({'error': 'max_age_days must be between 1 and 3650'}), 400

        report = wg_manager.audit_peers(max_age_days)

        return jsonify({
            'success': True,
            'data': report,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })

    except Exception as e:
        logger.error(f"Peer audit failed: {e}")
        return jsonify({'error': 'Failed to audit peers'}), 500


@app.route('/api/v1/pq-keygen', methods=['POST'])
@require_api_key
@limiter.limit("5 per hour")
def pq_keygen():
    """
    Post-Quantum KEM Encapsulation Endpoint.

    Flow:
      1. Client generates Kyber keypair: pk, sk = KyberKEM.keygen()
      2. Client POSTs {'kyber_public_key': base64(pk)}
      3. Server encapsulates: ciphertext, shared_secret = KyberKEM.encaps(pk)
      4. Client decapsulates: shared_secret = KyberKEM.decaps(ciphertext, sk)

    The server never generates or stores the client's private key.
    """
    try:
        if not PQ_ENABLED:
            return jsonify({
                'success': False,
                'error': 'Post-quantum cryptography not enabled'
            }), 503

        data = request.get_json(force=False, silent=False)
        if not data or 'kyber_public_key' not in data:
            return jsonify({
                'error': 'Missing required field: kyber_public_key',
                'help': 'Generate a Kyber keypair client-side and send your public key here.'
            }), 400

        from crypto.pq_crypto import KyberKEM

        try:
            client_kyber_pk = base64.b64decode(data['kyber_public_key'])
        except Exception:
            return jsonify({'error': 'Invalid base64 encoding for kyber_public_key'}), 400

        kem = KyberKEM(k=2)
        ciphertext, shared_secret = kem.encaps(client_kyber_pk)

        logger.info(f"PQ encapsulation performed for {request.remote_addr}")

        return jsonify({
            'success': True,
            'data': {
                'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
                'algorithm': 'Kyber-512-SHAKE128-XOF',
                'ciphertext_size': len(ciphertext),
                'note': (
                    'Decapsulate the ciphertext with your Kyber private key '
                    'to recover the shared secret.'
                )
            }
        })

    except Exception as e:
        logger.error(f"PQ encapsulation failed: {e}")
        return jsonify({'error': 'Post-quantum encapsulation failed'}), 500


@app.route('/api/v1/anomalies', methods=['GET'])
@require_api_key
def get_anomalies():
    """Get recent anomalies."""
    try:
        anomalies = monitor.run_all_checks()
        return jsonify({
            'success': True,
            'data': anomalies,
            'count': len(anomalies)
        })
    except Exception as e:
        logger.error(f"Anomaly check failed: {e}")
        return jsonify({'error': 'Failed to check anomalies'}), 500


if __name__ == '__main__':
    print(
        "[ERROR] Do not run app.py directly in production.\n"
        "        Use Gunicorn:  gunicorn --config gunicorn.conf.py wsgi:application\n"
        "        Or systemd:    systemctl start wg-api",
        file=sys.stderr
    )
    sys.exit(1)
