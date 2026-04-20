"""
Authentication & Authorization Service

Request signing protocol:
  canonical = f"{METHOD}:{path}:{timestamp}:{sha256(body)}"
  signature  = HMAC-SHA256(api_key, canonical.encode())

Required headers:
  X-API-Key:   <api_key>
  X-Timestamp: <unix_seconds_utc>
  X-Signature: <hex(signature)>
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional
from functools import wraps
from flask import request, jsonify

from config import API_KEY
from utils.validators import validate_api_key
from utils.logger import setup_logger, log_anomaly
from pathlib import Path

logger = setup_logger('auth', Path('/opt/wg-api/logs/auth.log'))

# Replay window: ±300 seconds (5 minutes)
_REPLAY_WINDOW_SECONDS = 300


class AuthenticationError(Exception):
    """Authentication/authorization failure."""
    pass


def require_api_key(f):
    """
    Decorator: require valid X-API-Key header.
    Timing-safe comparison via hmac.compare_digest.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            logger.warning(f"Missing API key from {request.remote_addr}")
            log_anomaly('missing_api_key', {
                'source_ip': request.remote_addr,
                'endpoint': request.endpoint
            }, severity='WARNING')
            return jsonify({'error': 'Missing API key'}), 401

        if not validate_api_key(api_key):
            logger.warning(f"Invalid API key format from {request.remote_addr}")
            return jsonify({'error': 'Invalid API key format'}), 401

        if not hmac.compare_digest(api_key, API_KEY):
            logger.warning(f"Invalid API key from {request.remote_addr}")
            log_anomaly('invalid_api_key', {
                'source_ip': request.remote_addr,
                'endpoint': request.endpoint
            }, severity='ALERT')
            return jsonify({'error': 'Invalid API key'}), 403

        return f(*args, **kwargs)
    return decorated


def require_signed_request(f):
    """
    HMAC-SHA256 request signing decorator.

    Wraps require_api_key. Validates X-Timestamp (within ±300s) and
    X-Signature against the canonical string:
      "{METHOD}:{path}:{timestamp}:{hex(sha256(body))}"

    Apply to mutating endpoints. Read-only endpoints use require_api_key only.
    """
    @wraps(f)
    @require_api_key
    def decorated(*args, **kwargs):
        api_key   = request.headers.get('X-API-Key', '')
        timestamp = request.headers.get('X-Timestamp', '')
        signature = request.headers.get('X-Signature', '')

        if not timestamp:
            return jsonify({'error': 'Missing X-Timestamp header'}), 401

        try:
            req_time = int(timestamp)
        except ValueError:
            return jsonify({'error': 'Invalid X-Timestamp: must be Unix epoch seconds'}), 401

        delta = abs(int(time.time()) - req_time)
        if delta > _REPLAY_WINDOW_SECONDS:
            logger.warning(
                f"Replay attack blocked from {request.remote_addr}: "
                f"timestamp delta={delta}s (window={_REPLAY_WINDOW_SECONDS}s)"
            )
            log_anomaly('replay_attack_blocked', {
                'source_ip': request.remote_addr,
                'endpoint':  request.endpoint,
                'timestamp_delta_seconds': str(delta),
            }, severity='ALERT')
            return jsonify({
                'error': 'Request timestamp expired',
                'detail': f'Timestamp must be within ±{_REPLAY_WINDOW_SECONDS}s of server time',
            }), 401

        if not signature:
            return jsonify({'error': 'Missing X-Signature header'}), 401

        body      = request.get_data() or b''
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{request.method}:{request.path}:{timestamp}:{body_hash}"

        expected_sig = hmac.new(
            api_key.encode('utf-8'),
            canonical.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            logger.warning(f"Invalid request signature from {request.remote_addr}")
            log_anomaly('invalid_request_signature', {
                'source_ip': request.remote_addr,
                'endpoint':  request.endpoint,
                'canonical': canonical[:80],
            }, severity='ALERT')
            return jsonify({'error': 'Invalid request signature'}), 403

        return f(*args, **kwargs)
    return decorated


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token."""
    return secrets.token_urlsafe(length)


def hash_secret(secret: str) -> str:
    """Hash a secret using PBKDF2."""
    salt = secrets.token_hex(16)
    hash_val = hashlib.pbkdf2_hmac(
        'sha256', secret.encode(), salt.encode(), 100000
    ).hex()
    return f"{salt}${hash_val}"


def verify_secret(secret: str, hashed: str) -> bool:
    """Verify a secret against its hash."""
    try:
        salt, stored_hash = hashed.split('$')
        computed = hashlib.pbkdf2_hmac(
            'sha256', secret.encode(), salt.encode(), 100000
        ).hex()
        return hmac.compare_digest(computed, stored_hash)
    except ValueError:
        return False
