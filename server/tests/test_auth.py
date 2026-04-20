"""
Unit Tests: Authentication & API Security
==========================================
Tests for Fix 1B (missing API key), rate limiting, and timing-safe comparison.

Run: pytest tests/test_auth.py -v
"""

import sys
import hmac
import time
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'wg-api'))


class TestRequireApiKey:
    """Test the @require_api_key decorator."""

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.read_text', return_value='valid-test-api-key-32chars1234567'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('subprocess.run'):
            yield

    @pytest.fixture
    def client(self):
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.read_text', return_value='valid-test-api-key-32chars1234567'), \
             patch('pathlib.Path.exists', return_value=True):
            from app import app
            app.config['TESTING'] = True
            with app.test_client() as c:
                yield c

    def test_missing_api_key_returns_401(self, client):
        """Fix 1B: Request without X-API-Key header must be rejected."""
        resp = client.get('/api/v1/status')
        assert resp.status_code == 401
        data = resp.get_json()
        assert 'error' in data
        assert 'API key' in data['error']

    def test_invalid_api_key_returns_403(self, client):
        """Wrong API key must be rejected with 403."""
        resp = client.get('/api/v1/status', headers={'X-API-Key': 'wrong-key'})
        assert resp.status_code in (401, 403)

    def test_health_endpoint_no_auth_required(self, client):
        """Health check endpoint must be publicly accessible (no auth)."""
        with patch('services.monitor.AnomalyMonitor.get_system_health',
                   return_value={'status': 'ok'}):
            resp = client.get('/api/v1/health')
        assert resp.status_code == 200

    def test_security_headers_present(self, client):
        """All responses must include security headers."""
        resp = client.get('/api/v1/health')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
        assert resp.headers.get('X-Frame-Options') == 'DENY'
        assert 'Strict-Transport-Security' in resp.headers


class TestTimingSafeComparison:
    """Verify API key comparison is timing-safe (prevents timing attacks)."""

    def test_hmac_compare_digest_used(self):
        """
        API key comparison must use hmac.compare_digest, not == operator.
        Direct string comparison (==) short-circuits on first mismatch,
        leaking timing information that can reveal the key character by character.
        """
        # Read the auth module source and verify it uses compare_digest
        auth_file = Path(__file__).parent.parent / 'wg-api' / 'services' / 'auth.py'
        source = auth_file.read_text()

        assert 'hmac.compare_digest' in source, \
            "auth.py does not use hmac.compare_digest — timing attack vulnerability"

        assert 'api_key ==' not in source and "api_key==" not in source, \
            "auth.py uses == for API key comparison — timing attack vulnerability"


class TestRateLimiting:
    """Verify rate limiting is applied to sensitive endpoints."""

    def test_rate_limit_decorator_applied(self):
        """add-peer and rotate-psk endpoints must have rate limiting."""
        app_file = Path(__file__).parent.parent / 'wg-api' / 'app.py'
        source = app_file.read_text()

        # Check that rate_limit decorator is applied before add_peer and rotate_psk
        assert "@rate_limit('add_peer'" in source, \
            "add-peer endpoint missing @rate_limit decorator"
        assert "@rate_limit('rotate_psk'" in source, \
            "rotate-psk endpoint missing @rate_limit decorator"
        assert "@rate_limit('revoke_peer'" in source, \
            "revoke-peer endpoint missing @rate_limit decorator"


class TestPQKEMEndpoint:
    """Test the corrected /pq-keygen endpoint (Fix 1B)."""

    def test_pq_keygen_requires_client_public_key(self):
        """
        Fix 1B: /pq-keygen must require client's kyber_public_key in the request.
        The old broken version generated a keypair and discarded the private key.
        The fixed version encapsulates to the client's public key.
        """
        app_file = Path(__file__).parent.parent / 'wg-api' / 'app.py'
        source = app_file.read_text()

        # The fixed endpoint must check for 'kyber_public_key' in request
        assert "'kyber_public_key'" in source, \
            "/pq-keygen does not check for kyber_public_key — Fix 1B not applied"

        # Must use encaps, not keygen alone
        assert 'kem.encaps(' in source, \
            "/pq-keygen must encapsulate to client's public key (kem.encaps)"

        # Must NOT just generate and return a keypair discarding private key
        pq_keygen_fn = source[source.index('def pq_keygen'):]
        pq_keygen_fn = pq_keygen_fn[:pq_keygen_fn.index('\ndef ')]

        assert 'public_key, private_key = kem.keygen()' not in pq_keygen_fn, \
            "pq_keygen still generates and discards private_key — Fix 1B not applied"
