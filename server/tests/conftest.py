"""
SecureVPN Test Suite — Shared Fixtures & Configuration
=======================================================
Run: pytest tests/ -v
"""

import os
import sys
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Make the wg-api package importable without a full install
WG_API_DIR = Path(__file__).parent.parent / 'wg-api'
sys.path.insert(0, str(WG_API_DIR))

# ── Environment stubs ──────────────────────────────────────────────────────
# Set env vars before any module-level code in config.py runs
os.environ.setdefault('SERVER_ENDPOINT', '127.0.0.1')

# Patch path-dependent code in config.py before import
import unittest.mock as _mock

_patcher_mkdir = _mock.patch('pathlib.Path.mkdir', return_value=None)
_patcher_mkdir.start()


@pytest.fixture(scope='session', autouse=True)
def stop_path_patcher():
    yield
    _patcher_mkdir.stop()


# ── Temp directories ───────────────────────────────────────────────────────
@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a fresh temporary directory for each test."""
    return tmp_path


@pytest.fixture
def wg_conf(tmp_path):
    """Provide a temporary wg0.conf with a minimal server block."""
    conf = tmp_path / 'wg0.conf'
    conf.write_text(
        "[Interface]\n"
        "Address = 10.77.0.1/24\n"
        "ListenPort = 51820\n"
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "# Post-Quantum PSK: Enabled\n"
    )
    return conf


@pytest.fixture
def server_pub_key_file(tmp_path):
    """Create a fake server public key file."""
    pub = tmp_path / 'server_public.key'
    pub.write_text('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n')
    return pub


@pytest.fixture
def flask_app():
    """Return a configured Flask test client."""
    # Patch heavy filesystem ops before importing app
    with patch('pathlib.Path.mkdir'), \
         patch('pathlib.Path.read_text', return_value='test-api-key-12345678901234567890'), \
         patch('pathlib.Path.exists', return_value=True):
        from app import app
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        with app.test_client() as client:
            yield client
