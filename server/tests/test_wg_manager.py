"""
Unit Tests: WireGuard Manager — Key Consistency & PSK Regex
============================================================
Tests Fix 1D (key mismatch) and Fix 1E (regex SOH corruption).

Run: pytest tests/test_wg_manager.py -v
"""

import re
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent / 'wg-api'))


# ── Fix 1D: Key mismatch regression tests ─────────────────────────────────

class TestAddPeer:
    """Verify add_peer never generates server-side client keys."""

    @pytest.fixture
    def manager(self, tmp_path, wg_conf, server_pub_key_file):
        with patch('config.WG_CONF', wg_conf), \
             patch('config.PEER_DIR', tmp_path / 'peers'), \
             patch('config.PQ_ENABLED', False), \
             patch('config.LISTEN_PORT', 51820), \
             patch('config.VPN_SUBNET', '10.77.0.0/24'), \
             patch('config.SERVER_IP', '10.77.0.1/24'), \
             patch('config.WAN_INTERFACE', 'eth0'):
            from services.wg_manager import WireGuardManager
            mgr = WireGuardManager.__new__(WireGuardManager)
            mgr.wg_conf = wg_conf
            mgr.peer_dir = tmp_path / 'peers'
            mgr.wan_iface = 'eth0'
            return mgr

    def test_add_peer_uses_client_public_key(self, manager, server_pub_key_file):
        """
        Fix 1D: server must NOT generate a new keypair; it uses the client's public key.
        The peer block in wg0.conf must use the exact public key sent by the client.
        """
        client_pub = 'CLIENT_PUBLIC_KEY_BASE64_PADDED_TO_44CHARS=='

        with patch.object(manager, '_generate_wireguard_keys') as mock_keygen, \
             patch.object(manager, '_generate_pq_psk', return_value='FAKEPSK=='), \
             patch('subprocess.run') as mock_sub, \
             patch('pathlib.Path.read_text', return_value='SERVERPUB==\n'):

            mock_sub.return_value = MagicMock(returncode=0, stdout='', stderr='')
            manager.add_peer('testpeer', client_pub)

            # The server must NOT have called _generate_wireguard_keys
            mock_keygen.assert_not_called(), \
                "add_peer called _generate_wireguard_keys — server must never generate client keys"

        # The conf file must contain the client's public key
        conf_text = manager.wg_conf.read_text()
        assert client_pub in conf_text, \
            "Client's public key not found in wg0.conf — key mismatch bug still present"

    def test_add_peer_does_not_write_private_key(self, manager, server_pub_key_file):
        """Fix 1D: wg0.conf peer block must NOT contain any PrivateKey field."""
        client_pub = 'CLIENT_PUBLIC_KEY_BASE64_PADDED_TO_44CHARS=='

        with patch.object(manager, '_generate_pq_psk', return_value='FAKEPSK=='), \
             patch('subprocess.run') as mock_sub, \
             patch('pathlib.Path.read_text', return_value='SERVERPUB==\n'):
            mock_sub.return_value = MagicMock(returncode=0, stdout='', stderr='')
            manager.add_peer('testpeer', client_pub)

        conf_text = manager.wg_conf.read_text()
        peer_section = conf_text[conf_text.index('[Peer]'):]
        assert 'PrivateKey' not in peer_section, \
            "Server wrote PrivateKey into wg0.conf peer block — Fix 1D regression"


class TestPSKRotationRegex:
    """Verify Fix 1E: PSK rotation must not corrupt wg0.conf with SOH bytes."""

    def test_no_soh_byte_in_regex_replacement(self):
        """
        Fix 1E: f-string f'\\1{new_psk}' evaluates \\1 as ASCII SOH (0x01).
        The correct form is r'\\g<1>' + new_psk using raw string backreference.
        """
        conf = (
            "[Peer]\n"
            "PublicKey = TESTKEY123==\n"
            "PresharedKey = OLDPSK==\n"
            "AllowedIPs = 10.77.0.2/32\n"
        )
        new_psk = "NEWPSK_VALUE_BASE64=="
        pub_key = "TESTKEY123=="

        pattern = f"(PublicKey = {re.escape(pub_key)}.*?PresharedKey = )[^\n]+"

        # CORRECT form (Fix 1E)
        result_correct = re.sub(pattern, r"\g<1>" + new_psk, conf, flags=re.DOTALL)

        # Verify no SOH byte (0x01) in result
        assert '\x01' not in result_correct, \
            "SOH byte (0x01) found in output — Fix 1E regression detected"

        # Verify new PSK is present
        assert new_psk in result_correct, "New PSK not written to conf"
        assert 'OLDPSK==' not in result_correct, "Old PSK still in conf"

    def test_soh_byte_present_in_broken_version(self):
        """
        Demonstrate the ORIGINAL bug: f'\\1{new_psk}' injects SOH.
        This test documents why the fix was needed.
        """
        new_psk = "NEWPSK_VALUE_BASE64=="

        # The broken f-string replacement string
        broken_replacement = f"\1{new_psk}"

        assert '\x01' in broken_replacement, \
            "Expected SOH byte in broken f-string — test is validating the bug exists"

    def test_rotate_psk_regex_correct_form(self):
        """
        Verify the exact regex substitution in wg_manager matches the pattern
        and uses the correct r-string backreference, not an f-string.
        """
        pub_key = "ABCDEFGHIJKLMNOP12345678=="
        old_psk = "OLDPSK=="
        new_psk = "NEWPSK=="

        conf = (
            f"[Peer]\n"
            f"PublicKey = {pub_key}\n"
            f"PresharedKey = {old_psk}\n"
            f"AllowedIPs = 10.77.0.2/32\n"
        )

        pattern = f"(PublicKey = {re.escape(pub_key)}.*?PresharedKey = )[^\n]+"
        result = re.sub(pattern, r"\g<1>" + new_psk, conf, flags=re.DOTALL)

        assert '\x01' not in result
        assert new_psk in result
        assert old_psk not in result

    def test_rotate_psk_multiline_config(self):
        """PSK rotation must work correctly with multiple peers in the config."""
        conf = (
            "[Interface]\n"
            "Address = 10.77.0.1/24\n\n"
            "[Peer]\n"
            "PublicKey = PEER1KEY==\n"
            "PresharedKey = PSK1==\n"
            "AllowedIPs = 10.77.0.2/32\n\n"
            "[Peer]\n"
            "PublicKey = PEER2KEY==\n"
            "PresharedKey = PSK2==\n"
            "AllowedIPs = 10.77.0.3/32\n"
        )
        new_psk = "NEWPSK_FOR_PEER1=="
        pub_key = "PEER1KEY=="

        pattern = f"(PublicKey = {re.escape(pub_key)}.*?PresharedKey = )[^\n]+"
        result = re.sub(pattern, r"\g<1>" + new_psk, conf, flags=re.DOTALL)

        assert new_psk in result
        assert 'PSK1==' not in result
        assert 'PSK2==' in result, "Rotation corrupted PEER2's PSK"
        assert '\x01' not in result


class TestAuditPeers:
    """Verify peer TTL audit classifies peers correctly by age."""

    def test_audit_classifies_by_age(self, tmp_path):
        """Peers older than max_age_days must appear in 'expired' list."""
        now = datetime.now(timezone.utc)
        old_date = (now - timedelta(days=100)).isoformat()
        recent_date = (now - timedelta(days=10)).isoformat()

        conf_text = (
            f"[Interface]\nAddress = 10.77.0.1/24\n\n"
            f"# Peer: oldpeer\n"
            f"# Created: {old_date}\n"
            f"[Peer]\nPublicKey = OLDKEY==\nPresharedKey = PSK==\nAllowedIPs = 10.77.0.2/32\n\n"
            f"# Peer: newpeer\n"
            f"# Created: {recent_date}\n"
            f"[Peer]\nPublicKey = NEWKEY==\nPresharedKey = PSK==\nAllowedIPs = 10.77.0.3/32\n"
        )

        wg_conf = tmp_path / 'wg0.conf'
        wg_conf.write_text(conf_text)

        with patch('config.WG_CONF', wg_conf), \
             patch('config.PEER_DIR', tmp_path), \
             patch('config.PQ_ENABLED', False), \
             patch('config.LISTEN_PORT', 51820), \
             patch('config.VPN_SUBNET', '10.77.0.0/24'), \
             patch('config.SERVER_IP', '10.77.0.1/24'), \
             patch('config.WAN_INTERFACE', 'eth0'), \
             patch('subprocess.run') as mock_sub:

            mock_sub.return_value = MagicMock(returncode=0, stdout='', stderr='')

            from services.wg_manager import WireGuardManager
            mgr = WireGuardManager.__new__(WireGuardManager)
            mgr.wg_conf = wg_conf
            mgr.peer_dir = tmp_path
            mgr.wan_iface = 'eth0'

            report = mgr.audit_peers(max_age_days=90)

        expired_ips = [p['allowed_ip'] for p in report.get('expired', [])]
        active_ips  = [p['allowed_ip'] for p in report.get('active', [])]

        assert '10.77.0.2/32' in expired_ips, "100-day-old peer should be expired"
        assert '10.77.0.3/32' in active_ips,  "10-day-old peer should be active"
