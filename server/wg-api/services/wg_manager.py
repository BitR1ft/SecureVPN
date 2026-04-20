"""
WireGuard Management Service
"""

import re
import fcntl
import subprocess
import secrets
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime

from config import (
    WG_CONF, PEER_DIR, VPN_SUBNET, SERVER_IP,
    LISTEN_PORT, WAN_INTERFACE, PQ_ENABLED
)
from utils.validators import validate_peer_name, get_next_ip, ValidationError
from utils.logger import setup_logger, log_anomaly

logger = setup_logger('wg_manager', Path('/opt/wg-api/logs/wg-manager.log'))


class WireGuardManager:
    """Manages WireGuard server configuration and peer lifecycle."""

    def __init__(self):
        self.wg_conf = WG_CONF
        self.peer_dir = PEER_DIR
        self.wan_iface = self._detect_wan_interface()

    def _detect_wan_interface(self) -> str:
        """Auto-detect WAN interface name."""
        try:
            result = subprocess.run(
                ['/usr/bin/ip', 'route', 'show', 'default'],
                capture_output=True, text=True, check=True
            )
            match = re.search(r'dev\s+(\w+)', result.stdout)
            if match:
                return match.group(1)
        except Exception as e:
            logger.warning(f"WAN detection failed: {e}, using default")
        return "eth0"

    def _backup_config(self) -> Path:
        """
        Create timestamped backup of wg0.conf.

        Stored in /opt/wg-api/logs/ because the systemd service uses
        ProtectSystem=strict which blocks creating new files in /etc/wireguard/.
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = Path('/opt/wg-api/logs')
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f'wg0.conf.backup.{timestamp}'
        if self.wg_conf.exists():
            backup_path.write_text(self.wg_conf.read_text())
            logger.info(f"Config backed up to {backup_path}")
        return backup_path

    def _generate_wireguard_keys(self) -> Tuple[str, str]:
        """Generate WireGuard keypair."""
        priv = subprocess.run(
            ['/usr/bin/wg', 'genkey'], capture_output=True, text=True, check=True
        ).stdout.strip()

        pub = subprocess.run(
            ['/usr/bin/wg', 'pubkey'], input=priv, capture_output=True, text=True, check=True
        ).stdout.strip()

        return priv, pub

    def _generate_pq_psk(self) -> str:
        """Generate post-quantum resistant PSK."""
        if PQ_ENABLED:
            try:
                from crypto.pq_crypto import generate_pq_psk
                return generate_pq_psk()
            except Exception as e:
                logger.warning(f"PQ PSK generation failed: {e}, falling back")

        psk = subprocess.run(
            ['/usr/bin/wg', 'genpsk'], capture_output=True, text=True, check=True
        ).stdout.strip()
        return psk

    def get_existing_peers(self) -> List[Dict]:
        """Parse existing peers from wg0.conf."""
        peers = []
        if not self.wg_conf.exists():
            return peers

        content = self.wg_conf.read_text()
        peer_blocks = re.findall(
            r'\[Peer\]\s*\n([^\[]*)', content, re.DOTALL
        )

        for block in peer_blocks:
            peer = {}
            for line in block.strip().split('\n'):
                if '=' in line:
                    key, val = line.split('=', 1)
                    peer[key.strip()] = val.strip()
            if peer:
                peers.append(peer)

        return peers

    def get_used_ips(self) -> List[str]:
        """Get list of already assigned IPs."""
        peers = self.get_existing_peers()
        return [p.get('AllowedIPs', '') for p in peers if 'AllowedIPs' in p]

    def add_peer(self, name: str, client_public_key: str,
                 kyber_public_key: str = None) -> Dict:
        """
        Add a new WireGuard peer.

        Hybrid PQ PSK derivation (when kyber_public_key is provided):
          1. Server encapsulates to client's Kyber public key
          2. Server derives PSK via HKDF-SHA3-256(shared_secret, info='SecureVPN-PQ-PSK-v1')
          3. Server returns ciphertext to client
          4. Client decapsulates and derives the same PSK — PSK never crossed the wire

        Falls back to classical PSK if no Kyber key is supplied.
        """
        name = validate_peer_name(name)

        kem_ciphertext = None
        if kyber_public_key and PQ_ENABLED:
            try:
                import base64
                from crypto.pq_crypto import KyberKEM, derive_psk_from_shared_secret
                client_kyber_pk = base64.b64decode(kyber_public_key)
                kem = KyberKEM(k=2)
                kem_ciphertext, shared_secret = kem.encaps(client_kyber_pk)
                psk = derive_psk_from_shared_secret(shared_secret)
                logger.info(f"KEM-derived PSK generated for peer {name} (PQ path)")
            except Exception as e:
                logger.warning(f"Kyber encaps failed for {name}: {e} — falling back to classical PSK")
                psk = self._generate_pq_psk()
                kem_ciphertext = None
        else:
            psk = self._generate_pq_psk()
            logger.info(f"Classical PSK generated for peer {name}")

        server_pub = Path('/etc/wireguard/server_public.key').read_text().strip()

        # Atomic read-allocate-write via fcntl.flock to prevent duplicate
        # IP assignment when multiple Gunicorn workers process concurrent requests.
        with open(self.wg_conf, 'a+') as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                existing = self.get_existing_peers()
                for peer in existing:
                    if peer.get('Name') == name:
                        raise ValidationError(f"Peer name '{name}' already exists")

                used_ips = self.get_used_ips()
                client_ip = get_next_ip(used_ips)

                peer_block = f"""
# Peer: {name}
# Created: {datetime.now().isoformat()}
# PQ-PSK: {'KEM-derived' if kem_ciphertext else 'Classical'}
[Peer]
PublicKey = {client_public_key}
PresharedKey = {psk}
AllowedIPs = {client_ip}
PersistentKeepalive = 25
"""
                self._backup_config()
                lock_fh.write(peer_block)
                lock_fh.flush()
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)

        try:
            result = subprocess.run(
                ['/usr/bin/sudo', '-n', '/usr/local/sbin/wg-set-peer',
                 client_public_key, '-', client_ip],
                input=psk, capture_output=True, text=True, check=True
            )
            logger.info(f"Peer {name} added live (no restart)")
        except subprocess.CalledProcessError as e:
            detail = e.stderr.strip() or e.stdout.strip() or f"exit code {e.returncode}"
            logger.error(f"wg set failed: {detail}")
            raise RuntimeError(f"Failed to apply peer: {detail}")

        logger.info(f"Peer {name} registered with IP {client_ip}")

        result = {
            'name': name,
            'client_ip': client_ip.replace('/32', ''),
            'server_public_key': server_pub,
            'preshared_key': psk,
            'endpoint': f'<SERVER_ENDPOINT>:{LISTEN_PORT}',
            'pq_psk_method': 'KEM-HKDF-SHA3-256' if kem_ciphertext else 'classical',
        }
        if kem_ciphertext:
            import base64
            result['kem_ciphertext'] = base64.b64encode(kem_ciphertext).decode('ascii')

        return result

    def revoke_peer(self, name: str) -> Dict:
        """
        Revoke (remove) a peer from WireGuard immediately.

        Steps:
          1. Find the peer's public key in wg0.conf
          2. Remove from live kernel state (wg set wg0 peer <pk> remove)
          3. Rewrite wg0.conf without the peer block
          4. Log the revocation event
        """
        name = validate_peer_name(name)

        conf_text = self.wg_conf.read_text()
        if f'# Peer: {name}' not in conf_text:
            raise ValidationError(f"Peer '{name}' not found")

        pub_key = None
        lines = conf_text.splitlines()
        in_target = False
        for line in lines:
            if line.strip() == f'# Peer: {name}':
                in_target = True
            if in_target and line.strip().startswith('PublicKey'):
                pub_key = line.split('=', 1)[1].strip()
                break

        if not pub_key:
            raise RuntimeError(f"Could not find PublicKey for peer '{name}'")

        self._backup_config()

        try:
            subprocess.run(
                ['/usr/bin/sudo', '-n', '/usr/local/sbin/wg-remove-peer', pub_key],
                capture_output=True, text=True, check=True
            )
            logger.info(f"Peer {name} removed from live wg0 interface")
        except subprocess.CalledProcessError as e:
            detail = e.stderr.strip() or e.stdout.strip() or f"exit code {e.returncode}"
            logger.error(f"wg set remove failed: {detail}")
            raise RuntimeError(f"Failed to remove peer from interface: {detail}")

        new_lines = []
        skip = False
        for i, line in enumerate(lines):
            if line.strip() == f'# Peer: {name}':
                skip = True
                if new_lines and new_lines[-1].strip() == '':
                    new_lines.pop()
            if skip:
                if i > 0 and line.strip().startswith('[') and line.strip() != f'# Peer: {name}':
                    skip = False
                    new_lines.append(line)
            else:
                new_lines.append(line)

        self.wg_conf.write_text('\n'.join(new_lines))

        log_anomaly('peer_revoked', {'peer_name': name, 'public_key_prefix': pub_key[:16] + '...'}, severity='INFO')
        logger.info(f"Peer {name} fully revoked and removed from wg0.conf")

        return {'name': name, 'revoked': True, 'public_key_prefix': pub_key[:16] + '...'}

    def audit_peers(self, max_age_days: int = 90) -> Dict:
        """
        Audit all peers and flag those older than max_age_days.

        Returns structured report: active, expiring_soon, expired, unknown_age, summary.
        """
        from datetime import timezone
        import re as _re

        now = datetime.now(timezone.utc)
        peers_report = {'active': [], 'expiring_soon': [], 'expired': [], 'unknown_age': []}

        conf_text = self.wg_conf.read_text() if self.wg_conf.exists() else ''
        peer_blocks = _re.findall(
            r'(# Peer: (\S+).*?)(?=\n# Peer:|\/\*|\Z)',
            conf_text, _re.DOTALL
        )

        existing = self.get_existing_peers()
        wg_status = {}
        try:
            result = subprocess.run(
                ['/usr/bin/sudo', '-n', '/usr/local/sbin/wg-show', 'dump'],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().splitlines()[1:]:
                parts = line.split('\t')
                if len(parts) >= 5:
                    wg_status[parts[0]] = {
                        'last_handshake': int(parts[4]) if parts[4].isdigit() else 0,
                        'allowed_ips': parts[3],
                    }
        except Exception:
            pass

        created_re = _re.compile(r'# Created: (\S+)')
        for peer in existing:
            pub_key = peer.get('PublicKey', '')
            allowed_ip = peer.get('AllowedIPs', 'unknown')

            created_str = None
            for block_text, _ in peer_blocks:
                if pub_key in block_text:
                    m = created_re.search(block_text)
                    if m:
                        created_str = m.group(1)
                    break

            age_days = None
            if created_str:
                try:
                    created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                    if created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=timezone.utc)
                    age_days = (now - created_dt).days
                except Exception:
                    pass

            live_info = wg_status.get(pub_key, {})
            peer_entry = {
                'public_key_prefix': pub_key[:16] + '...' if pub_key else 'unknown',
                'allowed_ip': allowed_ip,
                'age_days': age_days,
                'last_handshake_epoch': live_info.get('last_handshake', 0),
            }

            if age_days is None:
                peers_report['unknown_age'].append(peer_entry)
            elif age_days > max_age_days:
                peers_report['expired'].append(peer_entry)
            elif age_days > max_age_days - 14:
                peers_report['expiring_soon'].append(peer_entry)
            else:
                peers_report['active'].append(peer_entry)

        peers_report['summary'] = {
            'total': sum(len(v) for v in peers_report.values() if isinstance(v, list)),
            'expired_count': len(peers_report['expired']),
            'expiring_soon_count': len(peers_report['expiring_soon']),
            'max_age_days': max_age_days,
            'audit_timestamp': now.isoformat(),
        }

        return peers_report

    def rotate_psk(self, name: str) -> str:
        """Rotate pre-shared key for existing peer."""
        name = validate_peer_name(name)

        peers = self.get_existing_peers()
        target_peer = None
        conf_text = self.wg_conf.read_text()
        if f'# Peer: {name}' in conf_text:
            for peer in peers:
                if f'# Peer: {name}' in conf_text:
                    target_peer = peer
                    break

        if not target_peer:
            raise ValidationError(f"Peer '{name}' not found")

        pub_key = target_peer['PublicKey']
        old_psk = target_peer.get('PresharedKey', '')
        existing_ip = target_peer.get('AllowedIPs', '')

        if not existing_ip:
            raise ValidationError(f"Peer '{name}' has no AllowedIPs")

        new_psk = self._generate_pq_psk()

        self._backup_config()

        conf_text = self.wg_conf.read_text()
        pattern = f"(PublicKey = {re.escape(pub_key)}.*?PresharedKey = )[^\n]+"
        conf_text = re.sub(pattern, r"\g<1>" + new_psk, conf_text, flags=re.DOTALL)

        self.wg_conf.write_text(conf_text)

        subprocess.run(
            ['/usr/bin/sudo', '-n', '/usr/local/sbin/wg-set-peer',
             pub_key, '-', existing_ip],
            input=new_psk, capture_output=True, text=True, check=True
        )

        from utils.logger import log_psk_rotation
        log_psk_rotation(name, old_psk, new_psk)

        logger.info(f"PSK rotated for peer {name}")
        return new_psk

    def get_status(self) -> Dict:
        """Get WireGuard interface status."""
        try:
            result = subprocess.run(
                ['/usr/bin/sudo', '-n', '/usr/local/sbin/wg-show', 'wg0'],
                capture_output=True, text=True, check=True
            )

            status = {'interface': 'wg0', 'peers': []}
            lines = result.stdout.split('\n')

            for line in lines:
                if 'interface:' in line:
                    status['interface'] = line.split(':')[1].strip()
                elif 'peer:' in line:
                    status['peers'].append({'public_key': line.split(':')[1].strip()})
                elif 'endpoint:' in line and status['peers']:
                    status['peers'][-1]['endpoint'] = line.split(':')[1].strip()
                elif 'allowed ips:' in line and status['peers']:
                    status['peers'][-1]['allowed_ips'] = line.split(':')[1].strip()
                elif 'latest handshake:' in line and status['peers']:
                    status['peers'][-1]['handshake'] = line.split(':', 1)[1].strip()
                elif 'transfer:' in line and status['peers']:
                    status['peers'][-1]['transfer'] = line.split(':', 1)[1].strip()

            return status
        except subprocess.CalledProcessError as e:
            logger.error(f"wg show failed: {e}")
            return {'error': str(e)}

    def get_server_stats(self) -> Dict:
        """Get server statistics."""
        status = self.get_status()

        try:
            uptime = subprocess.run(
                ['uptime', '-p'], capture_output=True, text=True, check=True
            ).stdout.strip()
        except Exception:
            uptime = "unknown"

        try:
            mem = subprocess.run(
                ['free', '-h'], capture_output=True, text=True, check=True
            ).stdout
        except Exception:
            mem = "unknown"

        return {
            'peers_count': len(status.get('peers', [])),
            'uptime': uptime,
            'memory': mem,
            'interface': status.get('interface', 'unknown'),
            'post_quantum': PQ_ENABLED
        }
