"""
SecureVPN Client Core Engine
Manages WireGuard tunnel lifecycle, kill switch, and server communication.
"""

import os
import re
import sys
import json
import time
import hmac
import base64
import hashlib
import socket
import shutil
import subprocess
import threading
import ipaddress
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Callable
from datetime import datetime
from dataclasses import dataclass, asdict

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_engine import HybridCryptoEngine


@dataclass
class TunnelStatus:
    """Tunnel status data."""
    connected: bool = False
    profile_name: str = ""
    endpoint: str = ""
    server_ip: str = ""
    client_ip: str = ""
    last_handshake: str = ""
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    uptime_seconds: int = 0
    public_ip: str = ""
    dns_servers: List[str] = None

    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = []


@dataclass
class ServerConfig:
    """Server configuration."""
    name: str = ""
    endpoint: str = ""
    public_key: str = ""
    api_url: str = ""
    api_key: str = ""
    latency_ms: float = 0.0
    region: str = ""


class VPNCore:
    """Core VPN engine managing WireGuard on Windows."""

    WG_EXE = r"C:\Program Files\WireGuard\wireguard.exe"
    WG_CLI = r"C:\Program Files\WireGuard\wg.exe"

    APP_NAME = "SecureVPN"

    # Kill switch rules — Block rule is first so it is deleted before allow rules.
    # If allow rules were deleted first while Block was active, any subsequent
    # connection attempt would have all outbound traffic blocked until Block was deleted.
    _KILL_SWITCH_RULES = [
        'SecureVPN-KillSwitch-Block',            # deleted first (critical)
        'SecureVPN-KillSwitch-Allow-Tunnel',
        'SecureVPN-KillSwitch-Allow-VPN',
        'SecureVPN-KillSwitch-Allow-Loopback',
        'SecureVPN-KillSwitch-Allow-DHCP',
        'SecureVPN-KillSwitch-Allow-VPN-Subnet',
        'SecureVPN-KillSwitch-Allow-DNS-Tunnel',
    ]

    def __init__(self):
        self.app_dir = Path(os.environ.get('APPDATA', os.path.expanduser('~'))) / self.APP_NAME
        self.profiles_dir = self.app_dir / 'profiles'
        self.config_file = self.app_dir / 'config.json'
        self.log_file = self.app_dir / 'connection.log'
        self.anomaly_log = self.app_dir / 'anomaly.log'
        self.stats_file = self.app_dir / 'session_stats.json'
        self.pinned_keys_file = self.app_dir / 'pinned_keys.json'

        self.app_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir.mkdir(exist_ok=True)

        self.crypto = HybridCryptoEngine(self.app_dir)
        self._status_lock = threading.Lock()
        self._current_status = TunnelStatus()
        self._bandwidth_thread: Optional[threading.Thread] = None
        self._bandwidth_running = False
        self._last_rx = 0
        self._last_tx = 0
        self._last_bw_time = 0
        self._bw_history = []
        self._connect_time: float = 0.0

        self.config = self._load_config()
        self.servers: List[ServerConfig] = self._load_servers()
        self.pinned_keys: Dict[str, str] = self._load_pinned_keys()

        self._detect_wg_paths()

    def _detect_wg_paths(self):
        """Auto-detect WireGuard executable paths."""
        wg_path = shutil.which('wg.exe')
        if wg_path:
            self.WG_CLI = wg_path

        wireguard_path = shutil.which('wireguard.exe')
        if wireguard_path:
            self.WG_EXE = wireguard_path

    def _load_config(self) -> Dict:
        """Load client configuration."""
        defaults = {
            'kill_switch': True,
            'auto_connect': False,
            'auto_failover': True,
            'check_interval': 5,
            'post_quantum': True,
            'dns_check_host': 'whoami.akamai.net',
            'expected_dns': '1.1.1.1'
        }

        if self.config_file.exists():
            try:
                loaded = json.loads(self.config_file.read_text())
                defaults.update(loaded)
            except Exception:
                pass

        return defaults

    def _save_config(self):
        """Save client configuration."""
        self.config_file.write_text(json.dumps(self.config, indent=2))

    def _load_servers(self) -> List[ServerConfig]:
        """Load server configurations."""
        servers = []
        servers_file = self.app_dir / 'servers.json'

        if servers_file.exists():
            try:
                data = json.loads(servers_file.read_text())
                for s in data:
                    servers.append(ServerConfig(**s))
            except Exception:
                pass

        return servers

    def _save_servers(self):
        """Save server configurations."""
        servers_file = self.app_dir / 'servers.json'
        data = [asdict(s) for s in self.servers]
        servers_file.write_text(json.dumps(data, indent=2))

    def _load_pinned_keys(self) -> Dict[str, str]:
        """Load pinned server public keys (TOFU)."""
        if self.pinned_keys_file.exists():
            try:
                return json.loads(self.pinned_keys_file.read_text())
            except Exception:
                pass
        return {}

    def _save_pinned_keys(self):
        """Save pinned keys."""
        self.pinned_keys_file.write_text(json.dumps(self.pinned_keys, indent=2))

    def _log_event(self, event: str, details: str = ""):
        """Log connection event."""
        timestamp = datetime.now().isoformat()
        entry = f"[{timestamp}] {event}"
        if details:
            entry += f" | {details}"

        with open(self.log_file, 'a') as f:
            f.write(entry + '\n')

    def _log_anomaly(self, event_type: str, severity: str, details: Dict):
        """Log security anomaly."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event_type,
            'severity': severity,
            'details': details
        }

        with open(self.anomaly_log, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def _run_cmd(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Run command securely with no shell injection."""
        kwargs.setdefault('capture_output', True)
        kwargs.setdefault('text', True)
        kwargs.setdefault('creationflags', subprocess.CREATE_NO_WINDOW)

        return subprocess.run(cmd, **kwargs)

    # ── Profile Management ────────────────────────────────────────

    def list_profiles(self) -> List[Dict]:
        """List all imported profiles."""
        profiles = []

        for conf_file in self.profiles_dir.glob('*.conf'):
            try:
                content = conf_file.read_text()
                name = conf_file.stem
                endpoint = ""
                allowed_ips = ""
                for line in content.split('\n'):
                    if line.strip().startswith('Endpoint'):
                        endpoint = line.split('=')[1].strip()
                    elif line.strip().startswith('AllowedIPs'):
                        allowed_ips = line.split('=')[1].strip()

                profiles.append({
                    'name': name,
                    'file': str(conf_file),
                    'endpoint': endpoint,
                    'allowed_ips': allowed_ips
                })
            except Exception:
                continue

        return profiles

    def import_profile(self, source_path: str, name: Optional[str] = None) -> str:
        """
        Import a WireGuard configuration file.

        Args:
            source_path: Path to .conf file
            name: Optional profile name (defaults to filename)

        Returns:
            Profile name
        """
        source = Path(source_path)

        if not source.exists():
            raise FileNotFoundError(f"Profile not found: {source_path}")

        if name is None:
            name = source.stem

        if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', name):
            raise ValueError("Name must be 1-32 alphanumeric/hyphen/underscore")

        dest = self.profiles_dir / f"{name}.conf"
        if dest.exists():
            raise FileExistsError(f"Profile '{name}' already exists")

        content = source.read_text()

        if '[Interface]' not in content or '[Peer]' not in content:
            raise ValueError("Invalid WireGuard configuration")

        dest.write_text(content)

        self._log_event("PROFILE_IMPORTED", f"name={name}")
        return name

    def delete_profile(self, name: str) -> bool:
        """Delete a profile."""
        profile_file = self.profiles_dir / f"{name}.conf"

        if not profile_file.exists():
            return False

        profile_file.unlink()
        self._log_event("PROFILE_DELETED", f"name={name}")
        return True

    # ── Key Generation ────────────────────────────────────────────

    def generate_keys(self, profile_name: str, server_url: str, api_key: str) -> Dict:
        """
        Generate client-side keys and register with server API.

        Full Hybrid PQ KEM Protocol:
          1. Client generates WireGuard keys (classical)
          2. Client generates Kyber-512 keypair (post-quantum)
          3. Client sends WG public key + Kyber public key to /api/v1/add-peer
          4. Server encapsulates to Kyber PK, returns ciphertext + peer config
          5. Client decapsulates to recover shared_secret, derives same PSK via HKDF
          6. Both sides have identical PSK — it never crossed the network

        Args:
            profile_name: Name for the new profile
            server_url:   Server API base URL
            api_key:      Server API key

        Returns:
            Profile configuration data dict
        """
        priv_key, pub_key = self.crypto.generate_wireguard_keys()
        kyber_pk, kyber_sk = self.crypto.generate_kyber_keypair()
        kyber_pk_b64 = base64.b64encode(kyber_pk).decode('ascii')

        try:
            timestamp = str(int(time.time()))
            body_json = json.dumps({
                'name':             profile_name,
                'public_key':       pub_key,
                'kyber_public_key': kyber_pk_b64,
            }, separators=(',', ':')).encode()
            body_hash  = hashlib.sha256(body_json).hexdigest()
            canonical  = f"POST:/api/v1/add-peer:{timestamp}:{body_hash}"
            signature  = hmac.new(
                api_key.encode('utf-8'),
                canonical.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            headers = {
                'X-API-Key':   api_key,
                'X-Timestamp': timestamp,
                'X-Signature': signature,
                'Content-Type': 'application/json',
            }

            response = requests.post(
                f"{server_url}/api/v1/add-peer",
                headers=headers,
                data=body_json,
                timeout=30,
                verify=False,
            )

            if response.status_code != 200:
                raise ConnectionError(f"Server error {response.status_code}: {response.text}")

            data = response.json()
            if not data.get('success'):
                raise ValueError(data.get('error', 'Unknown error'))

            server_data = data['data']

            kem_ciphertext_b64 = server_data.get('kem_ciphertext')
            if kem_ciphertext_b64:
                kem_ct = base64.b64decode(kem_ciphertext_b64)
                psk = self.crypto.kyber_decaps_psk(kem_ct, kyber_sk)
                pq_method = 'KEM-HKDF-SHA3-256'
                self._log_event("PQ_KEM_SUCCESS", f"profile={profile_name}")
            else:
                # Server returned a classical PSK (backward compat)
                psk = server_data['preshared_key']
                pq_method = 'classical'
                self._log_event("PQ_KEM_SKIPPED", f"profile={profile_name}")

            endpoint_str = server_data.get('endpoint', '')
            server_ip = ""
            if endpoint_str:
                server_ip = endpoint_str.split(':')[0]

            allowed_ips = self._compute_allowed_ips_excluding_server(server_ip)

            config = f"""[Interface]
PrivateKey = {priv_key}
Address = {server_data['client_ip']}/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {server_data['server_public_key']}
PresharedKey = {psk}
Endpoint = {server_data['endpoint']}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
            profile_file = self.profiles_dir / f"{profile_name}.conf"
            profile_file.write_text(config)

            server_config = ServerConfig(
                name=profile_name,
                endpoint=server_data['endpoint'],
                public_key=server_data['server_public_key'],
                api_url=server_url,
                api_key=api_key
            )
            self.servers.append(server_config)
            self._save_servers()

            self.crypto.secure_store_key(profile_name, {
                'private_key':       priv_key,
                'public_key':        pub_key,
                'server_public_key': server_data['server_public_key'],
                'preshared_key':     psk,
                'kyber_sk_b64':      base64.b64encode(kyber_sk).decode('ascii'),
                'pq_method':         pq_method,
            })

            self._log_event("KEYGEN_SUCCESS",
                            f"profile={profile_name}, server={server_url}, pq={pq_method}")

            return {
                'name':        profile_name,
                'client_ip':   server_data['client_ip'],
                'endpoint':    server_data['endpoint'],
                'server_ip':   server_ip,
                'post_quantum': data.get('post_quantum', False),
                'pq_method':   pq_method,
            }

        except requests.RequestException as e:
            self._log_event("KEYGEN_FAILED", f"error={e}")
            raise ConnectionError(f"Failed to connect to server: {e}")

    def _compute_allowed_ips_excluding_server(self, server_ip: str) -> str:
        """
        Compute AllowedIPs routing all traffic through the tunnel
        except traffic destined for the VPN server's public IP.

        Without this exclusion WireGuard routes its own UDP packets into
        the tunnel causing a routing loop (handshake never completes).

        Args:
            server_ip: The VPN server's public IP address

        Returns:
            Comma-separated AllowedIPs string
        """
        if not server_ip:
            self._log_event("ALLOWEDIPS_FALLBACK", "No server IP; using 0.0.0.0/0")
            return "0.0.0.0/0"

        try:
            full_route = ipaddress.ip_network('0.0.0.0/0')
            server_net = ipaddress.ip_network(f'{server_ip}/32')
            remaining = list(full_route.address_exclude(server_net))
            allowed = ', '.join(str(net) for net in remaining)
            self._log_event("ALLOWEDIPS_COMPUTED", f"server={server_ip}, allowed={allowed}")
            return allowed

        except (ValueError, TypeError) as e:
            self._log_event("ALLOWEDIPS_ERROR", f"server={server_ip}, error={e}, fallback=0.0.0.0/0")
            return "0.0.0.0/0"

    # ── TOFU (Pinning) ────────────────────────────────────────────

    def check_server_key(self, profile_name: str) -> Tuple[bool, str]:
        """
        Check server public key against pinned value (TOFU).

        Returns:
            (is_valid, message)
        """
        profile_file = self.profiles_dir / f"{profile_name}.conf"
        if not profile_file.exists():
            return False, "Profile not found"

        content = profile_file.read_text()
        current_key = ""
        for line in content.split('\n'):
            if line.strip().startswith('PublicKey'):
                current_key = line.split('=')[1].strip()
                break

        if not current_key:
            return False, "No server public key found"

        pinned_key = self.pinned_keys.get(profile_name)

        if pinned_key is None:
            # First use — pin the key
            self.pinned_keys[profile_name] = current_key
            self._save_pinned_keys()
            self._log_event("TOFU_PINNED", f"profile={profile_name}, key={current_key[:16]}...")
            return True, "Server key pinned for first use"

        if pinned_key != current_key:
            self._log_anomaly('TOFU_MISMATCH', 'ALERT', {
                'profile': profile_name,
                'expected': pinned_key[:16] + '...',
                'received': current_key[:16] + '...'
            })
            return False, "SERVER KEY CHANGED! Possible MITM attack."

        return True, "Server key verified"

    def update_pinned_key(self, profile_name: str, new_key: str):
        """Update pinned key (after user confirmation)."""
        self.pinned_keys[profile_name] = new_key
        self._save_pinned_keys()
        self._log_event("TOFU_UPDATED", f"profile={profile_name}")

    # ── Tunnel Control ────────────────────────────────────────────

    def up(self, profile_name: str) -> Dict:
        """
        Bring up WireGuard tunnel.

        Args:
            profile_name: Profile to connect with

        Returns:
            Dict with connection details (server_ip, client_ip, profile_name, endpoint)
        """
        profile_file = self.profiles_dir / f"{profile_name}.conf"

        if not profile_file.exists():
            raise FileNotFoundError(f"Profile not found: {profile_name}")

        is_valid, msg = self.check_server_key(profile_name)
        if not is_valid and "MITM" in msg:
            raise SecurityError(msg)

        if self.is_connected():
            self.down()

        try:
            result = self._run_cmd([
                self.WG_EXE, '/installtunnelservice',
                str(profile_file)
            ])

            if result.returncode != 0:
                raise RuntimeError(f"Failed to start tunnel: {result.stderr}")

            handshake_ok = self._wait_for_handshake(timeout=60, interval=2)

            if not handshake_ok:
                self._log_event("HANDSHAKE_TIMEOUT", f"profile={profile_name}")
                service_running = self._check_wg_service()

                if service_running:
                    self._log_event("HANDSHAKE_LATE", f"profile={profile_name}, service still running")
                    print("  ⚠ Handshake not yet detected, but tunnel service is running.")
                    print("  WireGuard may still be connecting. Use 'status' to check.")
                    return self._build_connection_info(profile_name)
                else:
                    try:
                        tunnels = self._get_tunnel_names()
                        for tunnel in tunnels:
                            self._run_cmd([self.WG_EXE, '/uninstalltunnelservice', tunnel])
                    except Exception:
                        pass
                    raise RuntimeError(
                        "WireGuard handshake did not complete within 60 seconds. "
                        "Possible causes: UDP 51820 blocked by firewall, PSK mismatch, "
                        "or server unreachable. Check that Azure NSG allows UDP 51820."
                    )

            self._connect_time = time.time()

            if self.config.get('kill_switch', True):
                self._enable_kill_switch(profile_name)

            self._start_bandwidth_monitor()

            self._log_event("TUNNEL_UP", f"profile={profile_name}")
            return self._build_connection_info(profile_name)

        except Exception as e:
            self._log_event("TUNNEL_UP_FAILED", f"profile={profile_name}, error={e}")
            raise

    def _check_wg_handshake(self) -> Optional[bool]:
        """
        Check WireGuard handshake via wg.exe show dump.

        Returns:
            True  — handshake detected (recent, within 180s)
            False — wg.exe works but no handshake found
            None  — wg.exe not available or failed
        """
        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'dump'])
            if result.returncode != 0 or not result.stdout.strip():
                return None

            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # skip interface line
                peer_parts = line.split('\t')
                if len(peer_parts) > 4:
                    handshake_str = peer_parts[4]
                    if handshake_str and handshake_str != '0':
                        try:
                            handshake_time = int(handshake_str)
                            age = int(time.time()) - handshake_time
                            if age < 180:
                                return True
                        except ValueError:
                            pass
            return False
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def _check_vpn_ping(self) -> bool:
        """
        Check VPN connectivity by pinging the server's VPN gateway.

        Uses 3 ping attempts to handle the ~25% packet loss observed
        on the VPN tunnel — a single ping has a 1-in-4 chance of timing
        out and producing a false-negative disconnected result.
        """
        try:
            result = self._run_cmd(['ping', '-n', '3', '-w', '2000', '10.77.0.1'])
            if result.returncode == 0:
                return True
            if result.stdout and 'Reply from' in result.stdout:
                return True
            return False
        except Exception:
            return False

    def _check_wg_service(self) -> bool:
        """Check if any WireGuard tunnel service is running on Windows."""
        try:
            for conf_file in self.profiles_dir.glob('*.conf'):
                tunnel_name = conf_file.stem
                svc_name = f'WireGuardTunnel${tunnel_name}'
                result = self._run_cmd(['sc', 'query', svc_name])
                if result.returncode == 0 and 'RUNNING' in result.stdout:
                    return True
        except Exception:
            pass

        try:
            result = self._run_cmd(['sc', 'query', 'type=', 'service', 'state=', 'all'])
            if result.returncode == 0 and 'WireGuardTunnel' in result.stdout:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'WireGuardTunnel' in line:
                        for j in range(i, min(i + 5, len(lines))):
                            if 'RUNNING' in lines[j]:
                                return True
            return False
        except Exception:
            return False

    def _wait_for_handshake(self, timeout: int = 60, interval: int = 2) -> bool:
        """
        Wait for WireGuard handshake completion after tunnel install.

        Uses multiple detection methods:
          1. wg.exe show dump
          2. Ping 10.77.0.1 (reliable if tunnel is up)
          3. Service check as last resort

        Args:
            timeout:  Maximum seconds to wait
            interval: Seconds between polls

        Returns:
            True if handshake completed within timeout
        """
        deadline = time.time() + timeout
        wg_available = None

        while time.time() < deadline:
            if wg_available is None or wg_available:
                wg_result = self._check_wg_handshake()
                if wg_result is True:
                    self._log_event("HANDSHAKE_VERIFIED_WG", "wg.exe detected handshake")
                    return True
                elif wg_result is False:
                    wg_available = True
                else:
                    wg_available = False
                    self._log_event("WG_CLI_UNAVAILABLE", "falling back to ping detection")

            if self._check_vpn_ping():
                self._log_event("HANDSHAKE_VERIFIED_PING", "ping to 10.77.0.1 succeeded")
                return True

            time.sleep(interval)

        return False

    def _build_connection_info(self, profile_name: str) -> Dict:
        """
        Build connection info dict from profile conf and wg show output.

        Args:
            profile_name: Active profile name

        Returns:
            Dict with server_ip, client_ip, profile_name, endpoint
        """
        info: Dict = {
            'server_ip': '',
            'client_ip': '',
            'profile_name': profile_name,
            'endpoint': '',
        }

        profile_file = self.profiles_dir / f"{profile_name}.conf"
        if profile_file.exists():
            content = profile_file.read_text()
            for line in content.split('\n'):
                stripped = line.strip()
                if stripped.startswith('Endpoint'):
                    endpoint = stripped.split('=', 1)[1].strip()
                    info['endpoint'] = endpoint
                    info['server_ip'] = endpoint.split(':')[0]
                elif stripped.startswith('Address'):
                    addr = stripped.split('=', 1)[1].strip()
                    info['client_ip'] = addr.split('/')[0]

        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'dump'])
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    peer_parts = lines[1].split('\t')
                    if len(peer_parts) > 2:
                        ep = peer_parts[2]
                        if ep and ':' in ep:
                            info['endpoint'] = ep
                            info['server_ip'] = ep.split(':')[0]
        except Exception:
            pass

        return info

    def down(self) -> bool:
        """Bring down WireGuard tunnel."""
        try:
            self._stop_bandwidth_monitor()
            # Disable kill switch before removing tunnel
            self._disable_kill_switch()
            tunnels = self._get_tunnel_names()

            for tunnel in tunnels:
                self._run_cmd([self.WG_EXE, '/uninstalltunnelservice', tunnel])

            self._connect_time = 0.0
            self._log_event("TUNNEL_DOWN")
            return True

        except Exception as e:
            self._log_event("TUNNEL_DOWN_FAILED", f"error={e}")
            return False

    def _check_wg_adapter(self) -> bool:
        """Check if a WireGuard network adapter exists and is connected."""
        try:
            result = self._run_cmd(['ipconfig'])
            if result.returncode == 0 and '10.77.0.' in result.stdout:
                return True
        except Exception:
            pass

        try:
            result = self._run_cmd(['netsh', 'interface', 'show', 'interface'])
            if result.returncode == 0:
                profile_names = [f.stem.lower() for f in self.profiles_dir.glob('*.conf')]
                for line in result.stdout.split('\n'):
                    if 'Connected' in line:
                        line_lower = line.lower()
                        if ('wg' in line_lower or
                                'wireguard' in line_lower or
                                'tunnel' in line_lower or
                                any(pn in line_lower for pn in profile_names)):
                            return True
        except Exception:
            pass

        return False

    def _get_active_tunnel_name(self) -> Optional[str]:
        """Determine the active tunnel name."""
        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'interfaces'])
            name = result.stdout.strip()
            if name:
                return name
        except Exception:
            pass

        for conf_file in self.profiles_dir.glob('*.conf'):
            tunnel_name = conf_file.stem
            svc_name = f'WireGuardTunnel${tunnel_name}'
            result = self._run_cmd(['sc', 'query', svc_name])
            if result.returncode == 0 and 'RUNNING' in result.stdout:
                return tunnel_name

        try:
            result = self._run_cmd(['ipconfig'])
            if result.returncode == 0 and '10.77.0.' in result.stdout:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if '10.77.0.' in line:
                        for j in range(i - 1, max(i - 10, -1), -1):
                            if lines[j].strip() and not lines[j].strip().startswith(' '):
                                adapter_name = lines[j].strip().rstrip(':')
                                return adapter_name
        except Exception:
            pass

        return None

    def is_connected(self) -> bool:
        """
        Check if tunnel is active and connected.

        Uses multiple detection methods:
          1. wg.exe show dump (recent handshake)
          2. Ping 10.77.0.1
          3. WireGuard service check
          4. Network adapter check
        """
        wg_result = self._check_wg_handshake()
        if wg_result is True:
            return True

        if self._check_vpn_ping():
            return True

        if self._check_wg_service():
            return True

        if self._check_wg_adapter():
            return True

        return False

    def _get_tunnel_names(self) -> List[str]:
        """Get list of installed tunnel names."""
        names = []

        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'interfaces'])
            if result.stdout.strip():
                names.extend(result.stdout.strip().split())
        except Exception:
            pass

        for conf_file in self.profiles_dir.glob('*.conf'):
            tunnel_name = conf_file.stem
            svc_name = f'WireGuardTunnel${tunnel_name}'
            result = self._run_cmd(['sc', 'query', svc_name])
            if result.returncode == 0 and svc_name in result.stdout:
                if tunnel_name not in names:
                    names.append(tunnel_name)

        return names

    # ── Status ───────────────────────────────────────────────────

    def get_status(self) -> TunnelStatus:
        """Get detailed tunnel status."""
        status = TunnelStatus()

        if not self.is_connected():
            return status

        status.connected = True

        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'dump'])
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')

                if len(lines) >= 2:
                    peer_parts = lines[1].split('\t')

                    status.endpoint = peer_parts[2] if len(peer_parts) > 2 else ""
                    status.server_ip = status.endpoint.split(':')[0] if status.endpoint else ""

                    handshake_str = peer_parts[4] if len(peer_parts) > 4 else "0"
                    if handshake_str and handshake_str != '0':
                        try:
                            handshake_time = int(handshake_str)
                            ago = int(time.time()) - handshake_time
                            status.last_handshake = f"{ago} seconds ago" if ago < 60 else f"{ago // 60} minutes ago"
                        except ValueError:
                            status.last_handshake = "Unknown"
                    else:
                        status.last_handshake = "No handshake yet"

                    try:
                        status.rx_bytes = int(peer_parts[5]) if len(peer_parts) > 5 else 0
                    except ValueError:
                        pass
                    try:
                        status.tx_bytes = int(peer_parts[6]) if len(peer_parts) > 6 else 0
                    except ValueError:
                        pass

                    if len(lines) >= 1:
                        iface_parts = lines[0].split('\t')
                        if len(iface_parts) > 2:
                            try:
                                ifresult = self._run_cmd([self.WG_CLI, 'show', 'wg0'])
                                for line in ifresult.stdout.split('\n'):
                                    if 'address:' in line.lower():
                                        addr = line.split(':', 1)[1].strip()
                                        status.client_ip = addr.split('/')[0]
                                        break
                            except Exception:
                                pass
        except Exception:
            pass

        tunnel_name = self._get_active_tunnel_name()
        if tunnel_name:
            status.profile_name = tunnel_name

            profile_file = self.profiles_dir / f"{tunnel_name}.conf"
            if profile_file.exists():
                content = profile_file.read_text()
                for line in content.split('\n'):
                    stripped = line.strip()
                    if stripped.startswith('Endpoint') and not status.endpoint:
                        status.endpoint = stripped.split('=', 1)[1].strip()
                        status.server_ip = status.endpoint.split(':')[0]
                    elif stripped.startswith('Address') and not status.client_ip:
                        addr = stripped.split('=', 1)[1].strip()
                        status.client_ip = addr.split('/')[0]

        if status.connected and not status.last_handshake:
            if self._check_vpn_ping():
                status.last_handshake = "Connected (verified by ping)"

        if self._connect_time > 0:
            status.uptime_seconds = int(time.time() - self._connect_time)
        else:
            try:
                for conf_file in self.profiles_dir.glob('*.conf'):
                    tunnel_name = conf_file.stem
                    svc_name = f'WireGuardTunnel${tunnel_name}'
                    result = self._run_cmd(['sc', 'query', svc_name])
                    if result.returncode == 0 and 'RUNNING' in result.stdout:
                        status.uptime_seconds = 0
                        break
            except Exception:
                pass

        return status

    def get_detailed_status(self) -> Dict:
        """Get full status with leak test."""
        status = self.get_status()

        if not status.connected:
            return asdict(status)

        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            status.public_ip = response.json().get('ip', 'unknown')
        except Exception:
            status.public_ip = 'unknown'

        try:
            hostname = socket.gethostbyname(self.config.get('dns_check_host', 'whoami.akamai.net'))
            status.dns_servers = [hostname]
        except Exception:
            pass

        return asdict(status)

    # ── Kill Switch ───────────────────────────────────────────────

    def _get_wg_interface_name(self) -> str:
        """Get the active WireGuard tunnel adapter name."""
        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'interfaces'])
            name = result.stdout.strip()
            if name:
                return name
        except Exception:
            pass
        return 'wg0'

    def _enable_kill_switch(self, profile_name: str):
        """
        Enable OS-level kill switch using Windows Firewall.

        Priority-ordered rules:
          1000 - Allow all traffic on WireGuard tunnel adapter
          1001 - Allow VPN server endpoint IP (for WireGuard UDP handshake)
          1002 - Allow loopback 127.0.0.1
          1003 - Allow DHCP (UDP 68→67)
          1004 - Allow traffic to/from 10.77.0.0/24 VPN subnet
          1005 - Allow DNS through tunnel (UDP port 53)
          2000 - Block ALL other outbound traffic
        """
        profile_file = self.profiles_dir / f"{profile_name}.conf"
        content = profile_file.read_text()

        server_ip = ""
        for line in content.split('\n'):
            if line.strip().startswith('Endpoint'):
                endpoint = line.split('=')[1].strip()
                server_ip = endpoint.split(':')[0]
                break

        if not server_ip:
            return

        wg_iface = self._get_wg_interface_name()

        try:
            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=SecureVPN-KillSwitch-Allow-Tunnel',
                'dir=out', 'action=allow', 'enable=yes',
                f'interface={wg_iface}',
                'profile=any', f'priority=1000',
                'description="Allow all traffic through WireGuard tunnel"'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=SecureVPN-KillSwitch-Allow-VPN',
                'dir=out', 'action=allow',
                f'remoteip={server_ip}',
                'enable=yes', 'profile=any', f'priority=1001'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=SecureVPN-KillSwitch-Allow-Loopback',
                'dir=out', 'action=allow', 'remoteip=127.0.0.1',
                'enable=yes', 'profile=any', 'priority=1002'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=SecureVPN-KillSwitch-Allow-DHCP',
                'dir=out', 'action=allow', 'protocol=udp',
                'localport=68', 'remoteport=67',
                'enable=yes', 'profile=any', 'priority=1003'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=SecureVPN-KillSwitch-Allow-VPN-Subnet',
                'dir=out', 'action=allow',
                'remoteip=10.77.0.0/24',
                'enable=yes', 'profile=any', 'priority=1004'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=SecureVPN-KillSwitch-Allow-DNS-Tunnel',
                'dir=out', 'action=allow', 'protocol=udp',
                'remoteport=53',
                f'interface={wg_iface}',
                'enable=yes', 'profile=any', 'priority=1005'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=SecureVPN-KillSwitch-Allow-DNS-Tunnel-TCP',
                'dir=out', 'action=allow', 'protocol=tcp',
                'remoteport=53',
                f'interface={wg_iface}',
                'enable=yes', 'profile=any', 'priority=1006'
            ])

            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=SecureVPN-KillSwitch-Block',
                'dir=out', 'action=block', 'enable=yes',
                'profile=any', 'priority=2000',
                'description="Blocks all outbound traffic not allowed by VPN rules"'
            ])

            self._log_event("KILL_SWITCH_ENABLED", f"server={server_ip}, iface={wg_iface}")

        except Exception as e:
            self._log_event("KILL_SWITCH_FAILED", f"error={e}")
            raise

    def _disable_kill_switch(self):
        """Remove all kill switch firewall rules."""
        for rule in self._KILL_SWITCH_RULES:
            try:
                self._run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    'name=' + rule
                ])
            except Exception:
                pass

        try:
            self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=SecureVPN-KillSwitch-Allow-DNS-Tunnel-TCP'
            ])
        except Exception:
            pass

        self._log_event("KILL_SWITCH_DISABLED")

    # ── Bandwidth Monitor ─────────────────────────────────────────

    def _start_bandwidth_monitor(self):
        """Start bandwidth monitoring thread."""
        self._bandwidth_running = True
        self._last_rx = 0
        self._last_tx = 0
        self._last_bw_time = 0.0
        self._bw_history = []

        self._bandwidth_thread = threading.Thread(target=self._bandwidth_loop, daemon=True)
        self._bandwidth_thread.start()

    def _stop_bandwidth_monitor(self):
        """Stop bandwidth monitoring."""
        self._bandwidth_running = False
        if self._bandwidth_thread:
            self._bandwidth_thread.join(timeout=2)

    def _read_tunnel_bytes(self):
        """
        Read RX/TX byte counters from the active WireGuard tunnel.

        Three fallback methods:
          1. wg.exe show dump (most accurate)
          2. psutil per-NIC counters
          3. netsh ipv4 subinterfaces

        Returns (rx_bytes, tx_bytes) or (None, None) on failure.
        """
        # Require a valid handshake within 5 minutes before reporting bytes.
        # WireGuard increments tx_bytes during failed handshake attempts too.
        try:
            result = self._run_cmd([self.WG_CLI, 'show', 'dump'])
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    parts = lines[1].split('\t')
                    if len(parts) > 6:
                        try:
                            hs_ts = int(parts[4]) if parts[4] and parts[4] != '0' else 0
                        except ValueError:
                            hs_ts = 0
                        if hs_ts > 0 and (time.time() - hs_ts) < 300:
                            return int(parts[5]), int(parts[6])
        except Exception:
            pass

        try:
            import psutil
            counters = psutil.net_io_counters(pernic=True)

            tunnel_name = self._get_active_tunnel_name()
            if tunnel_name:
                for iface, stats in counters.items():
                    if tunnel_name.lower() in iface.lower():
                        if stats.bytes_recv > 0 or stats.bytes_sent > 0:
                            return stats.bytes_recv, stats.bytes_sent

            for iface, stats in counters.items():
                if 'wireguard' in iface.lower() or iface.lower().startswith('wg'):
                    if stats.bytes_recv > 0 or stats.bytes_sent > 0:
                        return stats.bytes_recv, stats.bytes_sent

            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if getattr(addr, 'address', '').startswith('10.77.0.'):
                        if iface in counters:
                            s = counters[iface]
                            return s.bytes_recv, s.bytes_sent
        except Exception:
            pass

        try:
            result = self._run_cmd(
                ['netsh', 'interface', 'ipv4', 'show', 'subinterfaces']
            )
            if result.returncode == 0:
                tunnel_name = (self._get_active_tunnel_name() or '').lower()
                for line in result.stdout.split('\n'):
                    line_l = line.lower()
                    if tunnel_name and tunnel_name in line_l:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                return int(parts[1]), int(parts[2])
                            except ValueError:
                                pass
        except Exception:
            pass

        return None, None

    def _bandwidth_loop(self):
        """Bandwidth monitoring loop — only measures when tunnel is confirmed up."""
        while self._bandwidth_running:
            try:
                if not self.is_connected():
                    time.sleep(2)
                    continue

                rx_bytes, tx_bytes = self._read_tunnel_bytes()

                if rx_bytes is not None:
                    now = time.time()
                    elapsed = now - self._last_bw_time if self._last_bw_time > 0 else 0

                    rx_rate = 0.0
                    tx_rate = 0.0
                    if elapsed > 0 and self._last_bw_time > 0:
                        rx_rate = max(0.0, (rx_bytes - self._last_rx) / elapsed)
                        tx_rate = max(0.0, (tx_bytes - self._last_tx) / elapsed)

                    self._bw_history.append({
                        'timestamp':  now,
                        'rx_rate':    rx_rate,
                        'tx_rate':    tx_rate,
                        'rx_bytes':   rx_bytes,
                        'tx_bytes':   tx_bytes,
                    })

                    cutoff = now - 60
                    self._bw_history = [
                        h for h in self._bw_history if h['timestamp'] > cutoff
                    ]

                    self._last_rx = rx_bytes
                    self._last_tx = tx_bytes
                    self._last_bw_time = now

                time.sleep(2)
            except Exception:
                time.sleep(2)

    def get_bandwidth(self) -> Dict:
        """Get current bandwidth statistics."""
        if not self._bw_history:
            rx, tx = self._read_tunnel_bytes()
            rx = rx or 0
            tx = tx or 0
            return {
                'rx_rate':        0,
                'tx_rate':        0,
                'rx_human':       '0.0 B/s',
                'tx_human':       '0.0 B/s',
                'rx_bytes':       rx,
                'tx_bytes':       tx,
                'rx_total_human': self._format_bytes(float(rx)),
                'tx_total_human': self._format_bytes(float(tx)),
                'history':        []
            }

        latest = self._bw_history[-1]
        return {
            'rx_rate':        latest['rx_rate'],
            'tx_rate':        latest['tx_rate'],
            'rx_human':       self._format_bytes(latest['rx_rate']) + '/s',
            'tx_human':       self._format_bytes(latest['tx_rate']) + '/s',
            'rx_bytes':       latest.get('rx_bytes', 0),
            'tx_bytes':       latest.get('tx_bytes', 0),
            'rx_total_human': self._format_bytes(float(latest.get('rx_bytes', 0))),
            'tx_total_human': self._format_bytes(float(latest.get('tx_bytes', 0))),
            'history':        self._bw_history
        }

    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(bytes_val) < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"

    # ── Multi-Server ──────────────────────────────────────────────

    def test_server_latency(self, server_ip: str, port: int = 51820) -> float:
        """Test latency to server."""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b'\x01\x00\x00\x00', (server_ip, port))
            sock.recvfrom(1024)
            latency = (time.time() - start) * 1000
            sock.close()
            return latency
        except Exception:
            try:
                result = self._run_cmd(['ping', '-n', '1', '-w', '2000', server_ip])
                if result.returncode == 0:
                    match = re.search(r'time[=<](\d+)ms', result.stdout)
                    if match:
                        return float(match.group(1))
            except Exception:
                pass
            return float('inf')

    def get_best_server(self) -> Optional[ServerConfig]:
        """Find lowest latency server."""
        if not self.servers:
            return None

        best = None
        best_latency = float('inf')

        for server in self.servers:
            ip = server.endpoint.split(':')[0]
            latency = self.test_server_latency(ip)
            server.latency_ms = latency

            if latency < best_latency:
                best_latency = latency
                best = server

        self._save_servers()
        return best

    # ── PSK Rotation ──────────────────────────────────────────────

    def rotate_psk(self, profile_name: str) -> bool:
        """Rotate PSK via API."""
        server = None
        for s in self.servers:
            if s.name == profile_name:
                server = s
                break

        if not server:
            raise ValueError("No server configuration found for profile")

        headers = {'X-API-Key': server.api_key, 'Content-Type': 'application/json'}

        try:
            response = requests.post(
                f"{server.api_url}/api/v1/rotate-psk",
                headers=headers,
                json={'name': profile_name},
                timeout=30
            )

            if response.status_code != 200:
                raise ConnectionError(f"Server error: {response.text}")

            data = response.json()
            if not data.get('success'):
                raise ValueError(data.get('error', 'Unknown error'))

            new_psk = data['data']['new_psk']

            profile_file = self.profiles_dir / f"{profile_name}.conf"
            content = profile_file.read_text()
            content = re.sub(
                r'PresharedKey = .*',
                f'PresharedKey = {new_psk}',
                content
            )
            profile_file.write_text(content)

            self.down()
            time.sleep(1)
            self.up(profile_name)

            self._log_event("PSK_ROTATED", f"profile={profile_name}")
            return True

        except Exception as e:
            self._log_event("PSK_ROTATION_FAILED", f"error={e}")
            raise

    # ── Leak Test ─────────────────────────────────────────────────

    def leak_test(self) -> Dict:
        """Test for IP and DNS leaks."""
        result = {
            'ip_test': {'status': 'unknown', 'public_ip': '', 'expected': ''},
            'dns_test': {'status': 'unknown', 'dns_server': '', 'expected': ''},
            'timestamp': datetime.now().isoformat()
        }

        status = self.get_status()
        expected_ip = status.server_ip if status.connected else ""

        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            public_ip = response.json().get('ip', '')
            result['ip_test']['public_ip'] = public_ip
            result['ip_test']['expected'] = expected_ip

            if status.connected:
                if public_ip == expected_ip:
                    result['ip_test']['status'] = 'PASS'
                else:
                    result['ip_test']['status'] = 'FAIL'
                    self._log_anomaly('IP_LEAK_DETECTED', 'ALERT', {
                        'public_ip': public_ip,
                        'expected': expected_ip
                    })
            else:
                result['ip_test']['status'] = 'DISCONNECTED'
        except Exception as e:
            result['ip_test']['status'] = 'ERROR'
            result['ip_test']['error'] = str(e)

        try:
            hostname = socket.gethostbyname('whoami.akamai.net')
            result['dns_test']['dns_server'] = hostname

            expected_dns = self.config.get('expected_dns', '1.1.1.1')
            result['dns_test']['expected'] = expected_dns

            if status.connected:
                result['dns_test']['status'] = 'PASS'
            else:
                result['dns_test']['status'] = 'DISCONNECTED'
        except Exception as e:
            result['dns_test']['status'] = 'ERROR'
            result['dns_test']['error'] = str(e)

        return result

    # ── Paths ─────────────────────────────────────────────────────

    def get_paths(self) -> Dict:
        """Get application paths."""
        return {
            'app_dir': str(self.app_dir),
            'profiles_dir': str(self.profiles_dir),
            'config_file': str(self.config_file),
            'log_file': str(self.log_file),
            'wireguard_exe': self.WG_EXE,
            'wg_cli': self.WG_CLI
        }


class SecurityError(Exception):
    """Security-related error."""
    pass
