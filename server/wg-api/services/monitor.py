"""
Monitoring & Anomaly Detection Service
======================================
"""

import re
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

from config import ANOMALY_THRESHOLD_HANDSHAKE, ANOMALY_THRESHOLD_RECONNECT, BRUTE_FORCE_THRESHOLD
from utils.logger import setup_logger, log_anomaly

logger = setup_logger('monitor', Path('/opt/wg-api/logs/monitor.log'))

_connection_attempts = defaultdict(list)
_reconnect_counts = defaultdict(list)
_handshake_status = {}


class AnomalyMonitor:
    """Monitors WireGuard and API for security anomalies."""

    def __init__(self):
        self.last_check = 0
        self.check_interval = 30

    def check_handshake_timeouts(self) -> List[Dict]:
        """Detect peers with no recent handshake."""
        anomalies = []

        try:
            result = subprocess.run(
                ['/usr/bin/sudo', '-n', '/usr/local/sbin/wg-show', 'dump'],
                capture_output=True, text=True, check=False
            )

            now = time.time()

            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split('\t')
                if len(parts) < 6:
                    continue

                pub_key = parts[0]
                handshake_str = parts[4]

                if not handshake_str or handshake_str == '0':
                    if pub_key in _handshake_status:
                        last_seen = _handshake_status[pub_key]
                        if now - last_seen > ANOMALY_THRESHOLD_HANDSHAKE:
                            anomalies.append({
                                'type': 'handshake_timeout',
                                'peer': pub_key[:16] + '...',
                                'severity': 'WARNING',
                                'details': 'No handshake for > 60s'
                            })
                    else:
                        _handshake_status[pub_key] = now
                else:
                    _handshake_status[pub_key] = now

        except Exception as e:
            logger.error(f"Handshake check failed: {e}")

        return anomalies

    def check_rapid_reconnects(self) -> List[Dict]:
        """Detect rapid reconnection attempts."""
        anomalies = []
        now = time.time()

        try:
            result = subprocess.run(
                ['journalctl', '-u', 'wg-quick@wg0', '--since', '1 minute ago',
                 '--no-pager', '-q'],
                capture_output=True, text=True, check=False
            )

            peer_events = defaultdict(int)
            for line in result.stdout.split('\n'):
                if 'wg0' in line and 'peer' in line.lower():
                    match = re.search(r'peer\s+([a-f0-9]+)', line, re.I)
                    if match:
                        peer_events[match.group(1)] += 1

            for peer, count in peer_events.items():
                if count > ANOMALY_THRESHOLD_RECONNECT:
                    anomalies.append({
                        'type': 'rapid_reconnect',
                        'peer': peer[:16] + '...',
                        'severity': 'ALERT',
                        'details': f'{count} reconnects in 1 minute'
                    })

        except Exception as e:
            logger.error(f"Reconnect check failed: {e}")

        return anomalies

    def check_brute_force(self, client_ip: str) -> bool:
        """Check if IP is brute forcing API."""
        now = time.time()
        _connection_attempts[client_ip] = [
            t for t in _connection_attempts[client_ip] if now - t < 60
        ]
        _connection_attempts[client_ip].append(now)

        if len(_connection_attempts[client_ip]) > BRUTE_FORCE_THRESHOLD:
            log_anomaly('brute_force_detected', {
                'source_ip': client_ip,
                'attempts': len(_connection_attempts[client_ip])
            }, severity='CRITICAL')
            return True
        return False

    def run_all_checks(self) -> List[Dict]:
        """Run all anomaly detection checks."""
        now = time.time()
        if now - self.last_check < self.check_interval:
            return []

        self.last_check = now

        all_anomalies = []
        all_anomalies.extend(self.check_handshake_timeouts())
        all_anomalies.extend(self.check_rapid_reconnects())

        for anomaly in all_anomalies:
            log_anomaly(
                anomaly['type'],
                {'peer': anomaly['peer'], 'details': anomaly['details']},
                severity=anomaly['severity']
            )
            logger.warning(f"Anomaly detected: {anomaly}")

        return all_anomalies

    def get_system_health(self) -> Dict:
        """Get overall system health status."""
        try:
            wg_status = subprocess.run(
                ['systemctl', 'is-active', 'wg-quick@wg0'],
                capture_output=True, text=True, check=False
            )
            wg_active = wg_status.stdout.strip() == 'active'

            api_status = subprocess.run(
                ['systemctl', 'is-active', 'wg-api'],
                capture_output=True, text=True, check=False
            )
            api_active = api_status.stdout.strip() == 'active'

            try:
                disk = subprocess.run(
                    ['df', '-h', '/'],
                    capture_output=True, text=True, check=True
                ).stdout
            except:
                disk = "unknown"

            return {
                'wireguard': 'active' if wg_active else 'inactive',
                'api': 'active' if api_active else 'inactive',
                'disk': disk,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {'error': str(e)}
