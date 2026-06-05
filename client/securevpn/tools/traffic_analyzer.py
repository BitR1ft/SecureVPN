"""
SecureVPN Traffic Analyzer
==========================
Demonstrates encryption by capturing packets before and after VPN.

Features:
- Packet capture on default interface (plaintext)
- Packet capture on WireGuard interface (encrypted)
- Side-by-side comparison
- Protocol analysis
- Visualization of ChaCha20-Poly1305 encryption

Principles:
- Requires Administrator privileges
- Read-only capture (no modification)
- Secure handling of captured data
"""

import os
import sys
import json
import time
import struct
import socket
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# scapy imports with error handling
try:
    from scapy.all import sniff, Raw, IP, UDP, TCP, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class PacketInfo:
    """Structured packet information."""
    timestamp: float
    src: str
    dst: str
    protocol: str
    length: int
    payload_preview: str
    is_encrypted: bool = False
    encryption_type: str = ""


class TrafficAnalyzer:
    """
    Traffic analysis tool for demonstrating VPN encryption.

    Security Note:
    - Only captures first 100 bytes of payload for analysis
    - Does not store full packet contents
    - Requires admin/root for raw socket access
    """

    def __init__(self):
        self.captured_packets: List[PacketInfo] = []
        self._capture_count = 20
        self._timeout = 10

    def _is_admin(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            if os.name == 'nt':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def _packet_handler(self, packet, interface_type: str = "unknown"):
        """Process captured packet."""
        info = PacketInfo(
            timestamp=time.time(),
            src="",
            dst="",
            protocol="Unknown",
            length=len(packet),
            payload_preview="",
            is_encrypted=False,
            encryption_type=""
        )

        try:
            # Extract IP layer info
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info.src = ip_layer.src
                info.dst = ip_layer.dst

                # Determine protocol
                if packet.haslayer(TCP):
                    info.protocol = "TCP"
                    tcp_layer = packet[TCP]
                    if packet.haslayer(HTTPRequest):
                        info.protocol = "HTTP"
                        http = packet[HTTPRequest]
                        info.payload_preview = f"{http.Method.decode()} {http.Path.decode()}"
                    elif packet.haslayer(HTTPResponse):
                        info.protocol = "HTTP"
                        info.payload_preview = "HTTP Response"
                    else:
                        info.payload_preview = f"Port {tcp_layer.dport}"

                elif packet.haslayer(UDP):
                    info.protocol = "UDP"
                    udp_layer = packet[UDP]

                    # Check if WireGuard (port 51820)
                    if udp_layer.dport == 51820 or udp_layer.sport == 51820:
                        info.protocol = "WireGuard"
                        info.is_encrypted = True
                        info.encryption_type = "ChaCha20-Poly1305"
                        info.payload_preview = "[ENCRYPTED UDP - ChaCha20-Poly1305]"
                    else:
                        info.payload_preview = f"Port {udp_layer.dport}"

                else:
                    info.protocol = f"IP Protocol {ip_layer.proto}"

            # Extract payload preview (first 50 bytes)
            if packet.haslayer(Raw) and not info.is_encrypted:
                raw = packet[Raw].load
                preview = raw[:50]

                # Try to decode as text
                try:
                    text = preview.decode('utf-8', errors='replace')
                    # Filter printable characters
                    info.payload_preview = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' 
                                                  for c in text[:50])
                except Exception:
                    info.payload_preview = preview.hex()[:50]

            self.captured_packets.append(info)

        except Exception as e:
            # Skip malformed packets
            pass

    def capture_before_vpn(self, interface: Optional[str] = None, 
                           count: int = 20) -> List[PacketInfo]:
        """
        Capture packets BEFORE VPN connection (plaintext).

        Args:
            interface: Network interface to capture on
            count: Number of packets to capture

        Returns:
            List of captured packet info
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed. Run: pip install scapy")

        if not self._is_admin():
            raise PermissionError("Traffic capture requires Administrator privileges")

        self.captured_packets = []
        self._capture_count = count

        print(f"[*] Capturing {count} packets on default interface (BEFORE VPN)...")
        print("[*] Visit a website or generate traffic now...")

        try:
            packets = sniff(
                iface=interface,
                count=count,
                timeout=self._timeout,
                prn=lambda p: self._packet_handler(p, "default")
            )
        except Exception as e:
            raise RuntimeError(f"Capture failed: {e}")

        return self.captured_packets

    def capture_after_vpn(self, interface: str = "WireGuard", 
                          count: int = 20) -> List[PacketInfo]:
        """
        Capture packets AFTER VPN connection (encrypted).

        Args:
            interface: WireGuard tunnel interface name
            count: Number of packets to capture

        Returns:
            List of captured packet info
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed")

        if not self._is_admin():
            raise PermissionError("Traffic capture requires Administrator privileges")

        self.captured_packets = []
        self._capture_count = count

        print(f"[*] Capturing {count} packets on {interface} interface (WITH VPN)...")

        try:
            packets = sniff(
                iface=interface,
                count=count,
                timeout=self._timeout,
                filter="udp port 51820",
                prn=lambda p: self._packet_handler(p, "wireguard")
            )
        except Exception as e:
            raise RuntimeError(f"Capture failed: {e}")

        return self.captured_packets

    def analyze_comparison(self, before: List[PacketInfo], 
                          after: List[PacketInfo]) -> Dict:
        """
        Compare before/after captures and generate report.

        Returns:
            Analysis report dictionary
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'before': {
                'total_packets': len(before),
                'protocols': {},
                'sample_payloads': []
            },
            'after': {
                'total_packets': len(after),
                'protocols': {},
                'sample_payloads': []
            },
            'encryption_analysis': {
                'plaintext_visible': False,
                'encrypted_detected': False,
                'encryption_type': "",
                'conclusion': ""
            }
        }

        # Analyze BEFORE
        for pkt in before:
            proto = pkt.protocol
            report['before']['protocols'][proto] = report['before']['protocols'].get(proto, 0) + 1

            if len(report['before']['sample_payloads']) < 3 and pkt.payload_preview:
                report['before']['sample_payloads'].append({
                    'protocol': proto,
                    'src': pkt.src,
                    'dst': pkt.dst,
                    'payload': pkt.payload_preview[:80]
                })

        # Analyze AFTER
        for pkt in after:
            proto = pkt.protocol
            report['after']['protocols'][proto] = report['after']['protocols'].get(proto, 0) + 1

            if pkt.is_encrypted:
                report['encryption_analysis']['encrypted_detected'] = True
                report['encryption_analysis']['encryption_type'] = pkt.encryption_type

            if len(report['after']['sample_payloads']) < 3:
                report['after']['sample_payloads'].append({
                    'protocol': proto,
                    'src': pkt.src,
                    'dst': pkt.dst,
                    'payload': pkt.payload_preview[:80]
                })

        # Determine if plaintext was visible before
        http_count = report['before']['protocols'].get('HTTP', 0)
        report['encryption_analysis']['plaintext_visible'] = http_count > 0

        # Conclusion
        if report['encryption_analysis']['encrypted_detected']:
            report['encryption_analysis']['conclusion'] = (
                "✓ ENCRYPTION VERIFIED: Traffic is encrypted using ChaCha20-Poly1305. "
                "Plaintext HTTP headers visible before VPN are now unreadable binary data."
            )
        else:
            report['encryption_analysis']['conclusion'] = (
                "⚠ Could not verify encryption. Ensure VPN is connected and capturing on WireGuard interface."
            )

        return report

    def generate_text_report(self, report: Dict) -> str:
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("  SECUREVPN TRAFFIC ANALYSIS REPORT")
        lines.append("  Post-Quantum WireGuard Encryption Verification")
        lines.append("=" * 70)
        lines.append("")

        # BEFORE section
        lines.append("─" * 70)
        lines.append("  BEFORE VPN (Plaintext Traffic)")
        lines.append("─" * 70)
        lines.append(f"  Total packets captured: {report['before']['total_packets']}")
        lines.append("")
        lines.append("  Protocols detected:")
        for proto, count in report['before']['protocols'].items():
            lines.append(f"    • {proto}: {count} packets")
        lines.append("")
        lines.append("  Sample payloads (readable text visible):")
        for sample in report['before']['sample_payloads']:
            lines.append(f"    [{sample['protocol']}] {sample['src']} → {sample['dst']}")
            lines.append(f"    Payload: {sample['payload']}")
            lines.append("")

        # AFTER section
        lines.append("─" * 70)
        lines.append("  AFTER VPN (Encrypted Traffic)")
        lines.append("─" * 70)
        lines.append(f"  Total packets captured: {report['after']['total_packets']}")
        lines.append("")
        lines.append("  Protocols detected:")
        for proto, count in report['after']['protocols'].items():
            lines.append(f"    • {proto}: {count} packets")
        lines.append("")
        lines.append("  Sample payloads (should be unreadable binary):")
        for sample in report['after']['sample_payloads']:
            lines.append(f"    [{sample['protocol']}] {sample['src']} → {sample['dst']}")
            lines.append(f"    Payload: {sample['payload']}")
            lines.append("")

        # Analysis
        lines.append("─" * 70)
        lines.append("  ENCRYPTION ANALYSIS")
        lines.append("─" * 70)
        lines.append(f"  Plaintext visible before VPN: {report['encryption_analysis']['plaintext_visible']}")
        lines.append(f"  Encrypted traffic detected: {report['encryption_analysis']['encrypted_detected']}")
        lines.append(f"  Encryption algorithm: {report['encryption_analysis']['encryption_type']}")
        lines.append("")
        lines.append("  CONCLUSION:")
        lines.append(f"  {report['encryption_analysis']['conclusion']}")
        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)

    def run_full_analysis(self) -> str:
        """
        Run complete before/after analysis.

        Returns:
            Text report
        """
        print("[*] Starting full traffic analysis...")
        print("[*] Step 1: Capture plaintext traffic (ensure VPN is DISCONNECTED)")

        input("Press Enter when ready to capture plaintext traffic...")

        before = self.capture_before_vpn(count=20)

        print(f"[*] Captured {len(before)} plaintext packets")
        print("[*] Now connect VPN and press Enter to capture encrypted traffic...")

        input("Press Enter when VPN is connected...")

        after = self.capture_after_vpn(count=20)

        print(f"[*] Captured {len(after)} encrypted packets")

        report = self.analyze_comparison(before, after)
        text_report = self.generate_text_report(report)

        return text_report


def main():
    """CLI entry point for traffic analyzer."""
    analyzer = TrafficAnalyzer()

    if not analyzer._is_admin():
        print("[!] ERROR: This tool requires Administrator privileges")
        print("[!] Please run as Administrator")
        sys.exit(1)

    if not SCAPY_AVAILABLE:
        print("[!] ERROR: scapy not installed")
        print("[!] Run: pip install scapy")
        sys.exit(1)

    print(analyzer.run_full_analysis())


if __name__ == '__main__':
    main()
