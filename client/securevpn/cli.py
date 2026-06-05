"""
SecureVPN CLI
Command-line interface for all VPN operations.

Usage:
    python securevpn_cli.py <command> [options]
    python -m securevpn.cli <command> [options]
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Optional

script_dir = Path(__file__).parent.resolve()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

from core.vpn_engine import VPNCore, SecurityError


def print_header():
    print("=" * 60)
    print("  SecureVPN CLI - Post-Quantum WireGuard VPN")
    print("  Air University - NCSA - CS325 Network Security")
    print("=" * 60)
    print()


def cmd_list(vpn: VPNCore, args):
    """List profiles."""
    profiles = vpn.list_profiles()

    if not profiles:
        print("No profiles imported yet.")
        print("Use 'import' to add a profile or 'keygen' to generate one.")
        return

    print(f"{'Name':<20} {'Endpoint':<30} {'AllowedIPs'}")
    print("-" * 80)

    for p in profiles:
        print(f"{p['name']:<20} {p['endpoint']:<30} {p['allowed_ips']}")

    print(f"\nTotal: {len(profiles)} profile(s)")


def cmd_import(vpn: VPNCore, args):
    """Import profile."""
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    try:
        name = vpn.import_profile(args.file, args.name)
        print(f"✓ Profile '{name}' imported successfully")
        print(f"  Location: {vpn.profiles_dir / f'{name}.conf'}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_up(vpn: VPNCore, args):
    """Connect to VPN."""
    profile = args.profile

    if not profile:
        profiles = vpn.list_profiles()
        if not profiles:
            print("Error: No profiles available. Import or generate one first.")
            sys.exit(1)
        profile = profiles[0]['name']
        print(f"Auto-selected profile: {profile}")

    print(f"Connecting to '{profile}'...")

    try:
        result = vpn.up(profile)
        if result:
            print("✓ Connected successfully")
            if isinstance(result, dict):
                print(f"  Server:    {result.get('server_ip', '')}")
                print(f"  Client IP: {result.get('client_ip', '')}")
                print(f"  Endpoint:  {result.get('endpoint', '')}")
            else:
                status = vpn.get_status()
                print(f"  Server: {status.endpoint}")
                print(f"  Client IP: {status.client_ip}")
        else:
            print("✗ Connection failed")
            sys.exit(1)
    except SecurityError as e:
        print(f"✗ Security error: {e}")
        print("  This may indicate a MITM attack or server key change.")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


def cmd_down(vpn: VPNCore, args):
    """Disconnect VPN."""
    print("Disconnecting...")

    if vpn.down():
        print("✓ Disconnected")
    else:
        print("✗ Disconnect failed or not connected")


def cmd_status(vpn: VPNCore, args):
    """Show status."""
    status = vpn.get_detailed_status()

    if not status['connected']:
        print("Status: DISCONNECTED")
        print("  No active tunnel")
        return

    print("Status: CONNECTED ✓")
    print(f"  Profile:     {status['profile_name']}")
    print(f"  Server:      {status['endpoint']}")
    print(f"  Client IP:   {status['client_ip']}")
    print(f"  Public IP:   {status['public_ip']}")
    print(f"  Handshake:   {status['last_handshake']}")
    print(f"  RX:          {status['rx_bytes']} bytes")
    print(f"  TX:          {status['tx_bytes']} bytes")

    bw = vpn.get_bandwidth()
    print(f"  Download:    {bw['rx_human']}")
    print(f"  Upload:      {bw['tx_human']}")


def cmd_paths(vpn: VPNCore, args):
    """Show paths."""
    paths = vpn.get_paths()

    print("Application Paths:")
    for key, value in paths.items():
        print(f"  {key:<15} {value}")


def cmd_keygen(vpn: VPNCore, args):
    """Generate keys via API."""
    print(f"Generating keys for profile '{args.name}'...")
    print(f"  Server: {args.server}")

    try:
        result = vpn.generate_keys(args.name, args.server, args.api_key)

        print("✓ Keys generated successfully")
        print(f"  Profile:      {result['name']}")
        print(f"  Client IP:    {result['client_ip']}")
        print(f"  Server:       {result.get('server_ip', '')}")
        print(f"  Endpoint:     {result['endpoint']}")
        print(f"  Post-Quantum: {'Yes' if result.get('post_quantum') else 'No'}")
        print(f"  PQ Method:    {result.get('pq_method', 'N/A')}")

    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


def cmd_verify(vpn: VPNCore, args):
    """Run leak test."""
    print("Running leak test...")
    print("  Checking IP and DNS...")

    result = vpn.leak_test()

    ip_test = result['ip_test']
    dns_test = result['dns_test']

    print()
    print(f"IP Test:   [{'PASS' if ip_test['status'] == 'PASS' else 'FAIL'}]")
    print(f"  Public IP: {ip_test.get('public_ip', 'N/A')}")
    print(f"  Expected:  {ip_test.get('expected', 'N/A')}")

    print()
    print(f"DNS Test:  [{'PASS' if dns_test['status'] == 'PASS' else 'FAIL'}]")
    print(f"  DNS Server: {dns_test.get('dns_server', 'N/A')}")

    if ip_test['status'] == 'FAIL' or dns_test['status'] == 'FAIL':
        print()
        print("⚠ LEAK DETECTED! Your traffic may not be properly tunneled.")
        sys.exit(1)
    else:
        print()
        print("✓ No leaks detected. Tunnel is secure.")


def cmd_rotate_psk(vpn: VPNCore, args):
    """Rotate PSK."""
    profile = args.profile

    if not profile:
        profiles = vpn.list_profiles()
        if not profiles:
            print("Error: No profiles available")
            sys.exit(1)
        profile = profiles[0]['name']

    print(f"Rotating PSK for '{profile}'...")

    try:
        vpn.rotate_psk(profile)
        print("✓ PSK rotated successfully")
        print("  Tunnel reconnected with new key")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


def cmd_analyze(vpn: VPNCore, args):
    """Run traffic analyzer."""
    try:
        from tools.traffic_analyzer import TrafficAnalyzer

        analyzer = TrafficAnalyzer()

        if not analyzer._is_admin():
            print("Error: Traffic analyzer requires Administrator privileges")
            print("Please run this command as Administrator")
            sys.exit(1)

        print(analyzer.run_full_analysis())

    except ImportError:
        print("Error: scapy not installed")
        print("Run: pip install scapy")
        sys.exit(1)


def cmd_servers(vpn: VPNCore, args):
    """Manage servers."""
    if args.action == 'list':
        if not vpn.servers:
            print("No servers configured")
            return

        print(f"{'Name':<15} {'Endpoint':<25} {'Latency':<10} {'API URL'}")
        print("-" * 90)

        for s in vpn.servers:
            latency = f"{s.latency_ms:.0f}ms" if s.latency_ms < float('inf') else "N/A"
            print(f"{s.name:<15} {s.endpoint:<25} {latency:<10} {s.api_url}")

    elif args.action == 'add':
        from core.vpn_engine import ServerConfig

        server = ServerConfig(
            name=args.name,
            endpoint=args.endpoint,
            api_url=args.api_url,
            api_key=args.api_key
        )
        vpn.servers.append(server)
        vpn._save_servers()
        print(f"✓ Server '{args.name}' added")

    elif args.action == 'test':
        print("Testing server latencies...")
        best = vpn.get_best_server()

        if best:
            print(f"\nBest server: {best.name} ({best.latency_ms:.0f}ms)")
        else:
            print("No servers configured")


def cmd_logs(vpn: VPNCore, args):
    """View logs."""
    if args.type == 'connection':
        log_file = vpn.log_file
    else:
        log_file = vpn.anomaly_log

    if not log_file.exists():
        print(f"No {args.type} logs found")
        return

    lines = log_file.read_text().split('\n')

    if args.tail:
        lines = lines[-args.tail:]

    for line in lines:
        if line.strip():
            print(line)


def cmd_config(vpn: VPNCore, args):
    """View/edit config."""
    if args.set:
        key, value = args.set.split('=', 1)

        if value.lower() in ('true', 'yes', 'on'):
            value = True
        elif value.lower() in ('false', 'no', 'off'):
            value = False
        else:
            try:
                value = int(value)
            except ValueError:
                pass

        vpn.config[key] = value
        vpn._save_config()
        print(f"✓ Set {key} = {value}")
    else:
        print("Current Configuration:")
        for key, value in vpn.config.items():
            print(f"  {key:<20} {value}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='SecureVPN CLI - Post-Quantum WireGuard VPN',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python securevpn_cli.py list
  python securevpn_cli.py import myprofile.conf --name laptop
  python securevpn_cli.py up --profile laptop
  python securevpn_cli.py status
  python securevpn_cli.py verify
  python securevpn_cli.py keygen myprofile --server http://192.168.1.100:5000 --api-key YOUR_KEY
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    subparsers.add_parser('list', help='List imported profiles')

    import_parser = subparsers.add_parser('import', help='Import profile')
    import_parser.add_argument('file', help='WireGuard .conf file')
    import_parser.add_argument('--name', '-n', help='Profile name')

    up_parser = subparsers.add_parser('up', help='Connect to VPN')
    up_parser.add_argument('--profile', '-p', help='Profile name')

    subparsers.add_parser('down', help='Disconnect VPN')
    subparsers.add_parser('status', help='Show connection status')
    subparsers.add_parser('paths', help='Show application paths')

    keygen_parser = subparsers.add_parser('keygen', help='Generate keys via API')
    keygen_parser.add_argument('name', help='Profile name')
    keygen_parser.add_argument('--server', '-s', required=True, help='Server API URL')
    keygen_parser.add_argument('--api-key', '-k', required=True, help='API key')

    subparsers.add_parser('verify', help='Run leak test')

    rotate_parser = subparsers.add_parser('rotate-psk', help='Rotate PSK')
    rotate_parser.add_argument('--profile', '-p', help='Profile name')

    subparsers.add_parser('analyze', help='Run traffic analyzer')

    servers_parser = subparsers.add_parser('servers', help='Manage servers')
    servers_parser.add_argument('action', choices=['list', 'add', 'test'])
    servers_parser.add_argument('--name', help='Server name')
    servers_parser.add_argument('--endpoint', help='Server endpoint')
    servers_parser.add_argument('--api-url', help='API URL')
    servers_parser.add_argument('--api-key', help='API key')

    logs_parser = subparsers.add_parser('logs', help='View logs')
    logs_parser.add_argument('--type', choices=['connection', 'anomaly'],
                             default='connection', help='Log type')
    logs_parser.add_argument('--tail', '-n', type=int, help='Show last N lines')

    config_parser = subparsers.add_parser('config', help='View/edit configuration')
    config_parser.add_argument('--set', help='Set config value (key=value)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    vpn = VPNCore()

    handlers = {
        'list': cmd_list,
        'import': cmd_import,
        'up': cmd_up,
        'down': cmd_down,
        'status': cmd_status,
        'paths': cmd_paths,
        'keygen': cmd_keygen,
        'verify': cmd_verify,
        'rotate-psk': cmd_rotate_psk,
        'analyze': cmd_analyze,
        'servers': cmd_servers,
        'logs': cmd_logs,
        'config': cmd_config
    }

    handler = handlers.get(args.command)
    if handler:
        handler(vpn, args)
    else:
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == '__main__':
    print_header()
    main()
