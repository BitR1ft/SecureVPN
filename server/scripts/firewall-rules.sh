#!/bin/bash
# Firewall Hardening Script
# Run after WireGuard setup

set -euo pipefail

echo "Applying firewall hardening rules..."

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Default policy: DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (adjust port if needed)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow WireGuard
iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Allow forwarding from wg0 to WAN
iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT

# NAT for VPN traffic
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Anti-spoofing
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP

# Rate limit new connections
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/minute --limit-burst 5 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

echo "Firewall rules applied successfully"
