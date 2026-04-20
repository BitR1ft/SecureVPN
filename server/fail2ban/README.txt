"""
Test: fail2ban Configuration for SecureVPN API
================================================
Filter:  /etc/fail2ban/filter.d/wg-api.conf
Jail:    /etc/fail2ban/jail.d/wg-api.conf

Installation:
  cp fail2ban/wg-api.conf      /etc/fail2ban/filter.d/wg-api.conf
  cp fail2ban/wg-api-jail.conf /etc/fail2ban/jail.d/wg-api.conf
  systemctl restart fail2ban
  fail2ban-client status wg-api
"""
