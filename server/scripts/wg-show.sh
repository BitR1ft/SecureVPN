#!/bin/bash
# /usr/local/sbin/wg-show
# ========================
# Root-owned wrapper for reading WireGuard interface state.
# Accepts only specific subcommands: "wg0" or "dump"
#
# Sudoers rule: wg-api ALL=(root) NOPASSWD: /usr/local/sbin/wg-show

set -euo pipefail

SUBCMD="${1:-wg0}"

case "$SUBCMD" in
    "wg0")
        if ! /usr/bin/wg show wg0 2>/dev/null; then
            echo "[wg-show] wg0 interface is not active"
            exit 0
        fi
        ;;
    "dump")
        if ! /usr/bin/wg show wg0 dump 2>/dev/null; then
            echo "[wg-show] wg0 interface is not active"
            exit 0
        fi
        ;;
    "conf")
        if ! /usr/bin/wg showconf wg0 2>/dev/null; then
            echo "[wg-show] wg0 interface is not active"
            exit 0
        fi
        ;;
    *)
        echo "[wg-show] REJECTED: unknown subcommand '$SUBCMD'" >&2
        exit 1
        ;;
esac
