"""
SecureVPN Client Entry Point
============================
"""

import sys


def main():
    # Always launch CLI by default
    from securevpn.cli import main as cli_main
    cli_main()


if __name__ == '__main__':
    main()
