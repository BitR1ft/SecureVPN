#!/usr/bin/env python3
"""
SecureVPN Launcher
==================
Works from any directory. Properly sets up Python path.
"""

import sys
import os
from pathlib import Path

# Add the directory containing this script to Python path
script_dir = Path(__file__).parent.resolve()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

# Import and run CLI
from securevpn.cli import main

if __name__ == '__main__':
    main()
