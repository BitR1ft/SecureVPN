#!/usr/bin/env python3
"""
SecureVPN GUI Launcher
======================
Entry point for the SecureVPN GUI application.
This file is used by PyInstaller to build the EXE.
"""

import sys
import os
from pathlib import Path

# Ensure the client directory is on the path so 'securevpn' package can be found
script_dir = Path(__file__).parent.resolve()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

# DPI awareness for crisp rendering on Windows
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from securevpn.gui.app import main

if __name__ == '__main__':
    main()
