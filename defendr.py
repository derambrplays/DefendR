#!/usr/bin/env python3
"""DefendR - Advanced Antivirus & Security Suite"""
import sys, os

if __name__ == "__main__":
    if not os.environ.get("DISPLAY"):
        print("DefendR requires a graphical display to run.")
        sys.exit(1)
    from defendr import main
    main()
