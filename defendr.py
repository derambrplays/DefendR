#!/usr/bin/env python3
"""DefendR - Advanced Antivirus & Security Suite"""
import sys, os

if __name__ == "__main__":
    if not os.environ.get("DISPLAY"):
        os.environ["DISPLAY"] = ":0"
    from defendr import main
    main()
