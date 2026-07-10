#!/usr/bin/env python3
"""DefendR - Advanced Antivirus & Security Suite"""
import sys, os

if __name__ == "__main__":
    if "--sudo" in sys.argv:
        try:
            script = os.path.abspath(__file__)
            args = [a for a in sys.argv if a != "--sudo"]
            os.execvp("pkexec", ["pkexec", sys.executable, "-m", "defendr"] + args)
        except FileNotFoundError:
            os.execvp("sudo", ["sudo", sys.executable, "-m", "defendr"] + [a for a in sys.argv if a != "--sudo"])
        except: pass
    if not os.environ.get("DISPLAY"):
        print("DefendR requires a graphical display to run.")
        sys.exit(1)
    from defendr import main
    main()
