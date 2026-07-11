#!/usr/bin/env python3
"""Split monolithic defendr.py into modular package."""
import re, os

content = open("defendr.py").read()

def extract_class(name):
    """Extract class definition by name."""
    m = re.search(r'(\nclass ' + name + r'.*?)(?=\nclass |\n# =====|\ndef main|\nif __name__)', content, re.DOTALL)
    if m: return m.group(1).strip()
    return None

def extract_func(name):
    m = re.search(r'(\ndef ' + name + r'.*?)(?=\ndef |\nclass |\n# =====)', content, re.DOTALL)
    if m: return m.group(1).strip()
    return None

os.makedirs("defendr", exist_ok=True)

# ---- constants.py ----
const_head = """# Constants and configuration for DefendR
import os
from pathlib import Path

DARK_BG = "#0a0015"
DARK_MID = "#1a0a2e"
DARK_CARD = "#140528"
BORDER = "#3d2b5e"
TEXT = "#e0e0e0"
TEXT_DIM = "#888"
ACCENT = "#7c4dff"
ACCENT_LIGHT = "#b388ff"
ACCENT_DARK = "#6200ea"
GREEN = "#2ecc71"
RED = "#e53935"
YELLOW = "#fdd835"
CYAN = "#00bfff"

QUARANTINE_DIR = os.path.expanduser("~/.defendr_quarantine")
CONFIG_DIR = os.path.expanduser("~/.defendr")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
"""
# Extract whitelist, sigs, etc from content
for name in ["PENTEST_WHITELIST", "MALICIOUS_SIGS", "SUSPICIOUS_EXTS",
             "SUSPICIOUS_STRINGS", "SUSPICIOUS_PROCESSES", "MALICIOUS_DOMAINS",
             "PHISHING_KEYWORDS", "RANSOMWARE_EXTENSIONS"]:
    m = re.search(r'^' + name + r' = [^\n]+(\n    .*)*', content, re.MULTILINE)
    if m:
        const_head += "\n" + m.group()

open("defendr/constants.py", "w").write(const_head)
print("✓ constants.py")

# ---- lang.py ----
m = re.search(r'(# ===================== TRANSLATION SYSTEM.*?)(?=class SplashScreen)', content, re.DOTALL)
if m:
    lang_code = "# Translation system (7 languages)\nimport os\nfrom constants import CONFIG_DIR\n\n" + m.group(1)
    open("defendr/lang.py", "w").write(lang_code)
    print("✓ lang.py")

# ---- engine.py ----
engine = extract_class("DefendREngine")
if engine:
    engine = "# Engine: scanning, signatures, whitelist\nimport os, json, threading, time, hashlib\nfrom pathlib import Path\nfrom datetime import datetime\nfrom constants import CONFIG_DIR, PENTEST_WHITELIST, MALICIOUS_SIGS, SUSPICIOUS_EXTS, SUSPICIOUS_STRINGS\n\n" + engine
    open("defendr/engine.py", "w").write(engine)
    print("✓ engine.py")

# ---- quarantine.py ----
q = extract_class("QuarantineManager")
if q:
    q = "# Quarantine management\nimport os, json, shutil\nfrom pathlib import Path\nfrom datetime import datetime\nfrom constants import QUARANTINE_DIR\n\n" + q
    open("defendr/quarantine.py", "w").write(q)
    print("✓ quarantine.py")

# ---- monitors.py ----
monitors = ""
for name in ["NetworkMonitor", "RealTimeProtector", "AntiRansomware", "WebcamProtector", "USBScanner", "GameMode"]:
    cls = extract_class(name)
    if cls:
        monitors += cls + "\n\n"
monitors = "# Monitors: network, real-time, ransomware, webcam, USB, game mode\nimport os, threading, time, subprocess, json\nfrom PyQt5 import QtCore, QtGui, QtWidgets\nfrom constants import *\nfrom engine import DefendREngine\n\n" + monitors
open("defendr/monitors.py", "w").write(monitors)
print("✓ monitors.py")

# ---- security.py ----
security = ""
for name in ["FirewallManager", "WebBlocker", "AntiPhishing", "SandboxManager", "RootkitDetector"]:
    cls = extract_class(name)
    if cls:
        security += cls + "\n\n"
security = "# Security tools: firewall, web blocker, anti-phishing, sandbox, rootkit detector\nimport os, subprocess, re, shutil, socket\nfrom PyQt5 import QtCore\nfrom constants import *\n\n" + security
open("defendr/security.py", "w").write(security)
print("✓ security.py")

# ---- tools.py ----
tools = ""
for name in ["DataShredder", "SoftwareUpdater", "CleanupManager", "PasswordManager", "VPNManager"]:
    cls = extract_class(name)
    if cls:
        tools += cls + "\n\n"
tools = "# Tools: shredder, software updater, cleanup, password manager, VPN\nimport os, subprocess, json, random, hashlib, base64, threading\nfrom pathlib import Path\nfrom PyQt5 import QtCore\nfrom constants import *\n\n" + tools
# Fix password manager encryption
tools = tools.replace(
    "import hashlib, base64\nclass PasswordManager",
    "from cryptography.fernet import Fernet\nimport base64, hashlib, os as _os\nclass PasswordManager"
)
tools = tools.replace(
    "return hashlib.sha256(password.encode()).hexdigest()",
    "import base64; return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())"
)
open("defendr/tools.py", "w").write(tools)
print("✓ tools.py")

# ---- network_tools.py ----
ntools = ""
for name in ["NetworkInspector", "WiFiInspector", "DNSOverHTTPS"]:
    cls = extract_class(name)
    if cls:
        ntools += cls + "\n\n"
ntools = "# Network tools: inspector, WiFi scanner, DNS over HTTPS\nimport os, subprocess, json, socket, threading, time, random\nfrom PyQt5 import QtCore\nfrom constants import *\n\n" + ntools
open("defendr/network_tools.py", "w").write(ntools)
print("✓ network_tools.py")

# ---- scheduler.py ----
sched = ""
for name in ["Scheduler", "SignatureUpdater"]:
    cls = extract_class(name)
    if cls:
        sched += cls + "\n\n"
sched = "# Scheduler and signature updater\nimport os, json, threading, time, subprocess, urllib.request\nfrom datetime import datetime, timedelta\nfrom PyQt5 import QtCore\nfrom constants import CONFIG_DIR\n\n" + sched
open("defendr/scheduler.py", "w").write(sched)
print("✓ scheduler.py")

# ---- ui.py (MainWindow only, not SplashScreen) ----
# Extract from "class MainWindow" to before "def main()"
ui_match = re.search(r'(class MainWindow.*?)(?=class SplashScreen)', content, re.DOTALL)
splash_match = re.search(r'(class SplashScreen.*?)(?=class MainWindow)', content, re.DOTALL)
if not splash_match:
    splash_match = re.search(r'(class SplashScreen.*?)(?=def main)', content, re.DOTALL)

if splash_match:
    splash_code = splash_match.group(1).strip()
else:
    splash_code = "# SplashScreen will be defined in ui.py"

ui_match = re.search(r'(class MainWindow.*?)(?=def main)', content, re.DOTALL)

if ui_match:
    ui_code = ui_match.group(1).strip()
    # Remove functions that are in other modules (extract only MainWindow class)
    ui_code = "# Main UI: MainWindow, SplashScreen\nimport os, sys, json, subprocess, threading, time, socket\nfrom datetime import datetime\nfrom PyQt5 import QtCore, QtGui, QtWidgets\n\n" + splash_code + "\n\n" + ui_code
    # Fix imports - replace local references
    ui_code = ui_code.replace("from constants import", "from defendr.constants import")
    ui_code = ui_code.replace("from engine import", "from defendr.engine import")
    ui_code = ui_code.replace("from monitors import", "from defendr.monitors import")
    ui_code = ui_code.replace("from security import", "from defendr.security import")
    ui_code = ui_code.replace("from tools import", "from defendr.tools import")
    ui_code = ui_code.replace("from network_tools import", "from defendr.network_tools import")
    ui_code = ui_code.replace("from quarantine import", "from defendr.quarantine import")
    ui_code = ui_code.replace("from scheduler import", "from defendr.scheduler import")
    ui_code = ui_code.replace("from lang import", "from defendr.lang import")
    open("defendr/ui.py", "w").write(ui_code)
    print("✓ ui.py")

# ---- __init__.py ----
init_code = """# DefendR package
import os, sys, socket, threading, subprocess
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import DARK_BG, DARK_CARD, DARK_MID, TEXT, ACCENT
from defendr.ui import MainWindow, SplashScreen
from defendr.lang import _
from defendr.constants import CONFIG_DIR

def main():
    LOCK_PORT = 48123
    lock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lock_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lock_sock.bind(("127.0.0.1", LOCK_PORT))
        lock_sock.listen(1)
    except OSError:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", LOCK_PORT)); s.sendall(b"raise"); s.close()
        except: pass
        sys.exit(0)

    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(DARK_BG))
    palette.setColor(QtGui.QPalette.Background, QtGui.QColor(DARK_BG))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(DARK_CARD))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor(TEXT))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(TEXT))
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(ACCENT))
    palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("white"))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(ACCENT))
    palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor("white"))
    app.setPalette(palette)
    font = QtGui.QFont("Consolas", 10)
    app.setFont(font)

    splash = SplashScreen()
    splash.draw(_("DefendR - Advanced Protection"), 10)

    window = MainWindow()
    splash.draw(_("DefendR - Advanced Protection"), 100)
    splash.finish(window)
    window.show()

    def listen_raise():
        while True:
            try:
                conn, addr = lock_sock.accept()
                data = conn.recv(1024)
                if data == b"raise":
                    window.raise_(); window.activateWindow(); window.show(); window.tray.show()
                conn.close()
            except: break
    threading.Thread(target=listen_raise, daemon=True).start()

    if os.geteuid() != 0:
        QtCore.QTimer.singleShot(3000, lambda: window.tray.showMessage(
            "DefendR", _("Run with sudo for full firewall and network monitoring."),
            QtWidgets.QSystemTrayIcon.Information, 3000))

    sys.exit(app.exec())

if __name__ == "__main__":
    if not os.environ.get("DISPLAY"):
        print("DefendR requires a graphical display to run.")
        sys.exit(1)
    main()
"""
open("defendr/__init__.py", "w").write(init_code)
print("✓ __init__.py")

print("\\nAll modules created!")
