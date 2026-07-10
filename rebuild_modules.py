#!/usr/bin/env python3
"""Rebuild all module files from git history."""
import subprocess, re, os

result = subprocess.run(["git", "show", "HEAD:defendr.py"], capture_output=True, text=True)
content = result.stdout

pkg = "defendr"
os.makedirs(pkg, exist_ok=True)

def extract_class(name):
    pattern = r'(\nclass ' + re.escape(name) + r'.*?)(?=\nclass |\n# =====|\ndef main|\nif __name__|\ndef detect_app)'
    m = re.search(pattern, content, re.DOTALL)
    if m: return m.group(1).strip()
    return None

def extract_func(name):
    pattern = r'(\ndef ' + re.escape(name) + r'.*?)(?=\ndef |\nclass |\n# =====)'
    m = re.search(pattern, content, re.DOTALL)
    if m: return m.group(1).strip()
    return None

fix_imports = lambda code: re.sub(r'^from (?!defendr)(\w+) import', r'from defendr.\1 import', code, flags=re.MULTILINE)

# ---- engine.py ----
engine_cls = extract_class("DefendREngine")
if engine_cls:
    engine_cls = fix_imports(engine_cls)
    engine_code = """# Engine: file scanning and threat detection
import os, json, threading, time, hashlib
from pathlib import Path
from datetime import datetime
from defendr.constants import CONFIG_DIR, PENTEST_WHITELIST, MALICIOUS_SIGS, SUSPICIOUS_EXTS, SUSPICIOUS_STRINGS

""" + engine_cls + "\n"
    open(f"{pkg}/engine.py", "w").write(engine_code)
    print("✓ engine.py")

# ---- quarantine.py ----
q_cls = extract_class("QuarantineManager")
if q_cls:
    q_cls = fix_imports(q_cls)
    q_code = """# Quarantine management
import os, json, shutil
from pathlib import Path
from datetime import datetime
from defendr.constants import QUARANTINE_DIR

""" + q_cls + "\n"
    open(f"{pkg}/quarantine.py", "w").write(q_code)
    print("✓ quarantine.py")

# ---- monitors.py ----
monitors = {}
for name in ["NetworkMonitor", "RealTimeProtector", "AntiRansomware", "WebcamProtector", "USBScanner", "GameMode"]:
    cls = extract_class(name)
    if cls:
        cls = fix_imports(cls)
        monitors[name] = cls
if monitors:
    code = """# Monitors: network, real-time, ransomware, webcam, USB, game mode
import os, threading, time, subprocess, json
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import *
from defendr.engine import DefendREngine

""" + "\n\n".join(monitors.values()) + "\n"
    open(f"{pkg}/monitors.py", "w").write(code)
    print("✓ monitors.py")

# ---- security.py ----
security = {}
for name in ["FirewallManager", "WebBlocker", "AntiPhishing", "SandboxManager", "RootkitDetector"]:
    cls = extract_class(name)
    if cls:
        cls = fix_imports(cls)
        security[name] = cls
if security:
    code = """# Security tools: firewall, web blocker, anti-phishing, sandbox, rootkit detector
import os, subprocess, re, shutil, socket
from PyQt5 import QtCore
from defendr.constants import *

""" + "\n\n".join(security.values()) + "\n"
    open(f"{pkg}/security.py", "w").write(code)
    print("✓ security.py")

# ---- tools.py ----
tools = {}
for name in ["DataShredder", "SoftwareUpdater", "CleanupManager", "PasswordManager", "VPNManager"]:
    cls = extract_class(name)
    if cls:
        cls = fix_imports(cls)
        tools[name] = cls
if tools:
    code = """# Tools: shredder, software updater, cleanup, password manager, VPN
import os, subprocess, json, random, hashlib, base64, threading
from pathlib import Path
from PyQt5 import QtCore
from defendr.constants import *

""" + "\n\n".join(tools.values()) + "\n"
    # Fix PasswordManager to use Fernet instead of XOR
    code = code.replace(
        'import hashlib, base64\n\nclass PasswordManager',
        'from cryptography.fernet import Fernet\nimport base64, os as _os\n\nclass PasswordManager'
    )
    code = code.replace(
        'return hashlib.sha256(password.encode()).hexdigest()',
        'return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())'
    )
    open(f"{pkg}/tools.py", "w").write(code)
    print("✓ tools.py")

# ---- network_tools.py ----
net_tools = {}
for name in ["NetworkInspector", "WiFiInspector", "DNSOverHTTPS"]:
    cls = extract_class(name)
    if cls:
        cls = fix_imports(cls)
        net_tools[name] = cls
if net_tools:
    code = """# Network tools: inspector, WiFi scanner, DNS over HTTPS
import os, subprocess, json, socket, threading, time, random
from PyQt5 import QtCore
from defendr.constants import *

""" + "\n\n".join(net_tools.values()) + "\n"
    open(f"{pkg}/network_tools.py", "w").write(code)
    print("✓ network_tools.py")

# ---- scheduler.py ----
sched = {}
for name in ["Scheduler", "SignatureUpdater"]:
    cls = extract_class(name)
    if cls:
        cls = fix_imports(cls)
        sched[name] = cls
if sched:
    code = """# Scheduler and signature updater
import os, json, threading, time, urllib.request
from datetime import datetime, timedelta
from PyQt5 import QtCore
from defendr.constants import CONFIG_DIR

""" + "\n\n".join(sched.values()) + "\n"
    open(f"{pkg}/scheduler.py", "w").write(code)
    print("✓ scheduler.py")

# ---- ui.py (SplashScreen + MainWindow) ----
splash = extract_class("SplashScreen")
mainwin = extract_class("MainWindow")
if mainwin:
    mainwin = fix_imports(mainwin)
    splash_code = ""
    if splash:
        splash = fix_imports(splash)
        splash_code = splash + "\n\n"
    
    ui_code = """# Main UI: SplashScreen, MainWindow, all pages and handlers
import os, sys, json, subprocess, threading, time, socket
from datetime import datetime
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import *
from defendr.engine import DefendREngine
from defendr.monitors import NetworkMonitor, RealTimeProtector, AntiRansomware, WebcamProtector, USBScanner, GameMode
from defendr.security import FirewallManager, WebBlocker, AntiPhishing, SandboxManager, RootkitDetector
from defendr.tools import DataShredder, SoftwareUpdater, CleanupManager, PasswordManager, VPNManager
from defendr.network_tools import NetworkInspector, WiFiInspector, DNSOverHTTPS
from defendr.quarantine import QuarantineManager
from defendr.scheduler import Scheduler, SignatureUpdater
from defendr.lang import _

""" + splash_code + mainwin + "\n"
    open(f"{pkg}/ui.py", "w").write(ui_code)
    print("✓ ui.py")

print("\nAll modules rebuilt!")
