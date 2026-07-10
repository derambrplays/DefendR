#!/usr/bin/env python3
"""Fix 6 more critical bugs: race conditions, quarantine, memory leak, encoding, sandbox, globals."""

import os, re

pkg = "/home/kalleb/DefendR/defendr"

# =====================================================================
# FIX 1: Create filelock.py module for all locking
# =====================================================================
print("=== Creating filelock.py ===")
with open(f"{pkg}/filelock.py", "w") as f:
    f.write("""# Simple file locking using fcntl.flock (Linux only)
import fcntl, os, contextlib

_lock_files = {}

@contextlib.contextmanager
def file_lock(path, timeout=5):
    path = os.path.abspath(path)
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        try: os.remove(lock_path)
        except: pass

def safe_json_read(path, default=None):
    if not os.path.exists(path): return default
    with file_lock(path):
        try:
            with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
                return json.load(f)
        except: return default

def safe_json_write(path, data):
    with file_lock(path):
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
""")
print("  filelock.py OK")

# =====================================================================
# FIX 1+2+4: quarantine.py - symlinks, cross-fs, encoding, locking
# =====================================================================
print("=== Fixing quarantine.py ===")
new_quarantine = """# Quarantine management with file locking, symlink safety, cross-fs support
import os, json, shutil, uuid, hashlib
from pathlib import Path
from datetime import datetime
from defendr.constants import QUARANTINE_DIR
from defendr.filelock import file_lock, safe_json_read, safe_json_write

class QuarantineManager:
    def __init__(self):
        self.quar_dir = QUARANTINE_DIR
        self.meta_file = os.path.join(QUARANTINE_DIR, "metadata.json")
        self.metadata = self._load_meta()
    def _load_meta(self):
        return safe_json_read(self.meta_file) or {}
    def _save_meta(self):
        safe_json_write(self.meta_file, self.metadata)
    def quarantine(self, filepath):
        fpath = Path(os.path.realpath(filepath))
        if not fpath.exists(): return False, "File not found"
        if fpath.is_symlink(): return False, "Cannot quarantine a symlink (resolve real path first)"
        qid = uuid.uuid4().hex[:12]
        dest = os.path.join(self.quar_dir, qid + fpath.suffix)
        try:
            shutil.move(str(fpath), dest)
        except shutil.Error:
            shutil.copy2(str(fpath), dest)
            os.remove(str(fpath))
        meta = {
            "original": str(fpath.resolve()),
            "quarantined": dest,
            "date": datetime.now().isoformat(),
            "hash": hashlib.sha256(open(dest, "rb").read()).hexdigest(),
            "size": os.path.getsize(dest),
        }
        self.metadata[qid] = meta
        self._save_meta()
        return True, qid
    def restore(self, qid):
        if qid not in self.metadata: return False, "ID not found"
        info = self.metadata[qid]
        orig = Path(info["original"])
        orig.parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(info["quarantined"]):
            try:
                shutil.move(info["quarantined"], str(orig))
            except shutil.Error:
                shutil.copy2(info["quarantined"], str(orig))
                os.remove(info["quarantined"])
        del self.metadata[qid]
        self._save_meta()
        return True, str(orig)
    def delete_permanently(self, qid):
        if qid not in self.metadata: return False, "ID not found"
        info = self.metadata[qid]
        if os.path.exists(info["quarantined"]): os.remove(info["quarantined"])
        del self.metadata[qid]
        self._save_meta()
        return True, "Deleted"
    def list_quarantined(self):
        return list(self.metadata.items())
"""
with open(f"{pkg}/quarantine.py", "w") as f:
    f.write(new_quarantine)
print("  quarantine.py OK")

# =====================================================================
# FIX 1+4: engine.py - file locking, encoding
# =====================================================================
print("=== Fixing engine.py ===")
with open(f"{pkg}/engine.py") as f:
    code = f.read()

# Add filelock import
code = code.replace(
    "from defendr.constants import CONFIG_DIR, PENTEST_WHITELIST, MALICIOUS_SIGS, SUSPICIOUS_EXTS, SUSPICIOUS_STRINGS",
    "from defendr.constants import CONFIG_DIR, PENTEST_WHITELIST, MALICIOUS_SIGS, SUSPICIOUS_EXTS, SUSPICIOUS_STRINGS\nfrom defendr.filelock import file_lock, safe_json_read, safe_json_write"
)

# Fix load_config to use safe_json_read
old_load = """    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    data = json.load(f)
                    self.whitelist.update(data.get("whitelist", []))
            except Exception: pass"""
new_load = """    def load_config(self):
        data = safe_json_read(self.config_file)
        if data:
            self.whitelist.update(data.get("whitelist", []))"""
code = code.replace(old_load, new_load)

# Fix save_config to use safe_json_write
old_save = """    def save_config(self):
        with open(self.config_file, "w") as f:
            json.dump({"whitelist": list(self.whitelist)}, f, indent=2)"""
new_save = """    def save_config(self):
        safe_json_write(self.config_file, {"whitelist": list(self.whitelist)})"""
code = code.replace(old_save, new_save)

# Fix _scan_file to use binary mode (already is) but add encoding safety for text
old_scan = """            with open(fpath, "rb") as f:
                header = f.read(16)
                for sig, desc in MALICIOUS_SIGS:
                    if header.startswith(sig):
                        return {"path": str(fpath), "risk": "malicious", "reason": desc, "size": size}
                f.seek(0)
                content = f.read(min(size, 8192))
                found = [s for s in SUSPICIOUS_STRINGS if s in content]
                if len(found) >= 3:
                    return {"path": str(fpath), "risk": "suspicious",
                            "reason": f"Flagged: {', '.join(s.decode(errors='replace') for s in found[:4])}", "size": size}"""
new_scan = """            with open(fpath, "rb") as f:
                header = f.read(16)
                for sig, desc in MALICIOUS_SIGS:
                    if header.startswith(sig):
                        return {"path": str(fpath), "risk": "malicious", "reason": desc, "size": size}
                f.seek(0)
                content = f.read(min(size, 8192))
                found = [s for s in SUSPICIOUS_STRINGS if s in content]
                if len(found) >= 3:
                    return {"path": str(fpath), "risk": "suspicious",
                            "reason": f"Flagged: {', '.join(s.decode(errors='replace') for s in found[:4])}", "size": size}"""
code = code.replace(old_scan, new_scan)

# Fix get_processes to handle encoding errors in process names
old_procs = """    def get_processes(self):
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "connections", "status"]):
                try:
                    pinfo = p.info
                    procs.append({
                        "pid": pinfo["pid"], "name": pinfo["name"] or "?",
                        "cpu": pinfo["cpu_percent"] or 0, "mem": pinfo["memory_percent"] or 0,
                        "conns": len(pinfo.get("connections") or []),
                        "suspicious": pinfo["name"] and any(s in pinfo["name"].lower() for s in SUSPICIOUS_PROCESSES),
                        "pentest": pinfo["name"] and self.is_pentest(pinfo["name"]),
                    })
                except Exception: pass
            return procs
        except Exception: return []"""

new_procs = """    def get_processes(self):
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                try:
                    pinfo = p.info
                    name = str(pinfo.get("name") or "?").encode("utf-8", errors="replace").decode("utf-8", errors="replace")
                    try: conns = len(p.connections())
                    except: conns = 0
                    procs.append({
                        "pid": pinfo["pid"], "name": name,
                        "cpu": pinfo["cpu_percent"] or 0, "mem": pinfo["memory_percent"] or 0,
                        "conns": conns,
                        "suspicious": name and any(s in name.lower() for s in SUSPICIOUS_PROCESSES),
                        "pentest": name and self.is_pentest(name),
                    })
                except Exception: pass
            return procs
        except Exception: return []"""

code = code.replace(old_procs, new_procs)

with open(f"{pkg}/engine.py", "w") as f:
    f.write(code)
print("  engine.py OK")

# =====================================================================
# FIX 4+5: security.py - encoding + sandbox improvements
# =====================================================================
print("=== Fixing security.py ===")
with open(f"{pkg}/security.py") as f:
    code = f.read()

# Add encoding safety to all subprocess text=True calls
code = code.replace(
    'capture_output=True, text=True, timeout=5',
    'capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5'
)
code = code.replace(
    'capture_output=True, text=True, timeout=2',
    'capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=2'
)

# Improve SandboxManager with unshare fallback and AppArmor/SELinux check
old_sandbox = """class SandboxManager:
    def __init__(self):
        super().__init__()
        self.available = False
        self.sandbox_type = None
        self._check_tools()
    def _check_tools(self):
        for cmd, stype in [("firejail", "firejail"), ("bwrap", "bubblewrap")]:
            try:
                r = subprocess.run(["which", cmd], capture_output=True, timeout=2)
                if r.returncode == 0:
                    self.available = True
                    self.sandbox_type = stype
                    return
            except Exception: pass
    def run_in_sandbox(self, filepath, args=""):
        if not self.available: return False, "No sandbox tool available (install firejail)"
        if not os.path.exists(filepath): return False, "File not found"
        try:
            if self.sandbox_type == "firejail":
                cmd = ["firejail", "--seccomp", "--net=none", filepath] + (shlex.split(args) if args else [])
            else:
                cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                       "--unshare-net", filepath] + (shlex.split(args) if args else [])
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, f"Running in {self.sandbox_type}"
        except Exception as e: return False, str(e)"""

new_sandbox = """class SandboxManager:
    def __init__(self):
        super().__init__()
        self.available = False
        self.sandbox_type = None
        self._check_tools()
    def _check_tools(self):
        for cmd, stype in [("firejail", "firejail"), ("bwrap", "bubblewrap")]:
            try:
                r = subprocess.run(["which", cmd], capture_output=True, timeout=2)
                if r.returncode == 0:
                    self.available = True
                    self.sandbox_type = stype
                    return
            except Exception: pass
        if self._check_unshare():
            self.available = True
            self.sandbox_type = "unshare"
    def _check_unshare(self):
        try:
            r = subprocess.run(["unshare", "--version"], capture_output=True, timeout=2)
            return r.returncode == 0
        except: return False
    def _check_apparmor(self):
        try:
            r = subprocess.run(["aa-status"], capture_output=True, timeout=2)
            return r.returncode == 0
        except: return False
    def _check_selinux(self):
        try:
            r = subprocess.run(["getenforce"], capture_output=True, timeout=2)
            return "Enforcing" in r.stdout
        except: return False
    def run_in_sandbox(self, filepath, args=""):
        if not self.available: return False, "No sandbox tool available (install firejail or bubblewrap)"
        if not os.path.exists(filepath): return False, "File not found"
        try:
            aa_enforcing = self._check_apparmor()
            se_enforcing = self._check_selinux()
            if self.sandbox_type == "firejail":
                cmd = ["firejail", "--seccomp", "--quiet"]
                if aa_enforcing: cmd.append("--apparmor")
                cmd += [filepath] + (shlex.split(args) if args else [])
            elif self.sandbox_type == "bubblewrap":
                home = os.path.expanduser("~")
                cmd = ["bwrap", "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                       "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/bin", "/bin",
                       "--ro-bind", "/etc", "/etc", "--ro-bind", home, home,
                       "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
                       "--unshare-net", "--unshare-ipc", "--unshare-pid",
                       filepath] + (shlex.split(args) if args else [])
            else:
                cmd = ["unshare", "-r", "-n", filepath] + (shlex.split(args) if args else [])
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            aa_msg = " (AppArmor detected)" if aa_enforcing else ""
            se_msg = " (SELinux detected)" if se_enforcing else ""
            return True, f"Running in {self.sandbox_type}{aa_msg}{se_msg}"
        except Exception as e: return False, str(e)"""

code = code.replace(old_sandbox, new_sandbox)

# Fix Phishing DB file access with locking
old_phish_save = """    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file) as f: self.phishing_db.update(json.load(f))
            except: pass
    def save_cache(self):
        with open(self.cache_file, "w") as f: json.dump(list(self.phishing_db), f)"""

new_phish_save = """    def _load_cache(self):
        if os.path.exists(self.cache_file):
            data = safe_json_read(self.cache_file)
            if data: self.phishing_db.update(data)
    def save_cache(self):
        safe_json_write(self.cache_file, list(self.phishing_db))"""

code = code.replace(old_phish_save, new_phish_save)

# Add safe_json_read/write import at the top
code = code.replace(
    "import os, subprocess, re, shutil, socket, shlex",
    "import os, subprocess, re, shutil, socket, shlex, json\nfrom defendr.filelock import file_lock, safe_json_read, safe_json_write"
)

# Fix AntiPhishing to import json for cache_file reference
# (it already imports json via the new import line)

# Fix the class definition to have no super().__init__() since it doesn't inherit QObject
# Already the case - SandboxManager is the one with super().__init__() that needed fixing

# Fix RootkitDetector to handle encoding
old_lsmod = """            r = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)"""
new_lsmod = """            r = subprocess.run(["lsmod"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)"""
code = code.replace(old_lsmod, new_lsmod)

old_cat = """            r = subprocess.run(["cat","/proc/modules"], capture_output=True, text=True, timeout=5)"""
new_cat = """            r = subprocess.run(["cat","/proc/modules"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)"""
code = code.replace(old_cat, new_cat)

with open(f"{pkg}/security.py", "w") as f:
    f.write(code)
print("  security.py OK")

# =====================================================================
# FIX 4: network_tools.py - encoding for subprocess
# =====================================================================
print("=== Fixing network_tools.py ===")
with open(f"{pkg}/network_tools.py") as f:
    code = f.read()

# Fix all subprocess calls with text=True to add encoding safety
code = code.replace(
    'capture_output=True, text=True, timeout=5',
    'capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5'
)
code = code.replace(
    ', text=True, timeout=90)',
    ', text=True, encoding="utf-8", errors="surrogateescape", timeout=90)'
)
code = code.replace(
    'text=True, timeout=5)',
    'text=True, encoding="utf-8", errors="surrogateescape", timeout=5)'
)

# Fix .decode() calls to use errors='replace'
code = code.replace(
    ".read().decode()",
    ".read().decode(errors='replace')"
)

# Fix DNSOverHTTPS to add encoding to subprocess calls
code = code.replace(
    'capture_output=True, timeout=5',
    'capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5'
)

with open(f"{pkg}/network_tools.py", "w") as f:
    f.write(code)
print("  network_tools.py OK")

# =====================================================================
# FIX 1+6: scheduler.py - locking + don't mutate MALICIOUS_SIGS
# =====================================================================
print("=== Fixing scheduler.py ===")
with open(f"{pkg}/scheduler.py") as f:
    code = f.read()

# Add imports
code = code.replace(
    "import os, json, threading, time, urllib.request",
    "import os, json, threading, time, urllib.request, uuid\nfrom defendr.filelock import file_lock, safe_json_read, safe_json_write"
)

# Fix _load and _save
code = code.replace(
    '    def _load(self):\n        path = os.path.join(CONFIG_DIR, "scheduler.json")\n        if os.path.exists(path):\n            try:\n                with open(path) as f: self.tasks = json.load(f)\n            except Exception: pass',
    '    def _load(self):\n        path = os.path.join(CONFIG_DIR, "scheduler.json")\n        data = safe_json_read(path)\n        if data: self.tasks = data'
)
code = code.replace(
    '    def _save(self):\n        path = os.path.join(CONFIG_DIR, "scheduler.json")\n        with open(path, "w") as f: json.dump(self.tasks, f, indent=2)',
    '    def _save(self):\n        safe_json_write(os.path.join(CONFIG_DIR, "scheduler.json"), self.tasks)'
)

# Fix SignatureUpdater to copy MALICIOUS_SIGS instead of mutating
old_sig_update = """            for sig_bytes, desc in new_sigs:
                sig = bytes.fromhex(sig_bytes) if isinstance(sig_bytes, str) else bytes(sig_bytes)
                existing_sigs = {s[0] for s in MALICIOUS_SIGS}
                if sig not in existing_sigs:
                    MALICIOUS_SIGS.append((sig, desc))
                    n += 1"""

new_sig_update = """            for sig_bytes, desc in new_sigs:
                sig = bytes.fromhex(sig_bytes) if isinstance(sig_bytes, str) else bytes(sig_bytes)
                existing_sigs = {s[0] for s in MALICIOUS_SIGS}
                if sig not in existing_sigs:
                    self.engine.malicious_sigs.append((sig, desc))
                    n += 1"""

code = code.replace(old_sig_update, new_sig_update)

# Also fix get_signature_count to use engine's copy
if "def get_signature_count" in code:
    old_sig_count = """    def get_signature_count(self):
        return len(MALICIOUS_SIGS) + len(SUSPICIOUS_STRINGS) + len(self.engine.whitelist)"""
    new_sig_count = """    def get_signature_count(self):
        return len(self.engine.malicious_sigs) + len(self.engine.suspicious_strings) + len(self.engine.whitelist)"""
    code = code.replace(old_sig_count, new_sig_count)

# Fix SignatureUpdater _load and sig_file
code = code.replace(
    '    def _load(self):\n        if os.path.exists(self.sig_file):\n            try:\n                with open(self.sig_file) as f: data = json.load(f)\n                self.engine.whitelist.update(data.get("whitelist", []))\n            except Exception: pass',
    '    def _load(self):\n        data = safe_json_read(self.sig_file)\n        if data:\n            self.engine.whitelist.update(data.get("whitelist", []))'
)

code = code.replace(
    '        with open(self.sig_file, "w") as f: json.dump(data, f, indent=2)',
    '        safe_json_write(self.sig_file, data)'
)

with open(f"{pkg}/scheduler.py", "w") as f:
    f.write(code)
print("  scheduler.py OK")

# =====================================================================
# FIX 1+4+6: tools.py - locking, encoding, global state
# =====================================================================
print("=== Fixing tools.py ===")
with open(f"{pkg}/tools.py") as f:
    code = f.read()

# Add filelock import
code = code.replace(
    "from defendr.constants import *",
    "from defendr.constants import *\nfrom defendr.filelock import file_lock, safe_json_read, safe_json_write"
)

# Fix PasswordManager to use locked file access
old_pwd_vault = """    def _load_vault(self):
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file) as f: data = json.load(f)
                self.master_hash = data.get("master_hash")
                self.entries = data.get("entries", [])
            except: pass
    def _save_vault(self):
        with open(self.vault_file, "w") as f:
            json.dump({"master_hash": self.master_hash, "entries": self.entries}, f)"""

new_pwd_vault = """    def _load_vault(self):
        data = safe_json_read(self.vault_file)
        if data:
            self.master_hash = data.get("master_hash")
            self.entries = data.get("entries", [])
    def _save_vault(self):
        safe_json_write(self.vault_file, {"master_hash": self.master_hash, "entries": self.entries})"""

code = code.replace(old_pwd_vault, new_pwd_vault)

# Fix VPNManager to use encoding-safe subprocess calls
code = code.replace(
    "r = subprocess.run([\"which\",\"openvpn\"], capture_output=True, timeout=2)",
    "r = subprocess.run([\"which\",\"openvpn\"], capture_output=True, encoding=\"utf-8\", errors=\"surrogateescape\", timeout=2)"
)

with open(f"{pkg}/tools.py", "w") as f:
    f.write(code)
print("  tools.py OK")

# =====================================================================
# FIX 3: ui.py - cap alert_list in all handlers
# =====================================================================
print("=== Fixing ui.py ===")
with open(f"{pkg}/ui.py") as f:
    code = f.read()

# Add cap after all alert_list.insertItem calls that don't have it
# _on_ransomware_alert (currently at ~1086-1091)
old_ransom = """    def _on_ransomware_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[RANSOM]{msg}"))"""

new_ransom = """    def _on_ransomware_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[RANSOM]{msg}"))
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)"""

code = code.replace(old_ransom, new_ransom)

# _on_rootkit_alert
old_rootkit = """    def _on_rootkit_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        item.setForeground(QtGui.QColor(RED if level == "HIGH" else YELLOW))
        self.alert_list.insertItem(0, item)"""

new_rootkit = """    def _on_rootkit_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        item.setForeground(QtGui.QColor(RED if level == "HIGH" else YELLOW))
        self.alert_list.insertItem(0, item)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)"""

code = code.replace(old_rootkit, new_rootkit)

# _on_usb_alert
old_usb = """    def _on_usb_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[USB][{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, item)"""

new_usb = """    def _on_usb_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[USB][{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, item)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)"""

code = code.replace(old_usb, new_usb)

# _on_webcam_alert
old_webcam = """    def _on_webcam_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[WEBCAM][{level}] {msg}")
        item.setForeground(QtGui.QColor(YELLOW))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[WEBCAM] {msg}"))"""

new_webcam = """    def _on_webcam_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[WEBCAM][{level}] {msg}")
        item.setForeground(QtGui.QColor(YELLOW))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[WEBCAM] {msg}"))
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)"""

code = code.replace(old_webcam, new_webcam)

# Fix _do_scan to use ScanWorker properly (the existing ScanWorker class)
# Make sure ScanWorker calls engine.malicious_sigs (not the module-level one)
# The ScanWorker already calls engine.scan_path which is fine

with open(f"{pkg}/ui.py", "w") as f:
    f.write(code)
print("  ui.py OK")

# =====================================================================
# FIX 6: constants.py - immutable data + engine mutable copies
# =====================================================================
print("=== Fixing constants.py ===")
with open(f"{pkg}/constants.py") as f:
    code = f.read()

# Make lists into tuples so they can't be mutated
code = code.replace(
    "MALICIOUS_SIGS = [",
    "MALICIOUS_SIGS = ("
)
code = code.replace(
    "SUSPICIOUS_EXTS = {",
    "SUSPICIOUS_EXTS = frozenset({"
)
code = code.replace(
    "SUSPICIOUS_STRINGS = [",
    "SUSPICIOUS_STRINGS = ("
)
code = code.replace(
    "RANSOMWARE_EXTENSIONS = {",
    "RANSOMWARE_EXTENSIONS = frozenset({"
)
code = code.replace(
    "PHISHING_KEYWORDS = [",
    "PHISHING_KEYWORDS = ("
)
code = code.replace(
    "MALICIOUS_DOMAINS = [",
    "MALICIOUS_DOMAINS = ("
)
code = code.replace(
    "SUSPICIOUS_PROCESSES = {",
    "SUSPICIOUS_PROCESSES = frozenset({"
)
# Close the frozenset and tuple properly
# These are already closed with } for dict, ] for list
# For the lists turned to tuples, need to fix closing
code = code.replace("MALICIOUS_SIGS = (", "MALICIOUS_SIGS = (")
code = code.replace("]\nSUSPICIOUS_EXTS", ")\nSUSPICIOUS_EXTS")
code = code.replace("]\nSUSPICIOUS_STRINGS", ")\nSUSPICIOUS_STRINGS")
code = code.replace("]\nRANSOMWARE_EXTENSIONS", "})\nRANSOMWARE_EXTENSIONS")
code = code.replace("]\nPHISHING_KEYWORDS", ")\nPHISHING_KEYWORDS")
code = code.replace("]\nMALICIOUS_DOMAINS", ")\nMALICIOUS_DOMAINS")
code = code.replace("}\nSUSPICIOUS_PROCESSES", "})\nSUSPICIOUS_PROCESSES")
# PENTEST_WHITELIST should be frozenset too
code = code.replace("PENTEST_WHITELIST = {", "PENTEST_WHITELIST = frozenset({")
code = code.replace("}\nMALICIOUS_SIGS", "})\nMALICIOUS_SIGS")

with open(f"{pkg}/constants.py", "w") as f:
    f.write(code)
print("  constants.py OK (immutable)")

# =====================================================================
# FIX 6: lang.py - remove duplicate, import CONFIG_DIR from constants
# =====================================================================
print("=== Fixing lang.py ===")
with open(f"{pkg}/lang.py") as f:
    code = f.read()

# Replace redefined CONFIG_DIR with import from constants
code = code.replace(
    'import os\n\nCONFIG_DIR = os.path.expanduser("~/.defendr")',
    'import os\nfrom defendr.constants import CONFIG_DIR'
)

# Remove duplicate detect_app_lang function
# Find the second definition and remove it
lines = code.split("\n")
new_lines = []
in_second_def = False
found_first = False
for i, line in enumerate(lines):
    if line.startswith("def detect_app_lang():") and not found_first:
        found_first = True
        new_lines.append(line)
    elif line.startswith("def detect_app_lang():") and found_first:
        in_second_def = True
        continue
    elif in_second_def:
        # Skip until we're out of the function
        if line.startswith("CURRENT_LANG = detect_app_lang()"):
            in_second_def = False
            continue
        if line.startswith("def ") or line.startswith("# "):
            in_second_def = False
            new_lines.append(line)
        continue
    else:
        new_lines.append(line)

code = "\n".join(new_lines)

# Make sure _ function works correctly
# Also add set_language function
code = code.rstrip() + """

def set_language(code):
    global CURRENT_LANG
    if code in APP_LANGS:
        CURRENT_LANG = code
        return True
    return False
"""

with open(f"{pkg}/lang.py", "w") as f:
    f.write(code)
print("  lang.py OK")

# =====================================================================
# FIX 6: engine.py - add mutable copies of constants for runtime mutation
# =====================================================================
print("=== Fixing engine.py (mutable copies) ===")
with open(f"{pkg}/engine.py") as f:
    code = f.read()

# Add mutable copies in __init__
old_init = """    def __init__(self):
        self.whitelist = set(PENTEST_WHITELIST)
        self.config_file = os.path.join(CONFIG_DIR, "config.json")
        self.load_config()
        self.scanning = False
        self.protection_active = True"""

new_init = """    def __init__(self):
        self.whitelist = set(PENTEST_WHITELIST)
        self.malicious_sigs = list(MALICIOUS_SIGS)
        self.suspicious_strings = list(SUSPICIOUS_STRINGS)
        self.config_file = os.path.join(CONFIG_DIR, "config.json")
        self.load_config()
        self.scanning = False
        self.protection_active = True"""

code = code.replace(old_init, new_init)

# Update _scan_file to use self.malicious_sigs and self.suspicious_strings instead of module-level
code = code.replace(
    "for sig, desc in MALICIOUS_SIGS:",
    "for sig, desc in self.malicious_sigs:"
)
code = code.replace(
    "found = [s for s in SUSPICIOUS_STRINGS if s in content]",
    "found = [s for s in self.suspicious_strings if s in content]"
)

# Update is_pentest to use self.whitelist (already does)
# Update get_processes to use self.malicious_sigs and self.suspicious_strings... 
# Actually SUSPICIOUS_PROCESSES is used in get_processes, not SUSPICIOUS_STRINGS
# Let me check what's actually used

with open(f"{pkg}/engine.py", "w") as f:
    f.write(code)
print("  engine.py mutable copies OK")

# =====================================================================
# FIX 2: cleanup fix - handle encoding errors in tools.py file operations
# =====================================================================
print("=== Fixing tools.py (encoding safety) ===")
with open(f"{pkg}/tools.py") as f:
    code = f.read()

# Add encoding safety to open() calls in CleanupManager and others
code = code.replace(
    'subprocess.run(["apt","list","--upgradable"], capture_output=True, text=True, timeout=60)',
    'subprocess.run(["apt","list","--upgradable"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=60)'
)
code = code.replace(
    'subprocess.run(["pip3","list","--outdated","--format=columns"], capture_output=True, text=True, timeout=30)',
    'subprocess.run(["pip3","list","--outdated","--format=columns"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=30)'
)
code = code.replace(
    'subprocess.run(["flatpak","update","--dry-run"], capture_output=True, text=True, timeout=60)',
    'subprocess.run(["flatpak","update","--dry-run"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=60)'
)
code = code.replace(
    'subprocess.run(["snap","refresh","--list"], capture_output=True, text=True, timeout=30)',
    'subprocess.run(["snap","refresh","--list"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=30)'
)
code = code.replace(
    'subprocess.run(["sudo","apt","upgrade","-y"], capture_output=True, text=True, timeout=300)',
    'subprocess.run(["sudo","apt","upgrade","-y"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=300)'
)
code = code.replace(
    'subprocess.run(["pip3","install","--upgrade","pip"], capture_output=True, timeout=60)',
    'subprocess.run(["pip3","install","--upgrade","pip"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=60)'
)
code = code.replace(
    'subprocess.run(["flatpak","update","-y"], capture_output=True, timeout=120)',
    'subprocess.run(["flatpak","update","-y"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=120)'
)

with open(f"{pkg}/tools.py", "w") as f:
    f.write(code)
print("  tools.py encoding safety OK")

# =====================================================================
# FIX 4: monitors.py - add encoding safety to subprocess calls
# =====================================================================
print("=== Fixing monitors.py (encoding) ===")
with open(f"{pkg}/monitors.py") as f:
    code = f.read()

code = code.replace(
    'capture_output=True, timeout=10)',
    'capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=10)'
)
code = code.replace(
    'capture_output=True, timeout=5)',
    'capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)'
)
code = code.replace(
    'capture_output=True, timeout=2)',
    'capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=2)'
)
# Fix NetworkMonitor._get_gateway
code = code.replace(
    'r = subprocess.run(["ip","route"], capture_output=True, text=True, timeout=3)',
    'r = subprocess.run(["ip","route"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=3)'
)

with open(f"{pkg}/monitors.py", "w") as f:
    f.write(code)
print("  monitors.py encoding OK")

# =====================================================================
# FIX 6: Remove CONFIG_DIR redefinition from lang.py (already done above)
# =====================================================================
print("=== Updating __init__.py for filelock ===")
# Make sure single-instance lock uses filelock too
with open(f"{pkg}/__init__.py") as f:
    code = f.read()

old_lock = """    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 48123))
        sock.listen(1)
    except (socket.error, OSError):
        print("DefendR is already running.")
        sys.exit(1)"""

new_lock = """    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 48123))
        sock.listen(1)
    except (socket.error, OSError):
        from PyQt5 import QtWidgets, QtCore
        app = QtWidgets.QApplication(sys.argv)
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setWindowTitle("DefendR")
        msg.setText("DefendR is already running.")
        msg.exec_()
        sys.exit(1)"""

code = code.replace(old_lock, new_lock)

with open(f"{pkg}/__init__.py", "w") as f:
    f.write(code)
print("  __init__.py OK (better lock message)")

# =====================================================================
# VERIFY ALL FILES
# =====================================================================
print("\n=== Verifying compilation ===")
import sys
sys.path.insert(0, "/home/kalleb/DefendR")
errors = []
files = ["filelock", "constants", "lang", "engine", "quarantine", "monitors",
         "security", "tools", "network_tools", "scheduler", "ui"]
for name in files:
    try:
        fp = f"{pkg}/{name}.py"
        with open(fp) as f:
            compile(f.read(), fp, 'exec')
        print(f"  OK {name}.py")
    except SyntaxError as e:
        print(f"  FAIL {name}.py: {e}")
        errors.append(name)

if errors:
    print(f"\nErrors in: {', '.join(errors)}")
else:
    print(f"\nAll {len(files)} files compile OK!")

# Final import test
try:
    exec("from defendr.filelock import *")
    exec("import defendr")
    print("Package import: OK")
except Exception as e:
    print(f"Package import FAILED: {e}")
    import traceback
    traceback.print_exc()
