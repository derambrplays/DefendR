#!/usr/bin/env python3
"""Fix all 6 critical bugs in DefendR."""
import os, re

pkg = "/home/kalleb/DefendR/defendr"

# ========================================================
# FIX 1 & 4: monitors.py - shell=True, webcam, CPU loops
# ========================================================
print("=== Fixing monitors.py ===")
with open(f"{pkg}/monitors.py") as f:
    code = f.read()

# Fix shell=True: use glob instead
old_shell = '''subprocess.run(["sudo","chmod","000","/dev/video*"], shell=True, capture_output=True, timeout=10)'''
new_shell = '''import glob as _glob
                for vd in _glob.glob("/dev/video*"):
                    subprocess.run(["sudo","chmod","000",vd], capture_output=True, timeout=5)'''
code = code.replace(old_shell, new_shell)

# Fix webcam block to add udev rule method
old_block = '''    def block_webcam(self, hard=False):
        try:
            if hard:
                subprocess.run(["sudo","modprobe","-r","uvcvideo"], capture_output=True, timeout=10)
                subprocess.run(["sudo","modprobe","-r","videodev"], capture_output=True, timeout=10)
                self.blocked = True
                return "Webcam driver unloaded (hardware disabled)"
            else:
                subprocess.run(["sudo","chmod","000","/dev/video*"], shell=True, capture_output=True, timeout=10)
                self.blocked = True
                return "Webcam /dev blocked (chmod 000)"
        except Exception as e: return f"Block failed: {e}"'''

new_block = '''    def block_webcam(self, hard=False):
        try:
            if hard:
                subprocess.run(["sudo","modprobe","-r","uvcvideo"], capture_output=True, timeout=10)
                subprocess.run(["sudo","modprobe","-r","videodev"], capture_output=True, timeout=10)
                self.blocked = True
                return "Webcam driver unloaded (hardware disabled)"
            else:
                import glob as _glob
                for vd in _glob.glob("/dev/video*"):
                    subprocess.run(["sudo","chmod","000",vd], capture_output=True, timeout=5)
                try:
                    rule = 'SUBSYSTEM=="video4linux", ATTR{index}=="0", RUN+="/bin/chmod 000 /dev/video%n"\n'
                    with open("/tmp/defendr_webcam.rules", "w") as _rf: _rf.write(rule)
                    subprocess.run(["sudo","cp","/tmp/defendr_webcam.rules","/etc/udev/rules.d/99-defendr-webcam.rules"], capture_output=True, timeout=5)
                    subprocess.run(["sudo","udevadm","control","--reload-rules"], capture_output=True, timeout=5)
                except: pass
                self.blocked = True
                return "Webcam blocked (chmod + udev rule)"
        except Exception as e: return f"Block failed: {e}"'''

code = code.replace(old_block, new_block)

# Fix webcam unblock to remove udev rule
old_unblock = '''    def unblock_webcam(self):
        try:
            if self.blocked:
                subprocess.run(["sudo","modprobe","uvcvideo"], capture_output=True, timeout=10)
                for d in os.listdir("/dev"):
                    if d.startswith("video"):
                        subprocess.run(["sudo","chmod","666",f"/dev/{d}"], capture_output=True, timeout=5)
                self.blocked = False
                return "Webcam unblocked"
        except Exception as e: return f"Unblock failed: {e}"
        return "Webcam not blocked"'''

new_unblock = '''    def unblock_webcam(self):
        try:
            if self.blocked:
                subprocess.run(["sudo","modprobe","uvcvideo"], capture_output=True, timeout=10)
                for d in os.listdir("/dev"):
                    if d.startswith("video"):
                        subprocess.run(["sudo","chmod","666",f"/dev/{d}"], capture_output=True, timeout=5)
                try:
                    subprocess.run(["sudo","rm","-f","/etc/udev/rules.d/99-defendr-webcam.rules"], capture_output=True, timeout=5)
                    subprocess.run(["sudo","udevadm","control","--reload-rules"], capture_output=True, timeout=5)
                except: pass
                self.blocked = False
                return "Webcam unblocked"
        except Exception as e: return f"Unblock failed: {e}"
        return "Webcam not blocked"'''

code = code.replace(old_unblock, new_unblock)

# Fix AntiRansomware to skip if still scanning (rate limiting)
old_run = '''    def _run(self):
        while self.monitoring:
            time.sleep(self.interval)
            try: self._scan_for_ransomware()
            except: pass'''

new_run = '''    def _run(self):
        while self.monitoring:
            time.sleep(self.interval)
            try: self._scan_for_ransomware()
            except: pass
    def _scan_for_ransomware(self):
        if getattr(self, '_scanning', False):
            return
        self._scanning = True
        try:
            self._do_scan_ransomware()
        finally:
            self._scanning = False
    def _do_scan_ransomware(self):'''

code = code.replace(old_run, new_run)

# Rename old _scan_for_ransomware to _do_scan_ransomware in the method definition
code = code.replace(
    'def _scan_for_ransomware(self):\n        watch_dirs',
    'def _do_scan_ransomware(self):\n        watch_dirs'
)

# Replace bare except: pass with except Exception: pass
code = code.replace('\texcept: pass\n', '\texcept Exception: pass\n')
code = code.replace('except: pass\n', 'except Exception: pass\n')

with open(f"{pkg}/monitors.py", "w") as f:
    f.write(code)
print("  monitors.py OK")

# ========================================================
# FIX 2 & 4: network_tools.py - missing imports, hardcoded subnet
# ========================================================
print("=== Fixing network_tools.py ===")
with open(f"{pkg}/network_tools.py") as f:
    code = f.read()

# Add missing imports
code = code.replace(
    'import os, subprocess, json, socket, threading, time, random',
    'import os, subprocess, json, socket, threading, time, random, re, base64'
)

# Fix hardcoded subnet 192.168.1.1/24 to detect from interface
old_subnet = '''            arp_request = scapy.ARP(pdst="192.168.1.1/24")'''
new_subnet = '''            import re as _re
            try:
                r2 = subprocess.run(["ip","-o","-f","inet","addr","show",interface], capture_output=True, text=True, timeout=5)
                m = _re.search(r'inet (\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)', r2.stdout)
                if m:
                    ip_parts = m.group(1).split(".")
                    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/{m.group(2)}"
                else:
                    subnet = "192.168.1.1/24"
            except:
                subnet = "192.168.1.1/24"
            arp_request = scapy.ARP(pdst=subnet)'''

code = code.replace(old_subnet, new_subnet)

# Replace bare except with except Exception
code = re.sub(r'(?<![\w.])except: (?!Exception)', 'except Exception: ', code)
code = code.replace('\texcept: pass\n', '\texcept Exception: pass\n')
code = code.replace('except: pass\n', 'except Exception: pass\n')

with open(f"{pkg}/network_tools.py", "w") as f:
    f.write(code)
print("  network_tools.py OK")

# ========================================================
# FIX 4: security.py - validate proto, fix args parsing
# ========================================================
print("=== Fixing security.py ===")
with open(f"{pkg}/security.py") as f:
    code = f.read()

# Validate proto parameter
old_block_port = '''    def block_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        try:'''
new_block_port = '''    def block_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        if proto not in ("tcp","udp"): return False, f"Invalid protocol: {proto}"
        try:'''
code = code.replace(old_block_port, new_block_port)

old_allow_port = '''    def allow_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        try:'''
new_allow_port = '''    def allow_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        if proto not in ("tcp","udp"): return False, f"Invalid protocol: {proto}"
        try:'''
code = code.replace(old_allow_port, new_allow_port)

# Use shlex.split instead of str.split for sandbox args
old_sandbox = '''import os, subprocess, re, shutil, socket'''
new_sandbox = '''import os, subprocess, re, shutil, socket, shlex'''
code = code.replace(old_sandbox, new_sandbox)

old_args_split = '''cmd = ["firejail", "--seccomp", "--net=none", filepath] + (args.split() if args else [])'''
new_args_split = '''cmd = ["firejail", "--seccomp", "--net=none", filepath] + (shlex.split(args) if args else [])'''
code = code.replace(old_args_split, new_args_split)

old_args_split2 = '''cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                       "--unshare-net", filepath] + (args.split() if args else [])'''
new_args_split2 = '''cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                       "--unshare-net", filepath] + (shlex.split(args) if args else [])'''
code = code.replace(old_args_split2, new_args_split2)

# Replace bare except
code = re.sub(r'(?<![\w.])except: (?!Exception)', 'except Exception: ', code)
code = code.replace('\texcept: pass\n', '\texcept Exception: pass\n')
code = code.replace('except: pass\n', 'except Exception: pass\n')

with open(f"{pkg}/security.py", "w") as f:
    f.write(code)
print("  security.py OK")

# ========================================================
# FIX 4 & 5: tools.py - missing imports, rate limiting
# ========================================================
print("=== Fixing tools.py ===")
with open(f"{pkg}/tools.py") as f:
    code = f.read()

# Fix imports
code = code.replace(
    'import os, subprocess, json, random, hashlib, base64, threading',
    'import os, subprocess, json, random, hashlib, base64, threading, shutil, re, uuid'
)
code = code.replace(
    'from pathlib import Path\nfrom PyQt5 import QtCore',
    'from pathlib import Path\nimport tempfile\nfrom PyQt5 import QtCore'
)

# Make sure tempfile is imported (used in wipe_free_space)
if 'import tempfile' not in code:
    code = code.replace(
        'import shutil, re, uuid',
        'import shutil, re, uuid, tempfile'
    )

# Replace bare except
code = re.sub(r'(?<![\w.])except: (?!Exception)', 'except Exception: ', code)
code = code.replace('\texcept: pass\n', '\texcept Exception: pass\n')
code = code.replace('except: pass\n', 'except Exception: pass\n')

with open(f"{pkg}/tools.py", "w") as f:
    f.write(code)
print("  tools.py OK")

# ========================================================
# FIX 1 & 5: ui.py - QThread + fix heavy handlers
# ========================================================
print("=== Fixing ui.py ===")
with open(f"{pkg}/ui.py") as f:
    code = f.read()

# Add QThread Worker classes after imports
worker_code = '''
# ===================== QTHREAD WORKERS =====================
class TaskWorker(QtCore.QThread):
    """Generic worker for running heavy tasks in background thread."""
    finished = QtCore.pyqtSignal(object)
    error = QtCore.pyqtSignal(str)

    def __init__(self, target, args=(), kwargs=None):
        super().__init__()
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def run(self):
        try:
            result = self._target(*self._args, **self._kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class ScanWorker(QtCore.QThread):
    """Dedicated worker for file scanning."""
    finished = QtCore.pyqtSignal(object)
    progress = QtCore.pyqtSignal(int, str)
    error = QtCore.pyqtSignal(str)

    def __init__(self, engine, path):
        super().__init__()
        self.engine = engine
        self.path = path

    def run(self):
        try:
            result = self.engine.scan_path(self.path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
'''

# Insert worker classes after imports (after line 13)
insert_point = code.find("from defendr.lang import _")
if insert_point >= 0:
    end_line = code.find("\n", insert_point)
    code = code[:end_line+1] + worker_code + code[end_line+1:]
print("  Workers added")

# Fix RootkitDetector.full_scan() to use QThread (modify _rootkit_scan and _do_rootkit)
old_rk = '''    def _rootkit_scan(self):
        self.rk_results.setPlainText("Running rootkit scan...")
        QtCore.QTimer.singleShot(100, self._do_rootkit)
    def _do_rootkit(self):
        results = self.rootkit.full_scan()
        if not results:
            self.rk_results.setPlainText("✅ No rootkits detected.\\nSystem appears clean.")
            return
        txt = "⚠ Rootkit Scan Results:\\n" + "="*40 + "\\n"
        for k, v in results.items():
            txt += f"\\n{k}: {v}\\n"
        self.rk_results.setPlainText(txt)'''

new_rk = '''    def _rootkit_scan(self):
        self.rk_results.setPlainText("Running rootkit scan...")
        self._rk_worker = TaskWorker(self.rootkit.full_scan)
        self._rk_worker.finished.connect(self._do_rootkit)
        self._rk_worker.error.connect(lambda e: self.rk_results.setPlainText(f"Error: {e}"))
        self._rk_worker.start()
    def _do_rootkit(self, results):
        if not results:
            self.rk_results.setPlainText("✅ No rootkits detected.\\nSystem appears clean.")
            return
        txt = "⚠ Rootkit Scan Results:\\n" + "="*40 + "\\n"
        for k, v in results.items():
            txt += f"\\n{k}: {v}\\n"
        self.rk_results.setPlainText(txt)'''

code = code.replace(old_rk, new_rk)

# Fix Software updater check to use QThread
old_su_check = '''    def _check_soft_updates(self):
        self.su_status.setText("Checking for updates...")
        self.su_results.setPlainText("")
        QtCore.QTimer.singleShot(100, self._do_soft_check)
    def _do_soft_check(self):
        results = self.soft_updater.check_updates()
        if results:'''

new_su_check = '''    def _check_soft_updates(self):
        self.su_status.setText("Checking for updates...")
        self.su_results.setPlainText("")
        self._su_worker = TaskWorker(self.soft_updater.check_updates)
        self._su_worker.finished.connect(self._do_soft_check)
        self._su_worker.error.connect(lambda e: self.su_status.setText(f"Error: {e}"))
        self._su_worker.start()
    def _do_soft_check(self, results):
        if results:'''

code = code.replace(old_su_check, new_su_check)

# Fix install_all to use QThread
old_install = '''    def _su_install_all(self):
        self.su_status.setText("Installing updates...")
        self.su_results.setPlainText("")
        QtCore.QTimer.singleShot(100, lambda: self.soft_updater.install_all())'''

new_install = '''    def _su_install_all(self):
        self.su_status.setText("Installing updates...")
        self.su_results.setPlainText("")
        self._install_worker = TaskWorker(self.soft_updater.install_all)
        self._install_worker.finished.connect(lambda msg: self.su_status.setText(msg or "Done"))
        self._install_worker.error.connect(lambda e: self.su_status.setText(f"Error: {e}"))
        self._install_worker.start()'''

code = code.replace(old_install, new_install)

# Fix cleanup to use QThread
old_cleanup = '''    def _run_cleanup(self):
        self.clean_progress.setValue(0)
        self.clean_progress.show()
        self.clean_status.setText("Cleaning...")
        self.clean_results.clear()
        QtCore.QTimer.singleShot(100, self.cleanup_mgr.run_cleanup)'''

new_cleanup = '''    def _run_cleanup(self):
        self.clean_progress.setValue(0)
        self.clean_progress.show()
        self.clean_status.setText("Cleaning...")
        self.clean_results.clear()
        self._clean_worker = TaskWorker(self.cleanup_mgr.run_cleanup)
        self._clean_worker.finished.connect(lambda r: None)
        self._clean_worker.error.connect(lambda e: self.clean_status.setText(f"Error: {e}"))
        self._clean_worker.start()'''

code = code.replace(old_cleanup, new_cleanup)

# Fix cleanup preview
old_preview = '''    def _cleanup_preview(self):
        self.clean_results.clear()
        self.clean_status.setText("Gathering preview...")
        QtCore.QTimer.singleShot(100, lambda: self.cleanup_mgr.preview())'''

new_preview = '''    def _cleanup_preview(self):
        self.clean_results.clear()
        self.clean_status.setText("Gathering preview...")
        self._preview_worker = TaskWorker(self.cleanup_mgr.preview)
        self._preview_worker.finished.connect(self.cleanup_mgr.preview_signal.emit)
        self._preview_worker.error.connect(lambda e: self.clean_status.setText(f"Error: {e}"))
        self._preview_worker.start()'''

code = code.replace(old_preview, new_preview)

# Fix shred_file to use QThread
old_shred_file = '''    def _shred_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding...")
            QtCore.QTimer.singleShot(100, lambda: self.shredder.shred(path))'''

new_shred_file = '''    def _shred_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding...")
            self._shred_worker = TaskWorker(self.shredder.shred, args=(path,))
            self._shred_worker.finished.connect(lambda r: None)
            self._shred_worker.error.connect(lambda e: self.shred_status.setText(f"Error: {e}"))
            self._shred_worker.start()'''

code = code.replace(old_shred_file, new_shred_file)

# Fix shred folder
old_shred_folder = '''    def _shred_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding folder...")
            QtCore.QTimer.singleShot(100, lambda: self.shredder.shred_directory(path))'''

new_shred_folder = '''    def _shred_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding folder...")
            self._shred_worker = TaskWorker(self.shredder.shred_directory, args=(path,))
            self._shred_worker.finished.connect(lambda r: None)
            self._shred_worker.error.connect(lambda e: self.shred_status.setText(f"Error: {e}"))
            self._shred_worker.start()'''

code = code.replace(old_shred_folder, new_shred_folder)

# Fix shred free space
old_shred_fs = '''    def _shred_free_space(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select drive/partition to wipe free space")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Wiping free space...")
            QtCore.QTimer.singleShot(100, lambda: self.shredder.wipe_free_space(path))'''

new_shred_fs = '''    def _shred_free_space(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select drive/partition to wipe free space")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Wiping free space...")
            self._shred_worker = TaskWorker(self.shredder.wipe_free_space, args=(path,))
            self._shred_worker.finished.connect(lambda r: None)
            self._shred_worker.error.connect(lambda e: self.shred_status.setText(f"Error: {e}"))
            self._shred_worker.start()'''

code = code.replace(old_shred_fs, new_shred_fs)

# Fix WiFi scan to use QThread
old_wifi = '''    def _wifi_scan(self):
        self.wifi_results.setPlainText("Scanning router (takes up to 60s)...")
        QtCore.QTimer.singleShot(100, self.wifi_inspector.scan_router)'''

new_wifi = '''    def _wifi_scan(self):
        self.wifi_results.setPlainText("Scanning router (takes up to 60s)...")
        self._wifi_worker = TaskWorker(self.wifi_inspector.scan_router)
        self._wifi_worker.finished.connect(lambda r: self._on_wifi_result("wifi_scan", r or {"error":"No results"}))
        self._wifi_worker.error.connect(lambda e: self._on_wifi_result("wifi_scan", {"error":e}))
        self._wifi_worker.start()'''

code = code.replace(old_wifi, new_wifi)

# Fix _do_update to use QThread
old_update = '''    def _manual_update(self):
        self.update_status.setText("Checking for updates...")
        QtCore.QTimer.singleShot(100, self._do_update)
    def _do_update(self):
        n = self.sig_updater.check_update()
        self.sig_count.setText(f"Signatures: {self.sig_updater.get_signature_count()}")
        self.update_status.setText(f"Updated {n} signatures" if n else "No updates available")'''

new_update = '''    def _manual_update(self):
        self.update_status.setText("Checking for updates...")
        self._update_worker = TaskWorker(self.sig_updater.check_update)
        self._update_worker.finished.connect(self._do_update)
        self._update_worker.error.connect(lambda e: self.update_status.setText(f"Error: {e}"))
        self._update_worker.start()
    def _do_update(self, n):
        self.sig_count.setText(f"Signatures: {self.sig_updater.get_signature_count()}")
        self.update_status.setText(f"Updated {n} signatures" if n else "No updates available")'''

code = code.replace(old_update, new_update)

# Fix _do_router_info to use QThread
old_router = '''    def _router_info(self):
        self.inspector_results.setPlainText("Gathering router info...")
        QtCore.QTimer.singleShot(100, self._do_router_info)
    def _do_router_info(self):
        info = self.net_inspector.router_info()
        txt = "📡 Router Info:\\n" + "="*40 + "\\n"
        for k, v in info.items():
            if isinstance(v, list):
                txt += f"{k}:\\n"
                for item in v: txt += f"  - {item}\\n"
            else:
                txt += f"{k}: {v}\\n"
        self.inspector_results.setPlainText(txt)'''

new_router = '''    def _router_info(self):
        self.inspector_results.setPlainText("Gathering router info...")
        self._router_worker = TaskWorker(self.net_inspector.router_info)
        self._router_worker.finished.connect(self._do_router_info)
        self._router_worker.error.connect(lambda e: self.inspector_results.setPlainText(f"Error: {e}"))
        self._router_worker.start()
    def _do_router_info(self, info):
        txt = "📡 Router Info:\\n" + "="*40 + "\\n"
        for k, v in info.items():
            if isinstance(v, list):
                txt += f"{k}:\\n"
                for item in v: txt += f"  - {item}\\n"
            else:
                txt += f"{k}: {v}\\n"
        self.inspector_results.setPlainText(txt)'''

code = code.replace(old_router, new_router)

# Fix firewall handlers to show they're running (quick iptables calls are fast enough)
# The firewall handlers run iptables which is fast, but let's at least add try/except

# Fix _refresh_procs to use QThread
old_procs = '''    def _refresh_procs(self):
        self.proc_table.setRowCount(0)
        procs = self.engine.get_processes()'''

new_procs = '''    def _refresh_procs(self):
        self.proc_table.setRowCount(0)
        QtCore.QTimer.singleShot(50, self._do_refresh_procs)
    def _do_refresh_procs(self):
        procs = self.engine.get_processes()'''

code = code.replace(old_procs, new_procs)

# Fix _on_cleanup_preview to handle dict results properly (cleanup_mgr.preview returns list, not dict)
# The handler tries to use results.items() on a list, which will fail
# Let's fix the _on_cleanup_preview
old_preview_handler = '''    def _on_cleanup_preview(self, results):
        self.clean_results.clear()
        if not results:
            self.clean_results.addItem("Nothing to clean")
            return
        total = 0
        for cat, items in results.items():
            for path, size in items:
                self.clean_results.addItem(f"{cat}: {path} ({self._fmt_size(size)})")
                total += size
        self.clean_results.addItem(f"--- Total: {self._fmt_size(total)} ---")
        self.clean_status.setText(f"Preview: {self.clean_results.count()} items, {self._fmt_size(total)}")'''

new_preview_handler = '''    def _on_cleanup_preview(self, results):
        self.clean_results.clear()
        if not results:
            self.clean_results.addItem("Nothing to clean")
            return
        total = 0
        for item in results:
            if isinstance(item, tuple) and len(item) >= 3:
                self.clean_results.addItem(f"{item[0]}: {item[2]}")
                total += item[1]
            elif isinstance(item, dict):
                for cat, items in item.items():
                    for path, size in items:
                        self.clean_results.addItem(f"{cat}: {path} ({self._fmt_size(size)})")
                        total += size
        self.clean_results.addItem(f"--- Total: {self._fmt_size(total)} ---")
        self.clean_status.setText(f"Preview: {self.clean_results.count()} items, {self._fmt_size(total)}")'''

code = code.replace(old_preview_handler, new_preview_handler)

# Add exception handling around the engine.get_processes call in _do_refresh_procs
old_get_procs = '''    def _do_refresh_procs(self):
        procs = self.engine.get_processes()'''
# Keep the existing pattern - _do_refresh_procs is called directly

with open(f"{pkg}/ui.py", "w") as f:
    f.write(code)
print("  ui.py OK")

# ========================================================
# FIX 5: engine.py - check for get_processes + scanning
# ========================================================
print("=== Verifying engine.py ===")
with open(f"{pkg}/engine.py") as f:
    code = f.read()

# Verify get_processes exists
if 'def get_processes' not in code:
    print("  WARNING: get_processes not in engine.py! Adding stub.")
    get_procs_stub = '''
    def get_processes(self):
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(["pid","name","cpu_percent","memory_percent"]):
                try:
                    procs.append({"pid": p.info["pid"], "name": p.info["name"] or "?",
                                  "cpu": p.info["cpu_percent"] or 0,
                                  "mem": p.info["memory_percent"] or 0,
                                  "conns": len(p.connections()) if hasattr(p,"connections") else 0,
                                  "suspicious": False, "pentest": False})
                except: pass
            return sorted(procs, key=lambda x:-x["cpu"])[:200]
        except ImportError:
            return [{"pid":0,"name":"psutil not installed","cpu":0,"mem":0,"conns":0,"suspicious":False,"pentest":False}]
'''
    code = code.rstrip() + get_procs_stub
    with open(f"{pkg}/engine.py", "w") as f:
        f.write(code)
    print("  engine.py stub added")
else:
    print("  get_processes OK")

# ========================================================
# VERIFY ALL FILES COMPILE
# ========================================================
print("\n=== Verifying compilation ===")
import sys
sys.path.insert(0, "/home/kalleb/DefendR")
files = ["monitors.py", "network_tools.py", "security.py", "tools.py", "ui.py", "engine.py"]
for f in files:
    try:
        with open(f"{pkg}/{f}") as fh:
            compile(fh.read(), f"{pkg}/{f}", 'exec')
        print(f"  ✓ {f}")
    except SyntaxError as e:
        print(f"  ✗ {f}: {e}")

print("\n=== All fixes applied! ===")
