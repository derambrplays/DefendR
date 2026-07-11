# Scheduler and signature updater
import os, json, threading, time, urllib.request, uuid
from defendr.filelock import file_lock, safe_json_read, safe_json_write
from datetime import datetime, timedelta
from PyQt5 import QtCore
from defendr.constants import CONFIG_DIR

class Scheduler(QtCore.QObject):
    scan_triggered = QtCore.pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.tasks = []
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self._check)
        self.timer.start(60000)
        self._load()
    def _load(self):
        path = os.path.join(CONFIG_DIR, "scheduler.json")
        data = safe_json_read(path)
        if data: self.tasks = data
    def _save(self):
        safe_json_write(os.path.join(CONFIG_DIR, "scheduler.json"), self.tasks)
    def add_task(self, name, path, interval_hours, scan_type="full"):
        task = {"id": uuid.uuid4().hex[:8], "name": name, "path": path,
                "interval": interval_hours, "type": scan_type,
                "last_run": None, "enabled": True}
        self.tasks.append(task)
        self._save()
        return task
    def remove_task(self, task_id):
        self.tasks = [t for t in self.tasks if t["id"] != task_id]
        self._save()
    def _check(self):
        now = datetime.now()
        for task in self.tasks:
            if not task.get("enabled"): continue
            last = task.get("last_run")
            if last is None:
                self.scan_triggered.emit(task["id"])
                task["last_run"] = now.isoformat()
                self._save()
            else:
                try:
                    last_dt = datetime.fromisoformat(last)
                    if (now - last_dt) > timedelta(hours=task["interval"]):
                        self.scan_triggered.emit(task["id"])
                        task["last_run"] = now.isoformat()
                        self._save()
                except Exception: pass

class SignatureUpdater(QtCore.QObject):
    update_signal = QtCore.pyqtSignal(str)
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.sig_file = os.path.join(CONFIG_DIR, "signatures.json")
        self._load()
    def _load(self):
        data = safe_json_read(self.sig_file)
        if data:
            self.engine.whitelist.update(data.get("whitelist", []))
    def check_update(self):
        try:
            import urllib.request
            url = "https://raw.githubusercontent.com/anomalyco/defendr-sigs/main/sigs.json"
            req = urllib.request.Request(url, headers={"User-Agent": "DefendR/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
            safe_json_write(self.sig_file, data)
            new_sigs = data.get("malware_patterns", [])
            new_whitelist = data.get("whitelist", [])
            n = 0
            for sig_bytes, desc in new_sigs:
                sig = bytes.fromhex(sig_bytes) if isinstance(sig_bytes, str) else bytes(sig_bytes)
                existing_hardcoded = {s[0] for s in self.engine.malware_patterns}
                existing_remote = {s[0] for s in self.engine._remote_patterns}
                if sig not in existing_hardcoded and sig not in existing_remote:
                    self.engine._remote_patterns.append((sig, desc))
                    n += 1
            for w in new_whitelist:
                if w not in self.engine.whitelist:
                    self.engine.whitelist.add(w)
                    n += 1
            self.update_signal.emit(f"Updated {n} signatures")
            return n
        except Exception as e:
            self.update_signal.emit(f"Update failed: {str(e)[:50]}")
            return 0
    def get_signature_count(self):
        return (len(self.engine.malware_patterns) + len(self.engine._remote_patterns)
                + len(self.engine._clamav_patterns)
                + len(self.engine.suspicious_strings) + len(self.engine.whitelist))
