import os, sys, hashlib, time, threading, subprocess
from pathlib import Path

from PyQt5 import QtCore

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHED_EXTS = {".py", ".png", ".wav", ".svg"}
CHECK_INTERVAL = 30


class SelfProtection(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self, main_pid):
        super().__init__()
        self.main_pid = main_pid
        self.running = False
        self._thread = None
        self._baseline = {}
        self._compute_baseline()

    def _compute_baseline(self):
        base = Path(BASE)
        for f in sorted(base.rglob("*")):
            if f.suffix in WATCHED_EXTS and f.is_file():
                rel = str(f.relative_to(base))
                self._baseline[rel] = self._hash_file(f)

    def _hash_file(self, path):
        try:
            h = hashlib.sha256()
            with open(str(path), "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._launch_watchdog()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self):
        while self.running:
            time.sleep(CHECK_INTERVAL)
            try:
                self._check_integrity()
                self._check_debug()
                self._check_proc_hiding()
            except Exception:
                pass

    def _check_integrity(self):
        changed = []
        base = Path(BASE)
        for relpath, old_hash in list(self._baseline.items()):
            abspath = base / relpath
            if not abspath.exists():
                changed.append(f"DEL {relpath}")
                continue
            new_hash = self._hash_file(abspath)
            if new_hash != old_hash:
                changed.append(f"MOD {relpath}")
        for f in sorted(base.rglob("*")):
            if f.suffix in WATCHED_EXTS and f.is_file():
                rel = str(f.relative_to(base))
                if rel not in self._baseline:
                    changed.append(f"NEW {rel}")
        if changed:
            self.alert_signal.emit("CRITICAL",
                f"DefendR violado: {'; '.join(changed[:5])}")

    def _check_debug(self):
        try:
            with open(f"/proc/{self.main_pid}/status") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        t = line.split(":")[1].strip()
                        if t != "0":
                            self.alert_signal.emit("HIGH",
                                f"DefendR sendo debugado! PID: {t}")
        except Exception:
            pass

    def _check_proc_hiding(self):
        try:
            procs = set()
            for p in os.listdir("/proc"):
                if p.isdigit():
                    procs.add(int(p))
            import psutil
            hidden = procs - set(psutil.pids())
            if hidden:
                self.alert_signal.emit("CRITICAL",
                    f"Rootkit: {len(hidden)} processos escondidos!")
        except Exception:
            pass

    def _launch_watchdog(self):
        try:
            py = repr(sys.executable)
            code = (
                "import os,sys,time,subprocess\n"
                f"pid={self.main_pid}\n"
                f"base={repr(BASE)}\n"
                f"pyexe={py}\n"
                "while True:\n"
                "  try:\n"
                "    os.kill(pid,0)\n"
                "  except OSError:\n"
                "    p=subprocess.Popen([pyexe,'defendr.py'],cwd=base,\n"
                "      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "    break\n"
                "  time.sleep(8)\n"
            )
            subprocess.Popen(
                [sys.executable, "-c", code],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
