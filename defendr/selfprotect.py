import os, sys, time, threading, subprocess, atexit
from pathlib import Path

from PyQt5 import QtCore

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECK_INTERVAL = 30
PID_FILE = os.path.join(BASE, ".defendr_pid")


class SelfProtection(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self, main_pid):
        super().__init__()
        self.main_pid = main_pid
        self.running = False
        self._thread = None
        self._watchdogs = []

    def start(self):
        if self.running:
            return
        self.running = True
        try:
            p = Path(os.path.join(BASE, ".defendr_stop"))
            if p.exists():
                p.unlink()
        except Exception:
            pass
        Path(PID_FILE).write_text(str(os.getpid()))
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._launch_watchdog()

    def stop(self):
        self.running = False
        try:
            Path(os.path.join(BASE, ".defendr_stop")).touch()
        except Exception:
            pass
        try:
            Path(PID_FILE).unlink()
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=3)
        for proc in self._watchdogs:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass
        self._watchdogs.clear()

    def _run(self):
        while self.running:
            time.sleep(CHECK_INTERVAL)
            try:
                self._check_debug()
                self._check_proc_hiding()
            except Exception:
                pass

    def _check_debug(self):
        pass

    def _check_proc_hiding(self):
        pass

    @staticmethod
    def _watchdog_script():
        try:
            py = repr(sys.executable)
            code = (
                "import os,sys,time,subprocess\n"
                f"base={repr(BASE)}\n"
                f"stop_flag={repr(os.path.join(BASE, '.defendr_stop'))}\n"
                f"pid_file={repr(PID_FILE)}\n"
                f"pyexe={py}\n"
                "def read_pid():\n"
                "  try:\n"
                "    with open(pid_file) as f:\n"
                "      return int(f.read().strip())\n"
                "  except: return None\n"
                "while True:\n"
                "  if os.path.exists(stop_flag):\n"
                "    try: os.remove(stop_flag)\n"
                "    except: pass\n"
                "    break\n"
                "  pid = read_pid()\n"
                "  if pid is None:\n"
                "    break\n"
                "  try:\n"
                "    os.kill(pid,0)\n"
                "  except OSError:\n"
                "    if not os.path.exists(stop_flag):\n"
                "      p = subprocess.Popen([pyexe,'defendr.py'],cwd=base,\n"
                "        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "      with open(pid_file,'w') as f: f.write(str(p.pid))\n"
                "    break\n"
                "  time.sleep(8)\n"
            )
            return code
        except Exception:
            return None

    def _launch_watchdog(self):
        try:
            code = self._watchdog_script()
            if not code:
                return
            proc = subprocess.Popen(
                [sys.executable, "-c", code],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._watchdogs.append(proc)
        except Exception:
            pass
