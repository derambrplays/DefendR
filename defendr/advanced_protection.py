import os, sys, time, threading, subprocess, re, shlex, shutil
from pathlib import Path

from PyQt5 import QtCore

BWRAP = shutil.which("bwrap")
FIREJAIL = shutil.which("firejail")


class ProcessSandbox(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self._sandbox_tool = None
        self._detect_sandbox()

    def _detect_sandbox(self):
        if FIREJAIL:
            self._sandbox_tool = ("firejail", "--private", "--net=none")
        elif BWRAP:
            self._sandbox_tool = (
                "bwrap", "--ro-bind", "/", "/",
                "--tmpfs", "/home", "--tmpfs", "/tmp",
                "--proc", "/proc", "--dev", "/dev",
                "--unshare-net", "--unshare-ipc", "--unshare-pid",
            )

    def is_available(self):
        return self._sandbox_tool is not None

    def run_sandboxed(self, filepath, args=""):
        if not self._sandbox_tool or not os.path.isfile(filepath):
            return False, "Sandbox ou arquivo invalido"

        basename = os.path.basename(filepath)
        ext = os.path.splitext(basename)[1].lower()
        interpreters = {
            ".exe": [], ".bin": [], ".elf": [],
            ".sh": ["/bin/bash"], ".py": [sys.executable],
            ".pl": ["/usr/bin/perl"], ".rb": ["/usr/bin/ruby"],
            ".php": ["/usr/bin/php"], ".js": ["/usr/bin/node"],
        }
        cmd = list(self._sandbox_tool)
        runner = interpreters.get(ext, [])
        if runner:
            cmd += runner
        cmd += [os.path.abspath(filepath)] + shlex.split(args)

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            proc.wait(timeout=15)
            return True, f"Executado em sandbox: {basename}"
        except subprocess.TimeoutExpired:
            proc.kill()
            return True, f"Sandbox timeout (15s): {basename}"
        except Exception as e:
            return False, f"Erro sandbox: {str(e)[:60]}"


class AntiExploit(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.running = False
        self._thread = None
        self._known_exploit_indicators = {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "LD_DEBUG", "LD_ORIGIN_PATH",
        }

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self):
        while self.running:
            try:
                self._check_env_injection()
                self._check_ptrace()
                self._check_aslr()
                time.sleep(10)
            except Exception:
                pass

    def _check_env_injection(self):
        pid = os.getpid()
        try:
            with open(f"/proc/{pid}/environ") as f:
                env = f.read().split("\0")
            for key in self._known_exploit_indicators:
                for e in env:
                    if e.startswith(key + "=") and not e.startswith(f"{key}="):
                        self.alert_signal.emit("HIGH",
                            f"Possivel exploit: {key} injetado no environment")
        except Exception:
            pass

    def _check_ptrace(self):
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope") as f:
                scope = f.read().strip()
            if scope == "0":
                self.alert_signal.emit("LOW",
                    "ptrace_scope=0: qualquer processo pode depurar outros")
        except Exception:
            pass

    def _check_aslr(self):
        try:
            with open("/proc/sys/kernel/randomize_va_space") as f:
                val = f.read().strip()
            if val == "0":
                self.alert_signal.emit("HIGH",
                    "ASLR desabilitado! Sistema vulneravel a exploit")
            elif val == "1":
                self.alert_signal.emit("LOW",
                    "ASLR parcial (1). Recomendado: 2 (full)")
        except Exception:
            pass

    def check_ptrace_attach(self, pid):
        """Verifica se um processo esta sendo tracado (debugado)"""
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer = line.split(":")[1].strip()
                        if tracer != "0":
                            return int(tracer)
        except Exception:
            pass
        return None


class MemoryScanner(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.running = False
        self._thread = None
        self._shellcode_patterns = self._compile_patterns()

    def _compile_patterns(self):
        patterns = {
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80": "execve /bin/sh (32-bit)",
            b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x70\x73\x56\x53\x54\x5f\x6a\x3b\x58\x0f\x05": "execve /bin/ps (64-bit)",
            b"\x31\xc0\xb0\x01\xcd\x80": "exit() shellcode",
            b"\xff\xe4": "jmp esp",
            b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80": "execve /bin/sh via jmp",
            b"\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68": "execve /bin/sh 32-bit",
        }
        # Build regex-like patterns for common NOP sled + shellcode
        return patterns

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self):
        while self.running:
            try:
                self._scan_processes()
                time.sleep(15)
            except Exception:
                pass

    def _scan_processes(self):
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "memory_maps"]):
                try:
                    pid = proc.info["pid"]
                    name = proc.info["name"]
                    if not name:
                        continue
                    self._scan_process_memory(pid, name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _scan_process_memory(self, pid, name):
        """Scan process memory for shellcode signatures"""
        try:
            target = f"/proc/{pid}/mem"
            if not os.path.exists(target):
                return

            maps_path = f"/proc/{pid}/maps"
            if not os.path.exists(maps_path):
                return

            with open(maps_path) as f:
                maps = f.read()

            for line in maps.split("\n"):
                if "rw-p" not in line and "rwxp" not in line:
                    continue
                if "[heap]" not in line and "[stack]" not in line and "rw" not in line:
                    continue

                parts = line.split()
                if not parts:
                    continue
                addrs = parts[0].split("-")
                if len(addrs) != 2:
                    continue
                try:
                    start = int(addrs[0], 16)
                    end = int(addrs[1], 16)
                except ValueError:
                    continue

                size = end - start
                if size > 1024 * 1024:
                    continue

                try:
                    with open(f"/proc/{pid}/mem", "rb") as mem:
                        mem.seek(start)
                        data = mem.read(min(size, 4096))
                        for sig, desc in self._shellcode_patterns.items():
                            if sig in data:
                                self.alert_signal.emit("HIGH",
                                    f"Shellcode detectado em {name}({pid}): {desc}")
                except Exception:
                    pass
        except Exception:
            pass


class BehavioralProtection(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.running = False
        self._thread = None
        self._prev_procs = set()
        self._fork_bomb_counter = {}
        self._process_births = {}

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self):
        while self.running:
            try:
                self._check_new_processes()
                self._check_fork_bomb()
                self._check_suspicious_procs()
                time.sleep(3)
            except Exception:
                pass

    def _check_new_processes(self):
        now = time.time()
        try:
            import psutil
            current = set(psutil.pids())
            new = current - self._prev_procs
            for pid in new:
                try:
                    p = psutil.Process(pid)
                    ppid = p.ppid()
                    name = p.name() or "?"
                    # Track rapid process births per parent
                    if ppid not in self._process_births:
                        self._process_births[ppid] = []
                    self._process_births[ppid].append(now)
                    # Clean old entries
                    self._process_births[ppid] = [t for t in self._process_births[ppid]
                                                    if now - t < 5]
                    # Check for rapid fork
                    suspicious_names = {
                        "python3", "perl", "bash", "sh", "nc", "ncat",
                        "nmap", "masscan", "hydra", "medusa",
                    }
                    if name in suspicious_names and len(self._process_births[ppid]) > 5:
                        parent = "?"
                        try:
                            parent = psutil.Process(ppid).name()
                        except Exception:
                            pass
                        self.alert_signal.emit("MEDIUM",
                            f"Processo suspeito: {name}({pid}) forked por {parent}({ppid}) "
                            f"{len(self._process_births[ppid])}x em 5s")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            self._prev_procs = current
        except Exception:
            pass

    def _check_fork_bomb(self):
        now = time.time()
        try:
            total = len(self._prev_procs) if self._prev_procs else 0
            if total < 10:
                return
            if total > 500 and total > self._fork_bomb_counter.get("last", 0) + 100:
                self._fork_bomb_counter["last"] = total
                self.alert_signal.emit("HIGH",
                    f"Possivel fork bomb: {total} processos rodando!")
        except Exception:
            pass

    def _check_suspicious_procs(self):
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "cmdline", "connections"]):
                try:
                    name = proc.info["name"] or ""
                    cmdline = " ".join(proc.info["cmdline"] or []) if proc.info["cmdline"] else ""
                    conns = proc.info["connections"] or []

                    # Detect reverse shell indicators
                    if conns and any(c.raddr for c in conns):
                        for c in conns:
                            if not c.raddr:
                                continue
                            ip = c.raddr.ip
                            port = c.raddr.port
                            # External connection from suspicious process
                            if ip not in ("127.0.0.1", "::1") and name in (
                                "nc", "ncat", "bash", "sh", "python3", "perl",
                            ):
                                if port not in (80, 443, 53):
                                    self.alert_signal.emit("HIGH",
                                        f"Possible reverse shell: {name}({proc.pid}) -> {ip}:{port}")
                                    break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass


class AdvancedProtection(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.sandbox = ProcessSandbox()
        self.anti_exploit = AntiExploit()
        self.memory_scanner = MemoryScanner()
        self.behavioral = BehavioralProtection()

        self.sandbox.alert_signal.connect(self._relay)
        self.anti_exploit.alert_signal.connect(self._relay)
        self.memory_scanner.alert_signal.connect(self._relay)
        self.behavioral.alert_signal.connect(self._relay)

    def _relay(self, severity, msg):
        self.alert_signal.emit(severity, msg)

    def start(self):
        self.anti_exploit.start()
        self.memory_scanner.start()
        self.behavioral.start()

    def stop(self):
        self.anti_exploit.stop()
        self.memory_scanner.stop()
        self.behavioral.stop()

    def run_sandboxed(self, filepath, args=""):
        return self.sandbox.run_sandboxed(filepath, args)

    def sandbox_available(self):
        return self.sandbox.is_available()
