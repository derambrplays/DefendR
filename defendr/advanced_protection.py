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
            b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80": "execve /bin/sh via jmp",
            b"\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68": "execve /bin/sh 32-bit",
            b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x70\x73\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05": "execve /bin/ps 64-bit",
            b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5": "Meterpreter shellcode",
        }
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
                time.sleep(120)
            except Exception:
                pass

    def _scan_processes(self):
        try:
            import psutil
            suspicious_names = {"nc", "ncat", "bash", "sh", "python3", "perl",
                                "ruby", "nmap", "masscan", "hydra", "medusa",
                                "msfconsole", "meterpreter", "cobaltstrike"}
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid = proc.info["pid"]
                    name = proc.info["name"]
                    if not name or name not in suspicious_names:
                        continue
                    self._scan_process_memory(pid, name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    def _scan_process_memory(self, pid, name):
        """Scan process memory for shellcode signatures"""
        try:
            maps_path = f"/proc/{pid}/maps"
            if not os.path.exists(maps_path):
                return

            with open(maps_path) as f:
                maps = f.read()

            for line in maps.split("\n"):
                if "rw-p" not in line and "rwxp" not in line:
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
                time.sleep(15)
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
            sus_names = {"nc", "ncat", "bash", "sh", "python3", "perl",
                         "ruby", "php", "nmap", "masscan", "hydra", "medusa"}
            for proc in psutil.process_iter(["pid", "name", "connections"]):
                try:
                    name = proc.info["name"] or ""
                    if name not in sus_names:
                        continue
                    conns = proc.info["connections"] or []
                    for c in conns:
                        if not c.raddr:
                            continue
                        ip = c.raddr.ip
                        port = c.raddr.port
                        if ip not in ("127.0.0.1", "::1") and port not in (80, 443, 53):
                            self.alert_signal.emit("HIGH",
                                f"Possivel reverse shell: {name}({proc.pid}) -> {ip}:{port}")
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass


class DosDetector(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.running = False
        self._thread = None
        self._conn_tracker = {}
        self._ddos_tracker = {}
        self._prev_rx = {}
        self._prev_ts = time.time()

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
                self._check_syn_flood()
                self._check_conn_flood()
                self._check_ddos()
                self._check_bandwidth()
                time.sleep(15)
            except Exception:
                pass

    def _parse_tcp_states(self):
        """Parse /proc/net/tcp and tcp6 returning connections by state and IP"""
        result = {"syn_recv": {}, "estab": {}, "all": {}}
        for proc_path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(proc_path) as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) < 4:
                            continue
                        local = parts[1]
                        remote = parts[2]
                        state = int(parts[3], 16)
                        # TCP states: 0A=SYN_RECV, 01=ESTABLISHED
                        # Extract IP from remote addr (format: 0100007F:0035)
                        ip_port = remote.split(":")
                        if len(ip_port) != 2:
                            continue
                        ip_hex = ip_port[0]
                        ip = self._hex_to_ip(ip_hex)
                        if not ip:
                            continue
                        if state == 0x0A:
                            result["syn_recv"][ip] = result["syn_recv"].get(ip, 0) + 1
                        elif state == 0x01:
                            result["estab"][ip] = result["estab"].get(ip, 0) + 1
                        result["all"][ip] = result["all"].get(ip, 0) + 1
            except Exception:
                pass
        return result

    def _hex_to_ip(self, hex_ip):
        """Convert hex IP like 0100007F to dotted decimal"""
        try:
            if len(hex_ip) == 8:
                # IPv4: 0100007F -> 127.0.0.1 (little-endian)
                parts = []
                for i in range(0, 8, 2):
                    parts.append(str(int(hex_ip[i:i+2], 16)))
                return ".".join(reversed(parts))
            elif len(hex_ip) == 32:
                # IPv6
                parts = []
                for i in range(0, 32, 8):
                    p = hex_ip[i:i+8]
                    parts.append(p[0:4] + ":" + p[4:8])
                return ":".join(parts)
        except Exception:
            pass
        return None

    def _check_syn_flood(self):
        """Detect SYN flood by checking SYN_RECV connections"""
        states = self._parse_tcp_states()
        syn_recv = states.get("syn_recv", {})
        total_syn = sum(syn_recv.values())

        if total_syn > 50:
            top_ip = max(syn_recv, key=syn_recv.get)
            self.alert_signal.emit("HIGH",
                f"SYN Flood detectado! {total_syn} conexoes SYN_RECV, "
                f"maior origem: {top_ip} ({syn_recv[top_ip]} conexoes)")

        # Check per-IP SYN flood
        for ip, count in syn_recv.items():
            if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                continue
            if count > 20:
                self.alert_signal.emit("HIGH",
                    f"SYN Flood de IP {ip}: {count} conexoes SYN_RECV")

    def _check_conn_flood(self):
        """Detect connection flood from single IP"""
        now = time.time()
        states = self._parse_tcp_states()
        total_conns = states.get("all", {})

        for ip, count in total_conns.items():
            if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                continue
            if ip not in self._conn_tracker:
                self._conn_tracker[ip] = []
            self._conn_tracker[ip].append((now, count))

            # Keep last 10 seconds
            self._conn_tracker[ip] = [
                (t, c) for t, c in self._conn_tracker[ip] if now - t < 10
            ]

            if len(self._conn_tracker[ip]) < 3:
                continue

            avg = sum(c for _, c in self._conn_tracker[ip]) / len(self._conn_tracker[ip])
            if avg > 80:
                self.alert_signal.emit("HIGH",
                    f"DoS detectado! IP {ip} com media de {avg:.0f} conexoes "
                    f"nos ultimos 10s")
                self._conn_tracker[ip] = []

    def _check_ddos(self):
        """Detect DDoS by checking many IPs hitting same port"""
        now = time.time()
        states = self._parse_tcp_states()
        total_conns = states.get("all", {})
        external = {ip: c for ip, c in total_conns.items()
                    if ip not in ("127.0.0.1", "::1", "0.0.0.0", "")}

        # Also check iptables for packet drop rates
        syn_drop = self._get_iptables_syn_drop()

        if syn_drop > 200:
            self.alert_signal.emit("HIGH",
                f"DDoS suspeito! {syn_drop} pacotes SYN descartados/minuto "
                f"({len(external)} IPs externos ativos)")

        if len(external) > 30 and sum(external.values()) > 150:
            top = sorted(external.items(), key=lambda x: -x[1])[:5]
            top_str = ", ".join(f"{ip}({c})" for ip, c in top)
            self.alert_signal.emit("HIGH",
                f"DDoS detectado! {len(external)} IPs diferentes, "
                f"total {sum(external.values())} conexoes. Top: {top_str}")
            return

        if len(external) > 15 and sum(external.values()) > 80:
            self.alert_signal.emit("MEDIUM",
                f"Possivel DDoS: {len(external)} IPs distintos, "
                f"{sum(external.values())} conexoes no total")

    def _get_iptables_syn_drop(self):
        """Get SYN packet drop rate via iptables counters"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n", "-v", "-x"],
                capture_output=True, text=True, timeout=5,
            )
            total_drops = 0
            for line in result.stdout.split("\n"):
                if "DROP" in line and "tcp" in line and "spt:" in line:
                    parts = line.split()
                    if parts[0].isdigit():
                        total_drops += int(parts[0])
            return total_drops
        except Exception:
            return 0

    def _check_bandwidth(self):
        """Monitor bandwidth usage via /proc/net/dev"""
        try:
            with open("/proc/net/dev") as f:
                lines = f.readlines()
            now = time.time()
            dt = now - self._prev_ts
            if dt < 1:
                return

            total_rx = 0
            for line in lines[2:]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                iface = parts[0].rstrip(":")
                if iface == "lo":
                    continue
                rx_bytes = int(parts[1])
                total_rx += rx_bytes

            if self._prev_rx:
                prev_total = sum(self._prev_rx.values()) if isinstance(self._prev_rx, dict) else 0
                if prev_total > 0:
                    rate = (total_rx - prev_total) / dt
                    rate_kbps = rate / 1024
                    if rate_kbps > 50_000:
                        self.alert_signal.emit("HIGH",
                            f"Banda anormal! {rate_kbps/1000:.1f} Mbps de download")
                    elif rate_kbps > 10_000:
                        self.alert_signal.emit("LOW",
                            f"Banda alta: {rate_kbps/1000:.1f} Mbps")

            self._prev_rx = {"total": total_rx}
            self._prev_ts = now
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
        self.dos_detector = DosDetector()

        self.sandbox.alert_signal.connect(self._relay)
        self.anti_exploit.alert_signal.connect(self._relay)
        self.memory_scanner.alert_signal.connect(self._relay)
        self.behavioral.alert_signal.connect(self._relay)
        self.dos_detector.alert_signal.connect(self._relay)

    def _relay(self, severity, msg):
        self.alert_signal.emit(severity, msg)

    def start(self):
        self.anti_exploit.start()
        self.memory_scanner.start()
        self.behavioral.start()
        self.dos_detector.start()

    def stop(self):
        self.anti_exploit.stop()
        self.memory_scanner.stop()
        self.behavioral.stop()
        self.dos_detector.stop()

    def run_sandboxed(self, filepath, args=""):
        return self.sandbox.run_sandboxed(filepath, args)

    def sandbox_available(self):
        return self.sandbox.is_available()
