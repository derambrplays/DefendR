# Monitors: network, real-time, ransomware, webcam, USB, game mode
import os, threading, time, subprocess, json
from pathlib import Path
from collections import defaultdict
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import *
from defendr.engine import DefendREngine

class NetworkMonitor(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)
    data_signal = QtCore.pyqtSignal(object)
    intrusion_signal = QtCore.pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.arp_table = {}
        self.arp_changes = {}
        self.known_dns = set()
        self.gateway_ip = None
        self._conn_history = defaultdict(lambda: {"ports": set(), "times": [], "inbound": 0})
        self._port_scan_alerted = set()
        self._suspect_connections = set()
        self.trusted_ips = {"127.0.0.1", "::1"}
        self._adb_alerted = False
        self._bruteforce_history = defaultdict(lambda: {"count": 0, "first": 0})
        self._bruteforce_alerted = set()
        self._known_devices = set()
        self._inbound_alerted = set()
        self._sensitive_ports = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
                                 5901: "VNC", 3306: "MySQL", 5432: "PostgreSQL",
                                 1433: "MSSQL", 445: "SMB", 139: "NetBIOS",
                                 389: "LDAP", 636: "LDAPS", 8443: "HTTPS-Alt",
                                 8080: "HTTP-Proxy", 21: "FTP", 111: "RPC"}
        self._monitoring_alerted = set()
        self._promisc_alerted = set()
        self._kernel_alerted = set()
        self._cpu_history = defaultdict(lambda: {"samples": [], "total_cpu": 0.0})
        self._fork_history = defaultdict(lambda: {"count": 0, "first": 0})
        self._fork_alerted = set()
        self._miner_alerted = set()
        self._fileless_alerted = set()
        self._inj_alerted = set()
    def start(self):
        if getattr(self, '_mon_thread', None) and self._mon_thread.is_alive():
            self.monitoring = False
            self._mon_thread.join(timeout=3)
        self.monitoring = True
        self._prime_dns()
        self._prime_devices()
        self._mon_thread = threading.Thread(target=self._run, daemon=True)
        self._mon_thread.start()
    def stop(self):
        self.monitoring = False
        if getattr(self, '_mon_thread', None):
            self._mon_thread.join(timeout=2)
    def _run(self):
        cycle = 0
        while self.monitoring:
            try:
                self._check_arp(); self._check_ports(); self._check_dns()
                self._check_inbound(); self._check_bruteforce()
                self._check_port_scan(); self._check_adb()
                self._check_monitoring()
                self._check_fileless_malware()
                self._check_process_injection()
                if cycle % 3 == 0:
                    self._check_cryptominer()
                if cycle % 5 == 0:
                    self._check_fork_bomb()
                cycle += 1
                time.sleep(2)
            except Exception: pass
    def _prime_dns(self):
        try:
            if not os.path.exists("/etc/resolv.conf"): return
            with open("/etc/resolv.conf") as f:
                for l in f:
                    if l.startswith("nameserver"):
                        ns = l.split()[1]
                        self.known_dns.add(ns)
        except Exception: pass
    def _prime_devices(self):
        try:
            self.gateway_ip = self._get_gateway()
            if self.gateway_ip:
                self._known_devices.add(self.gateway_ip)
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] not in ("00:00:00:00:00:00", ""):
                            self._known_devices.add(parts[0])
        except Exception:
            pass
    def _get_gateway(self):
        try:
            r = subprocess.run(["ip","route"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=3)
            for line in r.stdout.split("\n"):
                if "default" in line:
                    parts = line.split(); return parts[2]
        except Exception: pass
        return None
    def _check_arp(self):
        if not os.path.exists("/proc/net/arp"): return
        with open("/proc/net/arp") as f: lines = f.readlines()[1:]
        current = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 4: current[parts[0]] = (parts[3], parts[-1] if len(parts)>4 else "?")
        for ip,(hw,iface) in current.items():
            if hw in ("00:00:00:00:00:00", ""): continue
            if ip in ("0.0.0.0",): continue
            if ip in self.arp_table and self.arp_table[ip][0] != hw:
                if ip not in self.arp_changes: self.arp_changes[ip] = 0
                self.arp_changes[ip] += 1
                if self.arp_changes[ip] >= 2:
                    self.alert_signal.emit("MEDIUM",f"ARP SPOOF: {ip} changed MAC from {self.arp_table[ip][0]} to {hw}")
            if ip not in self._known_devices:
                self._known_devices.add(ip)
                self.alert_signal.emit("LOW", f"Novo dispositivo na rede: {ip} ({hw})")
            self.arp_table[ip] = (hw, iface)
        self.data_signal.emit({"type":"arp","data":current})
    def _check_ports(self):
        try:
            import psutil
            try: conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            for conn in conns:
                if conn.status=="LISTEN" and conn.laddr:
                    p=conn.laddr.port
                    if p in {4444,5555,6666,1337,31337,12345,54321,22222}:
                        pname="?"
                        if conn.pid:
                            try: pname=psutil.Process(conn.pid).name()
                            except Exception: pass
                        self.alert_signal.emit("MEDIUM",f"Suspicious listener on port {p} (PID {conn.pid}: {pname})")
        except Exception: pass
    def _check_dns(self):
        try:
            self.gateway_ip = self._get_gateway()
            if not os.path.exists("/etc/resolv.conf"): return
            with open("/etc/resolv.conf") as f: servers=[l.split()[1] for l in f if l.startswith("nameserver")]
            known_good={"8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","208.67.222.222","208.67.220.220","9.9.9.9","149.112.112.112"}
            for ns in servers:
                if ns in ("127.0.0.1","::1"): continue
                if ns.startswith("fe80:"): continue
                if ns in known_good: continue
                if self.gateway_ip and ns == self.gateway_ip: continue
                if ns == self.gateway_ip: continue
                if ns not in self.known_dns:
                    self.known_dns.add(ns)
                    self.alert_signal.emit("LOW",f"DNS: {ns} (not in standard whitelist)")
        except Exception: pass

    def _check_inbound(self):
        try:
            import psutil
            try: conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            for conn in conns:
                if not (conn.status == "ESTABLISHED" and conn.raddr and conn.laddr):
                    continue
                lport = conn.laddr.port
                if lport not in self._sensitive_ports:
                    continue
                service = self._sensitive_ports[lport]
                src = conn.raddr.ip
                if src in self.trusted_ips or src == self.gateway_ip:
                    continue
                key = f"{src}:{lport}"
                if key in self._inbound_alerted:
                    continue
                self._inbound_alerted.add(key)
                pname = "?"
                if conn.pid:
                    try: pname = psutil.Process(conn.pid).name()
                    except Exception: pass
                self._fire_intrusion("MEDIUM",
                    f"Conexao entrante {service}: {src} -> porta {lport} ({pname})",
                    f"{service} Inbound", src)
        except Exception:
            pass

    def _check_bruteforce(self):
        try:
            import psutil
            try: conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            now = time.time()
            seen_bf = set()
            for conn in conns:
                if not (conn.raddr and conn.status in ("SYN_SENT", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT")):
                    continue
                src = conn.raddr.ip
                if src in self.trusted_ips:
                    continue
                lport = conn.laddr.port
                if lport not in self._sensitive_ports:
                    continue
                service = self._sensitive_ports[lport]
                bf_key = f"{src}:{lport}"
                # Track unique connections to avoid double-counting across polls
                conn_id = f"{src}:{lport}:{conn.raddr.port}:{conn.pid or 0}"
                if conn_id in seen_bf:
                    continue
                seen_bf.add(conn_id)
                entry = self._bruteforce_history[bf_key]
                if entry["count"] == 0:
                    entry["first"] = now
                entry["count"] += 1
                if now - entry["first"] > 30:
                    entry["count"] = 0
                    continue
                if entry["count"] >= 8 and bf_key not in self._bruteforce_alerted:
                    self._bruteforce_alerted.add(bf_key)
                    self._fire_intrusion("HIGH",
                        f"Brute force {service} de {src}: {entry['count']} conexoes em 30s",
                        "Brute Force", src)
            stale = [k for k, v in self._bruteforce_history.items() if now - v["first"] > 30]
            for k in stale:
                del self._bruteforce_history[k]
        except Exception:
            pass

    def _check_port_scan(self):
        try:
            import psutil
            try: all_conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            now = time.time()
            # Build set of listening ports (services running on this machine)
            listeners = set()
            for conn in all_conns:
                if conn.status == "LISTEN":
                    listeners.add(conn.laddr.port)
            for conn in all_conns:
                if not (conn.raddr and conn.status in ("ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT")): continue
                # Only count connections to local listening ports (inbound)
                if conn.laddr.port not in listeners:
                    continue
                ip = conn.raddr.ip
                try:
                    from defendr.reputation import REPUTATION_PORT
                    if conn.raddr.port == REPUTATION_PORT or conn.laddr.port == REPUTATION_PORT:
                        continue
                except Exception:
                    pass
                self._conn_history[ip]["ports"].add(conn.laddr.port)
                self._conn_history[ip]["times"].append(now)
            clean = []
            for ip, data in list(self._conn_history.items()):
                data["times"] = [t for t in data["times"] if now - t < 10]
                if len(data["ports"]) >= 4 and len(data["times"]) >= 15 and ip not in self._port_scan_alerted:
                    self._port_scan_alerted.add(ip)
                    self._fire_intrusion("HIGH", f"Port scan detectado de {ip}: {len(data['ports'])} portas em 10s", "Port Scan", ip)
                if not data["times"]:
                    clean.append(ip)
            for ip in clean:
                del self._conn_history[ip]
        except Exception: pass

    def _check_adb(self):
        try:
            import psutil
            adb_pids = set()
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    name = proc.info["name"] or ""
                    cmd = " ".join(proc.info["cmdline"] or [])
                    if "adb" in name.lower() or "adb" in cmd.lower():
                        adb_pids.add(proc.info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if not adb_pids:
                return
            try: conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            for conn in conns:
                if conn.pid not in adb_pids:
                    continue
                if conn.raddr and conn.status == "ESTABLISHED":
                    local = conn.laddr.port
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                    if conn.raddr.ip == "127.0.0.1":
                        self.alert_signal.emit("MEDIUM", f"ADB tunnel: porta {local} -> {remote} (dispositivo Android acessando o PC)")
                        if not self._adb_alerted:
                            self._adb_alerted = True
                            self._fire_intrusion("MEDIUM", f"ADB reverse tunnel detectado: Android acessando 127.0.0.1:{local}", "ADB Tunnel", conn.raddr.ip)
        except Exception:
            pass

    def _check_monitoring(self):
        KNOWN_SPY = {
            "logkeys", "uberkey", "keylogger", "pykeylogger", "xkeylogger",
            "logkey", "keylog", "revealer", "keyboard-hook", "keyhook",
            "vncviewer", "screenkey", "screenlog",
            "ettercap", "driftnet", "dsniff", "arpspoof", "dnsspoof", "urlsnarf",
            "bettercap", "responder",
            "kismet", "aircrack-ng", "airmon-ng", "airodump-ng",
            "reaver", "wash", "fluxion", "wifite",
            "cellebrite", "ufed", "oxygen", "magnet", "encase",
            "fern", "burpsuite", "zap", "sqlmap",
        }
        KNOWN_FORENSIC = {
            "foremost", "scalpel", "volatility", "bulk_extractor",
            "autopsy", "sleuthkit", "tsk_recover", "dcfldd", "guymager",
            "gdb", "strace", "ltrace", "ftrace", "dtrace", "systemtap",
            "perf", "bpftrace", "radare2", "rizin", "iaito",
            "tcpdump", "wireshark", "tshark", "dumpcap",
            "nmap", "masscan", "zmap", "zenmap", "unicornscan",
            "hping3", "hping", "sniff", "pcap", "scapy",
            "evtest", "showkey", "grabber",
            "aircrack", "fern-wifi", "fluxion",
            "metasploit", "msfconsole", "msfvenom",
            "hydra", "medusa", "john", "hashcat", "ophcrack",
        }
        try:
            import psutil
            suspicious = []
            for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
                try:
                    pname = (proc.info["name"] or "").lower()
                    cmdline = " ".join(proc.info["cmdline"] or []).lower()
                    exe = (proc.info["exe"] or "").lower()

                    # Check known monitoring tool names
                    base = os.path.splitext(pname)[0]
                    if base in KNOWN_SPY:
                        suspicious.append((proc.info["pid"], pname, cmdline[:120], "spyware"))
                    elif base in KNOWN_FORENSIC:
                        suspicious.append((proc.info["pid"], pname, cmdline[:120], "forensic"))

                    # Behavioral: check for /dev/input readers (keyloggers)
                    try:
                        for fd_path in proc.open_files():
                            if "dev/input" in fd_path.path:
                                suspicious.append((proc.info["pid"], pname, f"lendo {fd_path.path}", "keylogger"))
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Behavioral: check for ptrace (TracerPid in /proc/pid/status)
                    try:
                        with open(f"/proc/{proc.info['pid']}/status") as stf:
                            for line in stf:
                                if line.startswith("TracerPid:"):
                                    tpid = line.split(":")[1].strip()
                                    if tpid and tpid != "0":
                                        suspicious.append((
                                            proc.info["pid"], pname,
                                            f"being traced by PID {tpid}",
                                            "backdoor"
                                        ))
                                    break
                    except Exception:
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            for pid, name, detail, stype in suspicious:
                key = f"mon_{pid}_{stype}"
                if key in self._monitoring_alerted:
                    continue
                self._monitoring_alerted.add(key)
                labels = {
                    "spyware": "Spyware", "forensic": "Ferramenta Forense",
                    "keylogger": "Keylogger", "backdoor": "Possivel Backdoor/C2",
                }
                severities = {"spyware": "HIGH", "forensic": "MEDIUM",
                              "keylogger": "HIGH", "backdoor": "HIGH"}
                severity = severities.get(stype, "MEDIUM")
                self.alert_signal.emit(severity,
                    f"[{labels.get(stype, stype)}] PID {pid}: {name} - {detail}")
                self._fire_intrusion(severity,
                    f"{name} ({detail})", f"Monitoring:{stype}", "localhost")

            # Check for promiscuous mode (packet sniffing)
            try:
                r = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True,
                                 encoding="utf-8", errors="surrogateescape", timeout=3)
                for line in r.stdout.splitlines():
                    if "PROMISC" in line.upper():
                        iface = line.split()[0]
                        if iface not in self._promisc_alerted:
                            self._promisc_alerted.add(iface)
                            self.alert_signal.emit("HIGH",
                                f"[Sniffer] Interface {iface} em modo promiscuo")
                            self._fire_intrusion("HIGH",
                                f"Interface {iface} em modo promiscuo", "Sniffer", "localhost")
            except Exception:
                pass

            # Check for loaded monitoring kernel modules
            try:
                r = subprocess.run(["lsmod"], capture_output=True, text=True,
                                 encoding="utf-8", errors="surrogateescape", timeout=3)
                sus_modules = {"systemtap"}
                for line in r.stdout.splitlines():
                    mod = line.split()[0].lower() if line.split() else ""
                    if mod in sus_modules:
                        if mod not in self._kernel_alerted:
                            self._kernel_alerted.add(mod)
                            self.alert_signal.emit("MEDIUM",
                                f"[Kernel] Modulo suspeito carregado: {mod}")
            except Exception:
                pass

            # Behavioral: check /proc for processes accessing /dev/mem or /dev/kmem
            try:
                r = subprocess.run(
                    ["lsof", "/dev/mem", "/dev/kmem", "/dev/port"],
                    capture_output=True, text=True, timeout=3,
                )
                for line in r.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        spid = parts[1]
                        sname = parts[0] if len(parts) > 0 else "?"
                        key = f"mem_{spid}"
                        if key not in self._monitoring_alerted:
                            self._monitoring_alerted.add(key)
                            self.alert_signal.emit("HIGH",
                                f"[Memory Access] PID {spid} ({sname}) acessando {parts[-1]}")
            except Exception:
                pass

        except Exception:
            pass

    def _check_cryptominer(self):
        try:
            import psutil
            now = time.time()
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "connections", "exe"]):
                try:
                    pid = proc.info["pid"]
                    cpu = proc.cpu_percent(interval=0)
                    name = (proc.info["name"] or "").lower()
                    exe = (proc.info["exe"] or "").lower()
                    if any(kw in name for kw in ("python3", "python", "bash", "zsh", "systemd", " snap")):
                        continue
                    if cpu < 50:
                        continue
                    hist = self._cpu_history[pid]
                    hist["samples"].append((now, cpu))
                    hist["total_cpu"] += cpu
                    hist["samples"] = [s for s in hist["samples"] if now - s[0] < 30]
                    if len(hist["samples"]) < 3:
                        continue
                    avg_cpu = sum(s[1] for s in hist["samples"]) / len(hist["samples"])
                    if avg_cpu < 60:
                        continue
                    conns = proc.connections()
                    miner_ports = {3333, 3334, 3335, 3336, 4444, 5555, 7777, 8888,
                                   14444, 33445, 42000, 42001, 42002}
                    mining_pool = False
                    for c in conns:
                        if c.raddr and c.raddr.port in miner_ports:
                            mining_pool = True
                            break
                    gpu_files = False
                    try:
                        for f in proc.open_files():
                            if "nvidia" in f.path.lower() or "dri" in f.path.lower() or "render" in f.path.lower():
                                gpu_files = True
                                break
                    except Exception:
                        pass
                    if mining_pool or gpu_files:
                        if pid not in self._miner_alerted:
                            self._miner_alerted.add(pid)
                            detail = f"CPU:{avg_cpu:.0f}%"
                            if mining_pool:
                                detail += " pool_miner"
                            if gpu_files:
                                detail += " gpu_access"
                            self.alert_signal.emit("HIGH",
                                f"[Cryptominer] PID {pid}: {name} - {detail}")
                            self._fire_intrusion("HIGH",
                                f"{name} ({detail})", "Cryptominer", "localhost")
                except Exception:
                    continue
        except Exception:
            pass

    def _check_fork_bomb(self):
        try:
            import psutil
            now = time.time()
            ppids = defaultdict(int)
            for proc in psutil.process_iter(["pid", "ppid"]):
                try:
                    ppids[proc.info["ppid"]] += 1
                except Exception:
                    continue
            for ppid, n_children in ppids.items():
                if n_children < 100:
                    continue
                try:
                    pname = psutil.Process(ppid).name()
                except Exception:
                    pname = "?"
                if pname in ("systemd", "init", "kthreadd"):
                    continue
                key = f"fork_{ppid}"
                hist = self._fork_history[ppid]
                if hist["count"] == 0:
                    hist["first"] = now
                hist["count"] += n_children
                if now - hist["first"] > 10:
                    if hist["count"] >= 100 and key not in self._fork_alerted:
                        self._fork_alerted.add(key)
                        self.alert_signal.emit("HIGH",
                            f"[Fork Bomb] PID {ppid} ({pname}) criou {hist['count']} processos em 10s")
                        self._fire_intrusion("HIGH",
                            f"PID {ppid} ({pname}) criou {hist['count']} processos", "ForkBomb", "localhost")
                    hist["count"] = 0
                    hist["first"] = now
        except Exception:
            pass

    def _check_fileless_malware(self):
        SKIP_NAMES = frozenset({
            "systemd", "systemd-userwork", "systemd-logind", "systemd-journald",
            "systemd-resolved", "systemd-timesyncd", "systemd-udevd", "systemd-networkd",
            "dnsmasq", "lightdm", "gdm", "sddm", "wdm", "lightdm-session",
            "accounts-daemon", "dbus", "dbus-daemon", "polkitd",
            "rtkit-daemon", "colord", "upowerd", "udisksd",
            "NetworkManager", "ModemManager", "cupsd", "cups-browsed",
            "avahi-daemon", "bluetoothd", "wpa_supplicant",
            "haveged", "irqbalance", "thermald",
        })
        SAFE_PATHS = frozenset({
            "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
            "/usr/lib/", "/lib/", "/lib64/", "/etc/",
        })
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    pid = proc.info["pid"]
                    name = proc.info["name"] or "?"
                    exe = proc.info.get("exe") or ""
                    cmdline = " ".join(proc.info["cmdline"] or [])
                    if name.startswith("kworker") or name.startswith("kthread"):
                        continue
                    if pid < 100 and exe == "":
                        continue
                    if exe == "" and cmdline == "":
                        continue
                    if exe and any(exe.startswith(p) for p in SAFE_PATHS):
                        continue
                    if name in SKIP_NAMES:
                        continue
                    if exe == "" or "memfd:" in exe.lower():
                        if pid not in self._fileless_alerted:
                            self._fileless_alerted.add(pid)
                            self.alert_signal.emit("HIGH",
                                f"[Fileless] PID {pid}: {name} - exe={exe} cmd={cmdline[:100]}")
                            self._fire_intrusion("HIGH",
                                f"PID {pid} ({name}) fileless: {exe}", "FilelessMalware", "localhost")
                except Exception:
                    continue
        except Exception:
            pass

    def _check_process_injection(self):
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid = proc.info["pid"]
                    for f in proc.open_files():
                        path = f.path
                        if "/proc/" in path and "/mem" in path:
                            parts = path.split("/")
                            target_pid = None
                            for i, p in enumerate(parts):
                                if p == "proc" and i + 2 < len(parts):
                                    try:
                                        tp = int(parts[i + 1])
                                        if tp != pid:
                                            target_pid = tp
                                    except ValueError:
                                        pass
                                    break
                            if target_pid is not None:
                                key = f"inj_{pid}_{target_pid}"
                                if key not in self._inj_alerted:
                                    self._inj_alerted.add(key)
                                    tname = "?"
                                    try:
                                        tname = psutil.Process(target_pid).name()
                                    except Exception:
                                        pass
                                    self.alert_signal.emit("HIGH",
                                        f"[Process Injection] PID {pid} ({proc.info['name']}) "
                                        f"escrevendo em /proc/{target_pid}/mem ({tname})")
                                    self._fire_intrusion("HIGH",
                                        f"PID {pid} injetando em PID {target_pid} ({tname})",
                                        "ProcessInjection", "localhost")
                except Exception:
                    continue
        except Exception:
            pass

    def _fire_intrusion(self, severity, msg, attack_type="", source_ip=""):
        self.alert_signal.emit(severity, f"[{attack_type}] {msg}")
        self.intrusion_signal.emit(severity, f"{msg}|{attack_type}|{source_ip}")

class RealTimeProtector(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str, str)
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.active = False
        self.observer = None
        self._debounce = {}
        self._debounce_lock = threading.Lock()
        self._scan_sem = threading.Semaphore(2)
        self._user_home = self._resolve_home()
        self.watched_dirs = self._get_watched_dirs()
        self._init_watchdog()
    @staticmethod
    def _resolve_home():
        import pwd
        try:
            uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or os.getuid())
            return pwd.getpwuid(uid).pw_dir
        except Exception:
            return os.path.expanduser("~")
    def _get_watched_dirs(self):
        home = self._user_home
        dirs = []
        for nome in ["Área de trabalho", "Desktop"]:
            d = os.path.join(home, nome)
            if os.path.isdir(d):
                dirs.append(d)
                break
        if not dirs:
            dirs.append(home)
        return dirs
    def _init_watchdog(self):
        try:
            import watchdog.observers
            import watchdog.events
            class DefendRHandler(watchdog.events.FileSystemEventHandler):
                def __init__(self, parent):
                    super().__init__()
                    self.parent = parent
                def on_created(self, event):
                    if not self.parent.active or event.is_directory: return
                    self.parent._check_file(event.src_path)
                def on_modified(self, event):
                    if not self.parent.active or event.is_directory: return
                    self.parent._check_file(event.src_path)
                def on_moved(self, event):
                    if not self.parent.active: return
                    if not event.is_directory:
                        self.parent._check_file(event.dest_path)
            self.handler_class = DefendRHandler
            self.watchdog_available = True
        except ImportError:
            self.watchdog_available = False
    def _should_skip(self, path):
        if not os.path.isfile(path):
            return True
        ext = os.path.splitext(path)[1].lower()
        skip_exts = {".log", ".tmp", ".temp", ".lnk", ".part", ".crdownload"}
        if ext in skip_exts:
            return True
        try:
            sz = os.path.getsize(path)
            if sz > 50 * 1024 * 1024 or sz == 0:
                return True
        except OSError:
            return True
        now = time.time()
        with self._debounce_lock:
            last = self._debounce.get(path, 0)
            if now - last < 2.0:
                return True
            self._debounce[path] = now
        return False
    def start(self):
        self.active = True
        if self.watchdog_available:
            try:
                import watchdog.observers
                self.observer = watchdog.observers.Observer()
                for d in self.watched_dirs:
                    if os.path.isdir(d):
                        self.observer.schedule(self.handler_class(self), d, recursive=True)
                self.observer.start()
            except Exception:
                pass
        self._poll_seen = set()
        self._poll_running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()
        threading.Thread(target=self._scan_existing, daemon=True).start()
    def _poll_loop(self):
        while self._poll_running:
            time.sleep(3)
            if not self.active:
                continue
            for d in self.watched_dirs:
                if not os.path.isdir(d):
                    continue
                try:
                    for f in os.listdir(d):
                        fp = os.path.join(d, f)
                        if fp not in self._poll_seen and os.path.isfile(fp):
                            self._poll_seen.add(fp)
                            self._check_file(fp)
                except Exception:
                    pass
    def stop(self):
        self.active = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=1)
            except Exception:
                pass
            self.observer = None
        self._debounce.clear()
    def _scan_existing(self):
        time.sleep(3)
        for d in self.watched_dirs:
            if not self.active or not os.path.isdir(d):
                continue
            try:
                for root, _dirs, files in os.walk(d):
                    if not self.active:
                        return
                    for f in files:
                        if not self.active:
                            return
                        self._check_file(os.path.join(root, f))
            except Exception:
                pass
    def _check_file(self, path):
        if self._should_skip(path) or self.engine.is_pentest(path):
            return
        self._scan_sem.acquire()
        try:
            all_pats = self.engine.malware_patterns + self.engine._clamav_patterns + self.engine._remote_patterns
            result = self.engine._scan_full_file(Path(path), all_pats)
            if result and result["risk"] in ("malicious", "suspicious"):
                self.alert_signal.emit(result["risk"], path, result["reason"])
        except Exception:
            pass
        finally:
            self._scan_sem.release()
    def scan_file(self, path):
        all_pats = self.engine.malware_patterns + self.engine._clamav_patterns + self.engine._remote_patterns
        return self.engine._scan_rapido_file(Path(path), all_pats)

class AntiRansomware(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.file_snapshots = {}
        self.change_threshold = 50
        self.interval = 10
    def start(self):
        self.monitoring = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    def stop(self):
        self.monitoring = False
    def _do_scan_ransomware(self):
        watch_dirs = [os.path.expanduser("~/Documents"),
                      os.path.expanduser("~/Documentos"),
                      os.path.expanduser("~/Downloads"),
                      os.path.expanduser("~/Área de trabalho"),
                      os.path.expanduser("~/Desktop"),
                      os.path.expanduser("~/Pictures"),
                      os.path.expanduser("~/Imagens"),
                      os.path.expanduser("~/Videos"),
                      os.path.expanduser("~/Vídeos")]
        encrypted_count = 0
        new_exts = {}
        for d in watch_dirs:
            if not os.path.isdir(d): continue
            try:
                for root, dirs, files in os.walk(d):
                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext in RANSOMWARE_EXTENSIONS:
                            encrypted_count += 1
                            new_exts[ext] = new_exts.get(ext, 0) + 1
                        if encrypted_count > 100: break
                    if encrypted_count > 100: break
            except Exception: pass
        if encrypted_count >= self.change_threshold:
            exts_str = ", ".join(f"{k}({v})" for k,v in sorted(new_exts.items(), key=lambda x:-x[1])[:5])
            self.alert_signal.emit("HIGH", f"Ransomware detected! {encrypted_count} encrypted files found. Extensions: {exts_str}")
    def _run(self):
        while self.monitoring:
            time.sleep(self.interval)
            try: self._scan_for_ransomware()
            except Exception: pass
    def _scan_for_ransomware(self):
        if getattr(self, '_scanning', False):
            return
        self._scanning = True
        try:
            self._do_scan_ransomware()
        finally:
            self._scanning = False
class WebcamProtector(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)
    block_signal = QtCore.pyqtSignal(str, int)
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.whitelist = {"zoom","teams","chrome","firefox","chromium","brave","skype","slack","discord","telegram","whatsapp","obs","obs64","kde-camera","gnome-camera","cheese","v4l2","guvcview","kamoso","vlc"}
        self.blocked = False
    def start(self):
        self.monitoring = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    def stop(self):
        self.monitoring = False
    def _get_webcam_users(self):
        users = []
        video_devs = [f"/dev/{d}" for d in os.listdir("/dev") if d.startswith("video")]
        for dev in video_devs:
            try:
                r = subprocess.run(["lsof", dev], capture_output=True, text=True, timeout=5)
                for line in r.stdout.strip().split("\n")[1:]:
                    if not line.strip(): continue
                    parts = line.split()
                    if len(parts) >= 2:
                        users.append({"pid": parts[1], "name": parts[0], "device": dev})
            except Exception: pass
        return users
    def block_webcam(self, hard=False):
        try:
            if hard:
                subprocess.run(["sudo","modprobe","-r","uvcvideo"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=10)
                subprocess.run(["sudo","modprobe","-r","videodev"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=10)
                self.blocked = True
                return "Webcam driver unloaded (hardware disabled)"
            else:
                import glob as _glob
                for vd in _glob.glob("/dev/video*"):
                    subprocess.run(["sudo","chmod","000",vd], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                self.blocked = True
                return "Webcam /dev blocked (chmod 000)"
        except Exception as e: return f"Block failed: {e}"
    def unblock_webcam(self):
        try:
            if self.blocked:
                subprocess.run(["sudo","modprobe","uvcvideo"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=10)
                for d in os.listdir("/dev"):
                    if d.startswith("video"):
                        subprocess.run(["sudo","chmod","666",f"/dev/{d}"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                try:
                    subprocess.run(["sudo","rm","-f","/etc/udev/rules.d/99-defendr-webcam.rules"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                    subprocess.run(["sudo","udevadm","control","--reload-rules"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                except Exception: pass
                self.blocked = False
                return "Webcam unblocked"
        except Exception as e: return f"Unblock failed: {e}"
        return "Webcam not blocked"
    def _run(self):
        while self.monitoring:
            try:
                users = self._get_webcam_users()
                for u in users:
                    proc_name = u["name"].lower().split("/")[-1] if "/" in u["name"] else u["name"].lower()
                    is_trusted = any(t for t in self.whitelist if t in proc_name)
                    if not is_trusted:
                        self.alert_signal.emit("HIGH", f"Unauthorized webcam access: {u['name']} (PID {u['pid']}) on {u['device']}")
                        self.block_signal.emit(u["name"], int(u["pid"]))
                time.sleep(4)
            except Exception: time.sleep(5)

class USBScanner(QtCore.QObject):
    scan_signal = QtCore.pyqtSignal(str)
    alert_signal = QtCore.pyqtSignal(str, str)
    IGNORED_MOUNTS = {"/mnt/defendr"}
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.monitoring = False
        self.known_mounts = set()
    def start(self):
        self.monitoring = True
        self.known_mounts = self._get_mounts()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    def stop(self):
        self.monitoring = False
    def _get_mounts(self):
        mounts = set()
        for base in ["/media", "/run/media", "/mnt"]:
            if not os.path.isdir(base):
                continue
            try:
                for root, dirs, _ in os.walk(base, topdown=True):
                    if root == base:
                        continue
                    if os.path.ismount(root) and root not in self.IGNORED_MOUNTS:
                        mounts.add(root)
                        dirs.clear()
            except Exception:
                pass
        return mounts
    def _run(self):
        while self.monitoring:
            try:
                current = self._get_mounts()
                new_mounts = current - self.known_mounts
                for m in new_mounts:
                    self.scan_signal.emit(m)
                    self.alert_signal.emit("INFO", f"USB device mounted: {m}")
                    self._auto_scan(m)
                self.known_mounts = current
                time.sleep(3)
            except Exception: time.sleep(5)
    def _auto_scan(self, mount_path):
        try:
            results = self.engine.scan_rapido(mount_path)
            if results["malicious"]:
                for r in results["malicious"]:
                    self.alert_signal.emit("HIGH", f"USB threat found: {r['path']} - {r['reason']}")
            elif results["suspicious"]:
                for r in results["suspicious"]:
                    self.alert_signal.emit("MEDIUM", f"USB suspicious: {r['path']} - {r['reason']}")
        except Exception: pass

class GameMode(QtCore.QObject):
    mode_changed = QtCore.pyqtSignal(bool)
    def __init__(self):
        super().__init__()
        self.active = False
        self.monitor_thread = None
        self._running = False
    def start(self):
        self._running = True
        self.monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        self.monitor_thread.start()
    def stop(self):
        self._running = False
    def _monitor(self):
        while self._running:
            try:
                import psutil
                gaming = False
                for p in psutil.process_iter(["name"]):
                    try:
                        name = p.info.get("name","").lower()
                        if name in ("steam","steamwebhelper","steam.exe","battle.net",
                                     "league of legends","csgo","cs2","dota2","fortnite",
                                     "valorant","cod.exe","minecraft","wine","wine64",
                                     "lutris","heroic","gamescope"):
                            gaming = True; break
                        if name and name not in ("python3","python","bash","zsh","systemd"):
                            try:
                                with open(f"/proc/{p.pid}/status") as f:
                                    for line in f:
                                        if line.startswith("State:") and "T" in line:
                                            break
                            except Exception: pass
                    except Exception: pass
                if gaming != self.active:
                    self.active = gaming
                    self.mode_changed.emit(gaming)
                time.sleep(5)
            except Exception: time.sleep(10)
    def suppress_notifications(self):
        return self.active
