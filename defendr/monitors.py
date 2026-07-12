# Monitors: network, real-time, ransomware, webcam, USB, game mode
import os, threading, time, subprocess, json
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
        self._conn_history = {}
        self._port_scan_alerted = set()
    def start(self):
        if getattr(self, 'thread', None) and self.thread.is_alive():
            self.monitoring = False
            self.thread.join(timeout=3)
        self.monitoring = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    def stop(self):
        self.monitoring = False
        if getattr(self, 'thread', None):
            self.thread.join(timeout=2)
    def _run(self):
        while self.monitoring:
            try:
                self._check_arp(); self._check_ports(); self._check_dns(); self._check_connections(); self._check_port_scan()
                time.sleep(2)
            except Exception: pass
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
                if ns in known_good: continue
                if self.gateway_ip and ns == self.gateway_ip: continue
                if ns == self.gateway_ip: continue
                if ns not in self.known_dns:
                    self.known_dns.add(ns)
                    self.alert_signal.emit("LOW",f"DNS: {ns} (not in standard whitelist)")
        except Exception: pass
    def _check_connections(self):
        try:
            import psutil
            try: conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            seen = set()
            for conn in conns:
                if not (conn.status == "ESTABLISHED" and conn.raddr): continue
                ip,port=conn.raddr.ip,conn.raddr.port
                if port == 53: continue
                local_prefixes=("127.","10.","172.16.","172.17.","172.18.","172.19.",
                    "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","192.168.","::1")
                if any(ip.startswith(p) for p in local_prefixes): continue
                key = f"{ip}:{port}"
                if key in seen: continue
                seen.add(key)
                if port in {4444,5555,6666,1337,31337,12345,54321,22222}:
                    pname="?"
                    if conn.pid:
                        try: pname=psutil.Process(conn.pid).name()
                        except Exception: pass
                    self._fire_intrusion("MEDIUM", f"Conexao suspeita: {ip}:{port} ({pname})", "Conexao Remota", ip)
        except Exception: pass

    def _check_port_scan(self):
        try:
            import psutil
            try: all_conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            now = time.time()
            for conn in all_conns:
                if not (conn.raddr and conn.status in ("SYN_SENT", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", "LAST_ACK", "FIN_WAIT1", "FIN_WAIT2")): continue
                ip = conn.raddr.ip
                if ip in ("127.0.0.1", "::1"): continue
                if ip not in self._conn_history:
                    self._conn_history[ip] = {"ports": set(), "times": []}
                self._conn_history[ip]["ports"].add(conn.raddr.port)
                self._conn_history[ip]["times"].append(now)
            clean = []
            for ip, data in list(self._conn_history.items()):
                data["times"] = [t for t in data["times"] if now - t < 10]
                if len(data["times"]) > 20 and ip not in self._port_scan_alerted:
                    self._port_scan_alerted.add(ip)
                    self._fire_intrusion("HIGH", f"Port scan detectado de {ip}: {len(data['ports'])} portas em 10s", "Port Scan", ip)
                if not data["times"]:
                    clean.append(ip)
            for ip in clean:
                del self._conn_history[ip]
        except Exception: pass

    def _fire_intrusion(self, severity, msg, attack_type="", source_ip=""):
        self.alert_signal.emit(severity, f"[{attack_type}] {msg}")
        self.intrusion_signal.emit(severity, f"{msg}|{attack_type}|{source_ip}")

class RealTimeProtector(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str, str)
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.active = False
        self.watchdog = None
        self.observer = None
        self.watched_dirs = ["/tmp", os.path.expanduser("~/Downloads"),
                             os.path.expanduser("~/Transferências"),
                             os.path.expanduser("~/Área de trabalho"),
                             os.path.expanduser("~/Desktop")]
        self._init_watchdog()
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
            self.handler_class = DefendRHandler
            self.watchdog_available = True
        except ImportError:
            self.watchdog_available = False
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
            except Exception: pass
    def stop(self):
        self.active = False
        if self.observer:
            try: self.observer.stop(); self.observer.join()
            except Exception: pass
            self.observer = None
    def _check_file(self, path):
        if not os.path.isfile(path) or self.engine.is_pentest(path): return
        ext = os.path.splitext(path)[1].lower()
        if ext not in SUSPICIOUS_EXTS: return
        result = self.engine._scan_file(Path(path))
        if result and result["risk"] in ("malicious","suspicious"):
            self.alert_signal.emit(result["risk"], path, result["reason"])
    def scan_file(self, path):
        return self.engine._scan_file(Path(path))

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
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.monitoring = False
        self.known_mounts = set()
    def start(self):
        self.monitoring = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    def stop(self):
        self.monitoring = False
    def _get_mounts(self):
        mounts = set()
        for d in ["/media", "/run/media", "/mnt"]:
            if os.path.isdir(d):
                try:
                    for f in os.listdir(d):
                        fp = os.path.join(d, f)
                        if os.path.ismount(fp): mounts.add(fp)
                except Exception: pass
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
            results = self.engine.scan_path(mount_path)
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
