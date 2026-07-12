# Security tools: firewall, web blocker, anti-phishing, sandbox, rootkit detector
import os, subprocess, re, shutil, socket, shlex, json
from defendr.filelock import file_lock, safe_json_read, safe_json_write
from PyQt5 import QtCore
from defendr.constants import *

class FirewallManager(QtCore.QObject):
    status_signal = QtCore.pyqtSignal(str)
    intrusion_signal = QtCore.pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.enabled = False
        self.rules = []
        self._scan_attempts = {}
        self._check_iptables()
        if self.iptables_ok:
            self._protect_server_port()
    def _protect_server_port(self):
        try:
            subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", "5000",
                           "-m", "state", "--state", "NEW", "-m", "recent", "--set",
                           "--name", "DEFENDR", "--rsource"], check=False, timeout=5,
                           capture_output=True)
            subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "5000",
                           "-m", "state", "--state", "NEW", "-m", "recent", "--update",
                           "--seconds", "60", "--hitcount", "10", "--name", "DEFENDR",
                           "--rttl", "-j", "DROP"], check=False, timeout=5,
                           capture_output=True)
            subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "5000",
                           "-s", "127.0.0.1", "-j", "ACCEPT"], check=False, timeout=5,
                           capture_output=True)
        except Exception:
            pass
    def _check_iptables(self):
        try:
            r = subprocess.run(["iptables","-L","-n"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            self.iptables_ok = r.returncode == 0
        except Exception: self.iptables_ok = False
    def is_available(self):
        return self.iptables_ok
    def enable(self):
        if not self.iptables_ok: return False, "iptables not available"
        try:
            subprocess.run(["iptables","-P","INPUT","DROP"], check=False, timeout=5)
            subprocess.run(["iptables","-P","FORWARD","DROP"], check=False, timeout=5)
            subprocess.run(["iptables","-A","INPUT","-m","state","--state","ESTABLISHED,RELATED","-j","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-A","INPUT","-i","lo","-j","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-A","OUTPUT","-m","state","--state","ESTABLISHED,RELATED","-j","ACCEPT"], check=False, timeout=5)
            self.enabled = True
            self.status_signal.emit("Firewall enabled (default deny inbound)")
            return True, "Firewall enabled"
        except Exception as e: return False, str(e)
    def disable(self):
        if not self.iptables_ok: return False, "iptables not available"
        try:
            subprocess.run(["iptables","-P","INPUT","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-P","FORWARD","ACCEPT"], check=False, timeout=5)
            self.enabled = False
            self.status_signal.emit("Firewall disabled")
            return True, "Firewall disabled"
        except Exception as e: return False, str(e)
    def block_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        if proto not in ("tcp","udp"): return False, f"Invalid protocol: {proto}"
        try:
            subprocess.run(["iptables","-A","INPUT","-p",proto,"--dport",str(port),"-j","DROP"], check=False, timeout=5)
            self.status_signal.emit(f"Blocked port {port}/{proto}")
            return True, f"Blocked port {port}"
        except Exception as e: return False, str(e)
    def allow_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        if proto not in ("tcp","udp"): return False, f"Invalid protocol: {proto}"
        try:
            subprocess.run(["iptables","-A","INPUT","-p",proto,"--dport",str(port),"-j","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-A","OUTPUT","-p",proto,"--dport",str(port),"-j","ACCEPT"], check=False, timeout=5)
            self.status_signal.emit(f"Allowed port {port}/{proto}")
            return True, f"Allowed port {port}"
        except Exception as e: return False, str(e)
    def flush(self):
        if not self.iptables_ok: return False, "iptables not available"
        try:
            subprocess.run(["iptables", "-F"], check=False, timeout=5)
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=False, timeout=5)
            self.rules = []; self.enabled = False
            self._protect_server_port()
            self.status_signal.emit("All firewall rules flushed")
            return True, "Rules flushed"
        except Exception as e: return False, str(e)
    def list_rules(self):
        if not self.iptables_ok: return []
        try:
            r = subprocess.run(["iptables","-L","-n","--line-numbers"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            return r.stdout.split("\n") if r.returncode == 0 else []
        except Exception: return []

    def detect_port_scan(self):
        try:
            r = subprocess.run(["iptables", "-L", "INPUT", "-n", "-v"],
                               capture_output=True, text=True, timeout=5,
                               encoding="utf-8", errors="surrogateescape")
            for line in r.stdout.split("\n"):
                parts = line.strip().split()
                if not parts or not parts[0].isdigit(): continue
                pkts = int(parts[0])
                if pkts <= 50: continue
                if "DROP" in line:
                    dport = "?"
                    if "dpt:" in line.lower():
                        for w in line.split():
                            if w.lower().startswith("dpt:"):
                                dport = w.split(":")[1]
                                break
                    src = "?"
                    for i, w in enumerate(parts):
                        if w == "DROP" and i > 2:
                            src = parts[i-4] if i-4 >= 0 else "?"
                            break
                    self.intrusion_signal.emit("HIGH",
                        f"Port scan: {pkts} pacotes DROP na porta {dport} de {src}")
                    return True
        except Exception:
            pass
        return False

    def detect_brute_force(self):
        try:
            # Check connections to port 5000 as brute force indicator
            try:
                import psutil
                conns = psutil.net_connections(kind="tcp")
                from_counter = {}
                for conn in conns:
                    if conn.raddr and conn.laddr and conn.laddr.port == 5000:
                        ip = conn.raddr.ip
                        if ip not in ("127.0.0.1", "::1"):
                            from_counter[ip] = from_counter.get(ip, 0) + 1
                for ip, count in from_counter.items():
                    if count > 10:
                        self.intrusion_signal.emit("MEDIUM",
                            f"Brute force: {count} conexoes de {ip} na porta 5000")
                        return True
            except Exception:
                pass
            # Fallback: check journalctl
            try:
                r = subprocess.run(["journalctl", "--since", "5 min ago", "-n", "100",
                                   "--no-pager"], capture_output=True, text=True, timeout=5,
                                   encoding="utf-8", errors="surrogateescape")
                login_attempts = 0
                for line in r.stdout.split("\n"):
                    if "login" in line.lower() and ("fail" in line.lower() or "invalid" in line.lower()):
                        login_attempts += 1
                if login_attempts > 10:
                    self.intrusion_signal.emit("MEDIUM", f"Brute force: {login_attempts} SSH/login failures in 5 min")
                    return True
            except Exception:
                pass
        except Exception:
            pass
        return False

class WebBlocker:
    def __init__(self):
        self.hosts_path = "/etc/hosts"
        self.blocked = []
        self.block_header = "# DefendR blocked domains"
        self._load()
    def _load(self):
        if not os.path.exists(self.hosts_path): return
        try:
            with open(self.hosts_path) as f: lines = f.readlines()
        except Exception: return
        in_block = False
        for line in lines:
            if self.block_header in line: in_block = True; continue
            if in_block:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "127.0.0.1":
                    self.blocked.append(parts[1])
        self.blocked = list(set(self.blocked))
    def block_domain(self, domain):
        domain = domain.strip().lower()
        if domain in self.blocked: return False, "Already blocked"
        try:
            with open(self.hosts_path, "a") as f:
                f.write(f"127.0.0.1 {domain}\n")
            self.blocked.append(domain)
            return True, f"Blocked {domain}"
        except PermissionError: return False, "Need root (sudo)"
        except Exception as e: return False, str(e)
    def unblock_domain(self, domain):
        if domain not in self.blocked: return False, "Not blocked"
        try:
            with open(self.hosts_path) as f: lines = f.readlines()
            with open(self.hosts_path, "w") as f:
                for line in lines:
                    if domain not in line: f.write(line)
            self.blocked.remove(domain)
            return True, f"Unblocked {domain}"
        except PermissionError: return False, "Need root (sudo)"
        except Exception as e: return False, str(e)
    def get_blocked(self):
        return self.blocked

class AntiPhishing:
    def __init__(self):
        self.phishing_db = set(MALICIOUS_DOMAINS)
        self.cache_file = os.path.join(CONFIG_DIR, "phishing_db.json")
        self._load_cache()
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file) as f: self.phishing_db.update(json.load(f))
            except Exception: pass
    def save_cache(self):
        with open(self.cache_file, "w") as f: json.dump(list(self.phishing_db), f)
    def check_url(self, url):
        url = url.lower()
        if not url.startswith("http"): url = "http://" + url
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
        except Exception: domain = url.split("/")[0]
        score = 0
        reasons = []
        if domain in self.phishing_db:
            score += 50; reasons.append("Known phishing domain")
        if len(domain) > 30:
            score += 10; reasons.append("Suspiciously long domain")
        if re.search(r'\d{2,}\.', domain):
            score += 10; reasons.append("IP-based domain (unusual)")
        for kw in PHISHING_KEYWORDS:
            if kw in domain:
                score += 20; reasons.append(f"Contains '{kw}'")
                break
        sub_count = domain.count(".")
        if sub_count > 3:
            score += 10; reasons.append(f"Too many subdomains ({sub_count})")
        return {"score": score, "risk": "high" if score >= 50 else ("medium" if score >= 20 else "low"),
                "reasons": reasons, "domain": domain}
    def add_phishing(self, domain):
        self.phishing_db.add(domain.lower())
        self.save_cache()

class SandboxManager:
    def __init__(self):
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
        except Exception as e: return False, str(e)

class RootkitDetector(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.results = {}
    def full_scan(self):
        self.results = {}
        self._check_hidden_procs()
        self._check_kernel_modules()
        self._check_ld_preload()
        self._check_promiscuous()
        self._check_suid()
        return self.results
    def _check_hidden_procs(self):
        try:
            procs = set()
            for p in os.listdir("/proc"):
                if p.isdigit(): procs.add(int(p))
            import psutil
            psutil_pids = set(psutil.pids())
            hidden = procs - psutil_pids
            if hidden:
                self.results["Hidden Processes"] = f"Found {len(hidden)} processes hidden from psutil: {sorted(hidden)[:10]}"
                self.alert_signal.emit("HIGH", f"Rootkit: {len(hidden)} hidden processes detected")
        except Exception: pass
    def _check_kernel_modules(self):
        try:
            r = subprocess.run(["lsmod"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            modules = r.stdout.lower()
            suspicious_modules = ["hideproc", "suterusu", "adore", "knark", "rootkit", "nethog"]
            found = [m for m in suspicious_modules if m in modules]
            if found:
                self.results["Suspicious Kernel Modules"] = f"Found: {', '.join(found)}"
                self.alert_signal.emit("HIGH", f"Rootkit: suspicious kernel modules: {', '.join(found)}")
        except Exception: pass
        try:
            r = subprocess.run(["cat","/proc/modules"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            self.results["Loaded Modules Count"] = f"{len(r.stdout.strip().split(chr(10)))} modules"
        except Exception: pass
    def _check_ld_preload(self):
        ld_preload = os.environ.get("LD_PRELOAD", "")
        ld_library = os.environ.get("LD_LIBRARY_PATH", "")
        if ld_preload:
            self.results["LD_PRELOAD"] = f"LD_PRELOAD is set: {ld_preload[:100]}"
            self.alert_signal.emit("MEDIUM", f"Rootkit: LD_PRELOAD detected: {ld_preload[:60]}")
        if ld_library and ("/tmp/" in ld_library or "/dev/shm" in ld_library):
            self.results["LD_LIBRARY_PATH"] = f"Unusual library path: {ld_library[:100]}"
            self.alert_signal.emit("MEDIUM", f"Suspicious LD_LIBRARY_PATH: {ld_library[:60]}")
    def _check_promiscuous(self):
        try:
            r = subprocess.run(["ip","link","show"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            if "PROMISC" in r.stdout:
                self.results["Promiscuous Mode"] = "Network interface in promiscuous mode (possible packet sniffer)"
                self.alert_signal.emit("MEDIUM", "Network: Promiscuous mode detected (packet sniffing)")
        except Exception: pass
    def _check_suid(self):
        try:
            suid_files = []
            suid_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
            for d in suid_dirs:
                if not os.path.isdir(d): continue
                for f in os.listdir(d):
                    fpath = os.path.join(d, f)
                    if os.path.isfile(fpath) and os.stat(fpath).st_mode & 0o4000:
                        suid_files.append(f)
            if suid_files:
                self.results["SUID Binaries"] = f"{len(suid_files)} SUID binaries found"
        except Exception: pass
