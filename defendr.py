#!/usr/bin/env python3
import sys, os, json, hashlib, threading, queue, time, socket, struct
import subprocess, re, shutil, base64, textwrap, tempfile, uuid
from datetime import datetime, timedelta
from pathlib import Path
from PyQt5 import QtCore, QtGui, QtWidgets

DARK_BG = "#0a0015"
DARK_MID = "#1a0a2e"
DARK_CARD = "#140528"
BORDER = "#3d2b5e"
TEXT = "#e0e0e0"
TEXT_DIM = "#888"
ACCENT = "#7c4dff"
ACCENT_LIGHT = "#b388ff"
ACCENT_DARK = "#6200ea"
GREEN = "#2ecc71"
RED = "#e53935"
YELLOW = "#fdd835"
CYAN = "#00bfff"

QUARANTINE_DIR = os.path.expanduser("~/.defendr_quarantine")
CONFIG_DIR = os.path.expanduser("~/.defendr")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

PENTEST_WHITELIST = {
    "metasploit", "msfconsole", "msfvenom", "meterpreter",
    "nmap", "zenmap", "wireshark", "tshark",
    "burpsuite", "burp", "sqlmap", "hydra", "thc-hydra",
    "john", "johnny", "hashcat",
    "aircrack", "airmon-ng", "airodump", "aireplay",
    "beef", "beef-xss", "nikto",
    "gobuster", "dirbuster", "wfuzz",
    "socat", "netcat", "nc", "ncat",
    "proxychains", "ettercap", "bettercap",
    "masscan", "openvas", "nessus",
    "exploitdb", "searchsploit",
    "veil", "veil-evasion", "shellter",
    "crackmapexec", "cme", "impacket",
    "responder", "mitmproxy",
    "maltego", "recon-ng", "theharvester",
    "sherlock", "holehe",
    "sublist3r", "amass", "subfinder",
    "httpx", "nuclei", "ffuf",
    "dirsearch", "feroxbuster",
    "chisel", "ligolo-ng", "frp", "stowaway",
    "merlin", "sliver", "cobaltstrike", "aggressor",
    "pupy", "pwn", "rop", "ret2",
    "radare2", "rizin", "cutter",
    "ghidra", "ida", "x64dbg", "x32dbg",
    "ollydbg", "immunity debugger",
    "gdb", "pwndbg", "peda", "gef",
    "winpwn", "mimikatz",
    "powershell -exec bypass", "powershell -enc",
}

MALICIOUS_SIGS = [
    (b"\x4d\x5a\x90\x00", "PE (Windows executable)"),
    (b"\x7f\x45\x4c\x46", "ELF (Linux executable)"),
    (b"\x50\x4b\x03\x04", "ZIP/OLE2 container"),
    (b"\x1f\x8b\x08", "GZip compressed"),
    (b"\x89\x50\x4e\x47", "PNG image (possible stego)"),
]
SUSPICIOUS_EXTS = {".exe", ".dll", ".scr", ".ps1", ".vbs", ".vbe",
                    ".js", ".jse", ".wsf", ".hta", ".bat",
                    ".cmd", ".com", ".pif", ".jar", ".docm", ".xlsm"}
SUSPICIOUS_STRINGS = [b"CreateRemoteThread", b"VirtualAllocEx",
                       b"WriteProcessMemory", b"GetProcAddress",
                       b"ShellExecute", b"WinExec",
                       b"cmd.exe /c", b"powershell -",
                       b"base64", b"FromBase64",
                       b"bypass", b"amsi", b"Invoke-",
                       b"DownloadString", b"DownloadFile",
                       b"Start-Process -Hidden",
                       b"WScript.Shell", b"FileSystemObject"]
SUSPICIOUS_PROCESSES = {
    "keylogger": "suspicious", "logkeys": "suspicious",
    "xnsniff": "suspicious", "xngrab": "suspicious",
    "wireshark": "network", "tshark": "network",
    "tcpdump": "network", "ettercap": "network",
}

MALICIOUS_DOMAINS = [
    "malware.com", "phishing.com", "trojan-bank.com",
    "fake-login.com", "steal-info.com", "ransomware.cc",
    "c2-server.net", "botnet-c2.com", "evil-domain.org",
]
PHISHING_KEYWORDS = ["login", "secure", "bank", "account", "verify",
                     "update", "confirm", "signin", "webmail", "paypal"]

RANSOMWARE_EXTENSIONS = {".encrypted", ".locked", ".crypt", ".enc",
                         ".cryp1", ".locky", ".wncry", ".wcry",
                         ".onion", ".zepto", ".cerber", ".odin",
                         ".legion", ".ecc", ".exx", ".ezz",
                         ".zzz", ".xyz", ".aaa", ".ccc", ".vvv"}

# ===================== TRANSLATION SYSTEM =====================
APP_LANGS = {
    "pt": {
        "DefendR - Advanced Protection": "DefendR - Protecao Avancada",
        "Dashboard": "Dashboard",
        "📊  Dashboard": "📊  Dashboard",
        "⚙  Process Monitor": "⚙  Monitor de Processos",
        "🔍  File Scanner": "🔍  Scanner de Arquivos",
        "🛡  Real-Time Protection": "🛡  Protecao em Tempo Real",
        "🔒  Firewall": "🔒  Firewall",
        "🌐  Network": "🌐  Rede",
        "📦  Quarantine": "📦  Quarentena",
        "🧰  Tools": "🧰  Ferramentas",
        "🔧  Settings": "🔧  Configuracoes",
        "▶ Start Real-Time Protection": "▶ Iniciar Protecao",
        "⏹ Stop Real-Time Protection": "⏹ Parar Protecao",
        "▶ Start Ransomware Detection": "▶ Iniciar Anti-Ransomware",
        "⏹ Stop Ransomware Detection": "⏹ Parar Anti-Ransomware",
        "▶ Start Webcam Monitor": "▶ Iniciar Webcam",
        "⏹ Stop Webcam Monitor": "⏹ Parar Webcam",
        "🔴 Block Webcam": "🔴 Bloquear Webcam",
        "🟢 Unblock Webcam": "🟢 Desbloquear Webcam",
        "Block": "Bloquear",
        "Unblock": "Desbloquear",
        "Check URL": "Verificar URL",
        "🛡 Enable Firewall": "🛡 Ativar Firewall",
        "Disable Firewall": "Desativar Firewall",
        "🔄 Flush Rules": "🔄 Limpar Regras",
        "Block Port": "Bloquear Porta",
        "Allow Port": "Liberar Porta",
        "🔄 Refresh Rules": "🔄 Atualizar Regras",
        "▶ Start": "▶ Iniciar",
        "⏹ Stop": "⏹ Parar",
        "🔍 ARP Scan Network": "🔍 Varredura ARP",
        "📡 Router Info": "📡 Info Roteador",
        "📡 Scan Router": "📡 Escanear Roteador",
        "▶ Start Continuous Monitor": "▶ Monitor Continuo",
        "⏹ Stop Monitoring": "⏹ Parar Monitor",
        "📂 Add Config": "📂 Adicionar Config",
        "▶ Connect": "▶ Conectar",
        "⏹ Disconnect": "⏹ Desconectar",
        "Reset to Default": "Restaurar Padrao",
        "🔒 Enable DNSSEC": "🔒 Ativar DNSSEC",
        "🔄 Refresh": "🔄 Atualizar",
        "🗑 Delete All": "🗑 Excluir Tudo",
        "📁 Select File & Run": "📁 Selecionar e Executar",
        "🔍 Run Rootkit Scan": "🔍 Escanear Rootkit",
        "🔓 Unlock Vault": "🔓 Destravar Cofre",
        "🔒 Lock": "🔒 Travar",
        "💾 Save Entry": "💾 Salvar",
        "➕ Add": "➕ Adicionar",
        "📁 Shred File": "📁 Destruir Arquivo",
        "📂 Shred Folder": "📂 Destruir Pasta",
        "🧹 Wipe Free Space": "🧹 Limpar Espaco Livre",
        "🧹 Run Cleanup": "🧹 Executar Limpeza",
        "👁 Preview Cleanup": "👁 Visualizar",
        "🔄 Check for Updates": "🔄 Verificar Atualizacoes",
        "📥 Install All Updates": "📥 Instalar Tudo",
        "🔍 Check for Updates": "🔍 Verificar Atualizacoes",
        "Enable Game Mode": "Ativar Game Mode",
        "Disable Game Mode": "Desativar Game Mode",
        "Open DefendR": "Abrir DefendR",
        "Quit": "Sair",
        "Game Mode": "Game Mode",
        "Protected by DefendR": "Protegido por DefendR",
        "No threats": "Nenhuma ameaca",
        "threat(s) found": "ameaca(s) encontrada(s)",
        "Run with sudo for full firewall and network monitoring.": "Execute com sudo para monitoramento completo de firewall e rede.",
        "Protecao continua ativa em segundo plano": "Protecao continua ativa em segundo plano",
        "DefendR": "DefendR",
        "Status: Stopped": "Status: Parado",
        "Status: Active": "Status: Ativo",
    },
    "en": {},
    "es": {
        "DefendR - Advanced Protection": "DefendR - Proteccion Avanzada",
        "📊  Dashboard": "📊  Panel",
        "🔍  File Scanner": "🔍  Escaner",
        "🛡  Real-Time Protection": "🛡  Proteccion en Tiempo Real",
        "🔒  Firewall": "🔒  Cortafuegos",
        "🌐  Network": "🌐  Red",
        "📦  Quarantine": "📦  Cuarentena",
        "🧰  Tools": "🧰  Herramientas",
        "🔧  Settings": "🔧  Ajustes",
        "▶ Start": "▶ Iniciar",
        "⏹ Stop": "⏹ Parar",
        "Block": "Bloquear",
        "Unblock": "Desbloquear",
        "Open DefendR": "Abrir DefendR",
        "Quit": "Salir",
    },
    "fr": {
        "DefendR - Advanced Protection": "DefendR - Protection Avancee",
        "📊  Dashboard": "📊  Tableau",
        "🔍  File Scanner": "🔍  Scanner",
        "🛡  Real-Time Protection": "🛡  Protection Temps Reel",
        "🔒  Firewall": "🔒  Pare-feu",
        "🌐  Network": "🌐  Reseau",
        "📦  Quarantine": "📦  Quarantaine",
        "🧰  Tools": "🧰  Outils",
        "🔧  Settings": "🔧  Parametres",
        "Block": "Bloquer",
        "Unblock": "Debloquer",
        "Open DefendR": "Ouvrir DefendR",
        "Quit": "Quitter",
    },
    "de": {
        "DefendR - Advanced Protection": "DefendR - Erweiterter Schutz",
        "📊  Dashboard": "📊  Ubersicht",
        "🔍  File Scanner": "🔍  Scanner",
        "🛡  Real-Time Protection": "🛡  Echtzeitschutz",
        "🔒  Firewall": "🔒  Firewall",
        "🌐  Network": "🌐  Netzwerk",
        "📦  Quarantine": "📦  Quarantane",
        "🧰  Tools": "🧰  Werkzeuge",
        "🔧  Settings": "🔧  Einstellungen",
        "Block": "Sperren",
        "Unblock": "Entsperren",
        "Open DefendR": "DefendR offnen",
        "Quit": "Beenden",
    },
    "it": {
        "DefendR - Advanced Protection": "DefendR - Protezione Avanzata",
        "📊  Dashboard": "📊  Dashboard",
        "🔍  File Scanner": "🔍  Scanner",
        "🛡  Real-Time Protection": "🛡  Protezione in Tempo Reale",
        "🔒  Firewall": "🔒  Firewall",
        "🌐  Network": "🌐  Rete",
        "📦  Quarantine": "📦  Quarantena",
        "🧰  Tools": "🧰  Strumenti",
        "🔧  Settings": "🔧  Impostazioni",
        "Block": "Blocca",
        "Unblock": "Sblocca",
        "Open DefendR": "Apri DefendR",
        "Quit": "Esci",
    },
    "ru": {
        "DefendR - Advanced Protection": "DefendR - Rasshirennaya zashchita",
        "📊  Dashboard": "📊  Panel",
        "🔍  File Scanner": "🔍  Skaner",
        "🛡  Real-Time Protection": "🛡  Zashchita v realnom vremeni",
        "🔒  Firewall": "🔒  Faivol",
        "🌐  Network": "🌐  Set",
        "📦  Quarantine": "📦  Karantin",
        "🧰  Tools": "🧰  Instrumenty",
        "🔧  Settings": "🔧  Nastroiki",
        "Block": "Blokirovat",
        "Unblock": "Razblokirovat",
        "Open DefendR": "Otkryt DefendR",
        "Quit": "Vyiti",
    },
}

def detect_app_lang():
    installed_file = os.path.join(CONFIG_DIR, "installed")
    if os.path.exists(installed_file):
        try:
            with open(installed_file) as f:
                for line in f:
                    if line.startswith("lang="):
                        code = line.strip().split("=", 1)[1]
                        if code in APP_LANGS: return code
        except: pass
    lang = os.environ.get("LANG", "pt").split("_")[0]
    return lang if lang in APP_LANGS else "en"

CURRENT_LANG = detect_app_lang()

def _(text):
    return APP_LANGS.get(CURRENT_LANG, APP_LANGS["en"]).get(text, text)

class DefendREngine:
    def __init__(self):
        self.whitelist = set(PENTEST_WHITELIST)
        self.config_file = os.path.join(CONFIG_DIR, "config.json")
        self.load_config()
        self.scanning = False
        self.protection_active = True

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    data = json.load(f)
                    self.whitelist.update(data.get("whitelist", []))
            except: pass

    def save_config(self):
        with open(self.config_file, "w") as f:
            json.dump({"whitelist": list(self.whitelist)}, f, indent=2)

    def is_pentest(self, path):
        name = os.path.basename(path).lower().rsplit(".", 1)[0]
        p = path.lower()
        return any(w in name or w in p for w in self.whitelist)

    def scan_path(self, path, progress_cb=None, result_cb=None):
        self.scanning = True
        results = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": 0}
        try:
            p = Path(path)
            files = list(p.rglob("*")) if p.is_dir() else [p]
            total = len(files)
            for i, f in enumerate(files):
                if not self.scanning: break
                if f.is_file():
                    r = self._scan_file(f)
                    if r:
                        results[r["risk"]].append(r)
                    else:
                        results["safe"] += 1
                if progress_cb and total > 0:
                    progress_cb(int((i+1)/total*100), f.name)
        finally:
            self.scanning = False
            if progress_cb: progress_cb(100, "Done")
        return results

    def _scan_file(self, fpath):
        try:
            size = fpath.stat().st_size
            if size == 0 or size > 100*1024*1024: return None
            ext = fpath.suffix.lower()
            if self.is_pentest(str(fpath)):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size}
            if ext not in SUSPICIOUS_EXTS: return None
            with open(fpath, "rb") as f:
                header = f.read(16)
                for sig, desc in MALICIOUS_SIGS:
                    if header.startswith(sig):
                        return {"path": str(fpath), "risk": "malicious", "reason": desc, "size": size}
                f.seek(0)
                content = f.read(min(size, 8192))
                found = [s for s in SUSPICIOUS_STRINGS if s in content]
                if len(found) >= 3:
                    return {"path": str(fpath), "risk": "suspicious",
                            "reason": f"Flagged: {', '.join(s.decode() for s in found[:4])}", "size": size}
            return None
        except (PermissionError, OSError): return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0}

    def get_processes(self):
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
                except: pass
            return procs
        except: return []

class NetworkMonitor(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str)
    data_signal = QtCore.pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.arp_table = {}
        self.arp_changes = {}
        self.known_dns = set()
        self.gateway_ip = None
    def start(self):
        self.monitoring = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
    def stop(self):
        self.monitoring = False
    def _run(self):
        while self.monitoring:
            try:
                self._check_arp(); self._check_ports(); self._check_dns(); self._check_connections()
                time.sleep(5)
            except: pass
    def _get_gateway(self):
        try:
            r = subprocess.run(["ip","route"], capture_output=True, text=True, timeout=3)
            for line in r.stdout.split("\n"):
                if "default" in line:
                    parts = line.split(); return parts[2]
        except: pass
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
                            except: pass
                        self.alert_signal.emit("MEDIUM",f"Suspicious listener on port {p} (PID {conn.pid}: {pname})")
        except: pass
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
        except: pass
    def _check_connections(self):
        try:
            import psutil
            try: conns = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError): return
            seen = set()
            for conn in conns:
                if conn.status=="ESTABLISHED" and conn.raddr:
                    ip,port=conn.raddr.ip,conn.raddr.port
                    if port == 53: continue
                    local_prefixes=("127.","10.","172.16.","172.17.","172.18.","172.19.",
                        "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.","192.168.","::1")
                    if not any(ip.startswith(p) for p in local_prefixes):
                        key = f"{ip}:{port}"
                        if key in seen: continue
                        seen.add(key)
                        if port in {4444,5555,6666,1337,31337,12345,54321,22222}:
                            pname="?"
                            if conn.pid:
                                try: pname=psutil.Process(conn.pid).name()
                                except: pass
                            self.alert_signal.emit("LOW",f"Remote connection: {ip}:{port} ({pname})")
        except: pass

# ===================== QUARANTINE MANAGER =====================
class QuarantineManager:
    def __init__(self):
        self.quar_dir = QUARANTINE_DIR
        self.meta_file = os.path.join(QUARANTINE_DIR, "metadata.json")
        self.metadata = self._load_meta()
    def _load_meta(self):
        if os.path.exists(self.meta_file):
            try:
                with open(self.meta_file) as f: return json.load(f)
            except: pass
        return {}
    def _save_meta(self):
        with open(self.meta_file, "w") as f: json.dump(self.metadata, f, indent=2)
    def quarantine(self, filepath):
        fpath = Path(filepath)
        if not fpath.exists(): return False, "File not found"
        qid = uuid.uuid4().hex[:12]
        dest = os.path.join(self.quar_dir, qid + fpath.suffix)
        shutil.move(str(fpath), dest)
        self.metadata[qid] = {
            "original": str(fpath.resolve()),
            "quarantined": dest,
            "date": datetime.now().isoformat(),
            "hash": hashlib.sha256(open(dest,"rb").read()).hexdigest(),
            "size": os.path.getsize(dest),
        }
        self._save_meta()
        return True, qid
    def restore(self, qid):
        if qid not in self.metadata: return False, "ID not found"
        info = self.metadata[qid]
        orig = Path(info["original"])
        orig.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(info["quarantined"], str(orig))
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

# ===================== REAL TIME PROTECTOR =====================
class RealTimeProtector(QtCore.QObject):
    alert_signal = QtCore.pyqtSignal(str, str, str)
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.active = False
        self.watchdog = None
        self.observer = None
        self.watched_dirs = ["/tmp", os.path.expanduser("~/Downloads"),
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
            except: pass
    def stop(self):
        self.active = False
        if self.observer:
            try: self.observer.stop(); self.observer.join()
            except: pass
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

# ===================== FIREWALL MANAGER =====================
class FirewallManager(QtCore.QObject):
    status_signal = QtCore.pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.enabled = False
        self.rules = []
        self._check_iptables()
    def _check_iptables(self):
        try:
            r = subprocess.run(["iptables","-L","-n"], capture_output=True, text=True, timeout=5)
            self.iptables_ok = r.returncode == 0
        except: self.iptables_ok = False
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
        try:
            subprocess.run(["iptables","-A","INPUT","-p",proto,"--dport",str(port),"-j","DROP"], check=False, timeout=5)
            self.status_signal.emit(f"Blocked port {port}/{proto}")
            return True, f"Blocked port {port}"
        except Exception as e: return False, str(e)
    def allow_port(self, port, proto="tcp"):
        if not self.iptables_ok: return False, "iptables not available"
        try:
            subprocess.run(["iptables","-A","INPUT","-p",proto,"--dport",str(port),"-j","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-A","OUTPUT","-p",proto,"--dport",str(port),"-j","ACCEPT"], check=False, timeout=5)
            self.status_signal.emit(f"Allowed port {port}/{proto}")
            return True, f"Allowed port {port}"
        except Exception as e: return False, str(e)
    def flush(self):
        if not self.iptables_ok: return False, "iptables not available"
        try:
            subprocess.run(["iptables","-F"], check=False, timeout=5)
            subprocess.run(["iptables","-P","INPUT","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-P","FORWARD","ACCEPT"], check=False, timeout=5)
            subprocess.run(["iptables","-P","OUTPUT","ACCEPT"], check=False, timeout=5)
            self.rules = []; self.enabled = False
            self.status_signal.emit("All firewall rules flushed")
            return True, "Rules flushed"
        except Exception as e: return False, str(e)
    def list_rules(self):
        if not self.iptables_ok: return []
        try:
            r = subprocess.run(["iptables","-L","-n","--line-numbers"], capture_output=True, text=True, timeout=5)
            return r.stdout.split("\n") if r.returncode == 0 else []
        except: return []

# ===================== WEB BLOCKER =====================
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
        except: return
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

# ===================== ANTI PHISHING =====================
class AntiPhishing:
    def __init__(self):
        self.phishing_db = set(MALICIOUS_DOMAINS)
        self.cache_file = os.path.join(CONFIG_DIR, "phishing_db.json")
        self._load_cache()
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file) as f: self.phishing_db.update(json.load(f))
            except: pass
    def save_cache(self):
        with open(self.cache_file, "w") as f: json.dump(list(self.phishing_db), f)
    def check_url(self, url):
        url = url.lower()
        if not url.startswith("http"): url = "http://" + url
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
        except: domain = url.split("/")[0]
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

# ===================== SANDBOX MANAGER =====================
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
            except: pass
    def run_in_sandbox(self, filepath, args=""):
        if not self.available: return False, "No sandbox tool available (install firejail)"
        if not os.path.exists(filepath): return False, "File not found"
        try:
            if self.sandbox_type == "firejail":
                cmd = ["firejail", "--seccomp", "--net=none", filepath] + (args.split() if args else [])
            else:
                cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                       "--unshare-net", filepath] + (args.split() if args else [])
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, f"Running in {self.sandbox_type}"
        except Exception as e: return False, str(e)

# ===================== ANTI RANSOMWARE =====================
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
    def _scan_for_ransomware(self):
        watch_dirs = [os.path.expanduser("~/Documents"),
                      os.path.expanduser("~/Downloads"),
                      os.path.expanduser("~/Área de trabalho"),
                      os.path.expanduser("~/Desktop"),
                      os.path.expanduser("~/Pictures"),
                      os.path.expanduser("~/Videos")]
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
            except: pass
        if encrypted_count >= self.change_threshold:
            exts_str = ", ".join(f"{k}({v})" for k,v in sorted(new_exts.items(), key=lambda x:-x[1])[:5])
            self.alert_signal.emit("HIGH", f"Ransomware detected! {encrypted_count} encrypted files found. Extensions: {exts_str}")
    def _run(self):
        while self.monitoring:
            time.sleep(self.interval)
            try: self._scan_for_ransomware()
            except: pass

# ===================== ROOTKIT DETECTOR =====================
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
        except: pass
    def _check_kernel_modules(self):
        try:
            r = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
            modules = r.stdout.lower()
            suspicious_modules = ["hideproc", "suterusu", "adore", "knark", "rootkit", "nethog"]
            found = [m for m in suspicious_modules if m in modules]
            if found:
                self.results["Suspicious Kernel Modules"] = f"Found: {', '.join(found)}"
                self.alert_signal.emit("HIGH", f"Rootkit: suspicious kernel modules: {', '.join(found)}")
        except: pass
        try:
            r = subprocess.run(["cat","/proc/modules"], capture_output=True, text=True, timeout=5)
            self.results["Loaded Modules Count"] = f"{len(r.stdout.strip().split(chr(10)))} modules"
        except: pass
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
            r = subprocess.run(["ip","link","show"], capture_output=True, text=True, timeout=5)
            if "PROMISC" in r.stdout:
                self.results["Promiscuous Mode"] = "Network interface in promiscuous mode (possible packet sniffer)"
                self.alert_signal.emit("MEDIUM", "Network: Promiscuous mode detected (packet sniffing)")
        except: pass
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
        except: pass

# ===================== SCHEDULER =====================
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
        if os.path.exists(path):
            try:
                with open(path) as f: self.tasks = json.load(f)
            except: pass
    def _save(self):
        path = os.path.join(CONFIG_DIR, "scheduler.json")
        with open(path, "w") as f: json.dump(self.tasks, f, indent=2)
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
                except: pass

# ===================== SIGNATURE UPDATER =====================
class SignatureUpdater(QtCore.QObject):
    update_signal = QtCore.pyqtSignal(str)
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.sig_file = os.path.join(CONFIG_DIR, "signatures.json")
        self._load()
    def _load(self):
        if os.path.exists(self.sig_file):
            try:
                with open(self.sig_file) as f: data = json.load(f)
                self.engine.whitelist.update(data.get("whitelist", []))
            except: pass
    def check_update(self):
        try:
            import urllib.request
            url = "https://raw.githubusercontent.com/anomalyco/defendr-sigs/main/sigs.json"
            req = urllib.request.Request(url, headers={"User-Agent": "DefendR/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
            with open(self.sig_file, "w") as f: json.dump(data, f, indent=2)
            new_sigs = data.get("malicious_sigs", [])
            new_whitelist = data.get("whitelist", [])
            n = 0
            for sig_bytes, desc in new_sigs:
                sig = bytes.fromhex(sig_bytes) if isinstance(sig_bytes, str) else bytes(sig_bytes)
                existing_sigs = {s[0] for s in MALICIOUS_SIGS}
                if sig not in existing_sigs:
                    MALICIOUS_SIGS.append((sig, desc))
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
        return len(MALICIOUS_SIGS) + len(SUSPICIOUS_STRINGS) + len(self.engine.whitelist)

# ===================== GAME MODE =====================
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
                            except: pass
                    except: pass
                if gaming != self.active:
                    self.active = gaming
                    self.mode_changed.emit(gaming)
                time.sleep(5)
            except: time.sleep(10)
    def suppress_notifications(self):
        return self.active

# ===================== USB SCANNER =====================
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
                except: pass
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
            except: time.sleep(5)
    def _auto_scan(self, mount_path):
        try:
            results = self.engine.scan_path(mount_path)
            if results["malicious"]:
                for r in results["malicious"]:
                    self.alert_signal.emit("HIGH", f"USB threat found: {r['path']} - {r['reason']}")
            elif results["suspicious"]:
                for r in results["suspicious"]:
                    self.alert_signal.emit("MEDIUM", f"USB suspicious: {r['path']} - {r['reason']}")
        except: pass

# ===================== VPN MANAGER =====================
class VPNManager(QtCore.QObject):
    status_signal = QtCore.pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.connected = False
        self.configs_dir = os.path.join(CONFIG_DIR, "vpn_configs")
        os.makedirs(self.configs_dir, exist_ok=True)
        self.process = None
        self._check_openvpn()
    def _check_openvpn(self):
        try:
            r = subprocess.run(["which","openvpn"], capture_output=True, timeout=2)
            self.openvpn_ok = r.returncode == 0
        except: self.openvpn_ok = False
    def is_available(self):
        return self.openvpn_ok
    def get_configs(self):
        configs = []
        if os.path.isdir(self.configs_dir):
            for f in sorted(os.listdir(self.configs_dir)):
                if f.endswith(".ovpn") or f.endswith(".conf"):
                    configs.append(os.path.join(self.configs_dir, f))
        return configs
    def add_config(self, filepath):
        if not os.path.exists(filepath): return False, "File not found"
        dest = os.path.join(self.configs_dir, os.path.basename(filepath))
        shutil.copy2(filepath, dest)
        return True, f"Config added: {os.path.basename(filepath)}"
    def connect(self, config_path):
        if not self.openvpn_ok: return False, "OpenVPN not installed"
        if self.process:
            self.disconnect()
        try:
            logfile = os.path.join(CONFIG_DIR, "vpn.log")
            self.process = subprocess.Popen(
                ["sudo","openvpn","--config",config_path,"--log",logfile],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.connected = True
            self.status_signal.emit(f"Connected: {os.path.basename(config_path)}")
            return True, "Connecting..."
        except Exception as e: return False, str(e)
    def disconnect(self):
        if self.process:
            try: self.process.terminate(); self.process.wait(timeout=5)
            except: self.process.kill()
            self.process = None
        self.connected = False
        self.status_signal.emit("Disconnected")
        return True, "Disconnected"

# ===================== PASSWORD MANAGER =====================
class PasswordManager:
    def __init__(self):
        self.vault_file = os.path.join(CONFIG_DIR, "vault.enc")
        self.master_hash = None
        self.unlocked = False
        self.entries = []
        self._load_vault()
    def _load_vault(self):
        if os.path.exists(self.vault_file):
            try:
                with open(self.vault_file) as f: data = json.load(f)
                self.master_hash = data.get("master_hash")
                self.entries = data.get("entries", [])
            except: pass
    def _save_vault(self):
        with open(self.vault_file, "w") as f:
            json.dump({"master_hash": self.master_hash, "entries": self.entries}, f)
    def set_master_password(self, password):
        self.master_hash = hashlib.sha256(password.encode()).hexdigest()
        self.unlocked = True
        self._save_vault()
        return True
    def unlock(self, password):
        if not self.master_hash: return self.set_master_password(password)
        if hashlib.sha256(password.encode()).hexdigest() == self.master_hash:
            self.unlocked = True
            return True
        return False
    def lock(self):
        self.unlocked = False
    def add_entry(self, site, username, password, notes=""):
        if not self.unlocked: return False
        entry = {"id": uuid.uuid4().hex[:8], "site": site, "username": username,
                 "password": self._encrypt(password), "notes": notes,
                 "created": datetime.now().isoformat()}
        self.entries.append(entry)
        self._save_vault()
        return True
    def get_entry(self, entry_id):
        for e in self.entries:
            if e["id"] == entry_id:
                entry = dict(e)
                entry["password"] = self._decrypt(entry["password"])
                return entry
        return None
    def get_entries(self):
        return [{"id": e["id"], "site": e["site"], "username": e["username"],
                 "created": e.get("created","")} for e in self.entries]
    def delete_entry(self, entry_id):
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        self._save_vault()
    def _encrypt(self, text):
        if not self.master_hash: return text
        key = self.master_hash[:32].encode()
        data = text.encode()
        encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
        return base64.b64encode(encrypted).decode()
    def _decrypt(self, crypt):
        if not self.master_hash: return crypt
        key = self.master_hash[:32].encode()
        encrypted = base64.b64decode(crypt.encode())
        decrypted = bytes([encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted))])
        return decrypted.decode()

# ===================== NETWORK INSPECTOR =====================
class NetworkInspector(QtCore.QObject):
    result_signal = QtCore.pyqtSignal(str, object)
    def __init__(self):
        super().__init__()
        self.scanning = False
    def arp_scan(self, interface=None):
        self.scanning = True
        try:
            import scapy.all as scapy
            if not interface:
                r = subprocess.run(["ip","route"], capture_output=True, text=True, timeout=5)
                for line in r.stdout.split("\n"):
                    if "default" in line:
                        parts = line.split()
                        interface = parts[-1] if len(parts) > 4 else None
                        break
            if not interface: interface = "eth0"
            arp_request = scapy.ARP(pdst="192.168.1.1/24")
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered = scapy.srp(packet, timeout=3, iface=interface, verbose=False)[0]
            devices = []
            for sent, received in answered:
                devices.append({"ip": received.psrc, "mac": received.hwsrc})
            self.result_signal.emit("arp_scan", devices)
            self.scanning = False
            return devices
        except ImportError:
            self.result_signal.emit("error", "scapy not installed")
            self.scanning = False
            return []
        except Exception as e:
            self.result_signal.emit("error", str(e))
            self.scanning = False
            return []
    def router_info(self):
        info = {}
        try:
            r = subprocess.run(["ip","route"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    info["gateway"] = parts[2]
                    if len(parts) > 4: info["interface"] = parts[4]
                    break
        except: pass
        try:
            r = subprocess.run(["ip","addr","show"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.split("\n"):
                m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m and not m.group(1).startswith("127."):
                    info["local_ip"] = m.group(1)
                    info["netmask"] = m.group(2)
                    break
        except: pass
        try:
            r = subprocess.run(["nmcli","-t","-f","NAME,DEVICE,TYPE","connection","show","--active"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                info["connections"] = [l for l in r.stdout.strip().split("\n") if l]
        except: pass
        self.result_signal.emit("router_info", info)
        return info

# ===================== CUSTOM WIDGETS =====================
class SidebarButton(QtWidgets.QPushButton):
    def __init__(self, text, icon_char, parent=None):
        super().__init__(f"  {icon_char}  {text}", parent)
        self.setFixedHeight(44)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton { background: transparent; color: #888; border: none; font-size: 12px;
                          font-family: Consolas; text-align: left; padding-left: 16px; border-radius: 0px; }
            QPushButton:hover { background: rgba(124,77,255,0.15); color: #b388ff; }
            QPushButton:checked { background: rgba(124,77,255,0.25); color: #7c4dff;
                                  border-left: 3px solid #7c4dff; padding-left: 13px; }
        """)
        self.setCheckable(True)

class StatCard(QtWidgets.QFrame):
    def __init__(self, title, icon, color=ACCENT_LIGHT):
        super().__init__()
        self.color = color
        self.setStyleSheet(f"StatCard {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 10px; padding: 10px; }}")
        self.setMinimumSize(130, 80)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 6, 6)
        top = QtWidgets.QHBoxLayout()
        icon_lbl = QtWidgets.QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size: 16px; color: {color}; background: transparent;")
        top.addWidget(icon_lbl)
        title_lbl = QtWidgets.QLabel(title)
        title_lbl.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent;")
        top.addWidget(title_lbl)
        top.addStretch()
        layout.addLayout(top)
        self.value_lbl = QtWidgets.QLabel("--")
        self.value_lbl.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {color}; background: transparent;")
        layout.addWidget(self.value_lbl)
    def set_value(self, val):
        self.value_lbl.setText(str(val))

class ScanWorker(QtCore.QThread):
    finished = QtCore.pyqtSignal(object)
    def __init__(self, engine, path):
        super().__init__()
        self.engine = engine
        self.path = path
    def run(self):
        results = self.engine.scan_path(self.path)
        self.finished.emit(results)

# ===================== MAIN WINDOW =====================
class SplashScreen(QtWidgets.QSplashScreen):
    def __init__(self):
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        pixmap = QtGui.QPixmap(icon_path) if os.path.exists(icon_path) else QtGui.QPixmap(256, 256)
        if not os.path.exists(icon_path):
            pixmap.fill(QtGui.QColor(DARK_BG))
        super().__init__(pixmap)
        self.setStyleSheet(f"color: {TEXT}; background: transparent;")
        self.show()
        self.showMessage(_("app_title"), QtCore.Qt.AlignBottom | QtCore.Qt.AlignCenter,
                         QtGui.QColor(ACCENT_LIGHT))

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.engine = DefendREngine()
        self.netmon = NetworkMonitor()
        self.netmon.alert_signal.connect(self._on_net_alert)
        self.netmon.data_signal.connect(self._on_net_data)
        self.quarantine = QuarantineManager()
        self.rt_protector = RealTimeProtector(self.engine)
        self.rt_protector.alert_signal.connect(self._on_rt_alert)
        self.firewall = FirewallManager()
        self.web_blocker = WebBlocker()
        self.anti_phish = AntiPhishing()
        self.sandbox = SandboxManager()
        self.ransomware = AntiRansomware()
        self.ransomware.alert_signal.connect(self._on_ransomware_alert)
        self.rootkit = RootkitDetector()
        self.rootkit.alert_signal.connect(self._on_rootkit_alert)
        self.scheduler = Scheduler()
        self.scheduler.scan_triggered.connect(self._on_scheduled_scan)
        self.sig_updater = SignatureUpdater(self.engine)
        self.sig_updater.update_signal.connect(self._on_update_status)
        self.game_mode = GameMode()
        self.game_mode.mode_changed.connect(self._on_game_mode)
        self.usb_scanner = USBScanner(self.engine)
        self.usb_scanner.scan_signal.connect(self._on_usb_scan)
        self.usb_scanner.alert_signal.connect(self._on_usb_alert)
        self.vpn = VPNManager()
        self.pwd_mgr = PasswordManager()
        self.net_inspector = NetworkInspector()
        self.net_inspector.result_signal.connect(self._on_inspect_result)
        self.wifi_inspector = WiFiInspector()
        self.wifi_inspector.result_signal.connect(self._on_wifi_result)
        self.wifi_inspector.device_signal.connect(self._on_wifi_device)
        self.shredder = DataShredder()
        self.shredder.progress_signal.connect(self._on_shred_progress)
        self.shredder.done_signal.connect(self._on_shred_done)
        self.soft_updater = SoftwareUpdater()
        self.soft_updater.update_signal.connect(self._on_soft_update)
        self.soft_updater.progress_signal.connect(self._on_soft_progress)
        self.webcam_protector = WebcamProtector()
        self.webcam_protector.alert_signal.connect(self._on_webcam_alert)
        self.webcam_protector.block_signal.connect(self._on_webcam_block)
        self.dns_over_https = DNSOverHTTPS()
        self.cleanup_mgr = CleanupManager()
        self.cleanup_mgr.progress_signal.connect(self._on_cleanup_progress)
        self.cleanup_mgr.done_signal.connect(self._on_cleanup_done)
        self.cleanup_mgr.preview_signal.connect(self._on_cleanup_preview)

        self.setWindowTitle(_("DefendR - Advanced Protection"))
        self.setMinimumSize(1200, 750)
        self.resize(1300, 800)
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        if os.path.exists(icon_path): self.setWindowIcon(QtGui.QIcon(icon_path))

        self._setup_ui()
        self._setup_tray()
        self._start_monitors()

    def closeEvent(self, event):
        if self.game_mode.suppress_notifications():
            event.accept()
            return
        event.ignore()
        self.hide()
        self.tray.showMessage("DefendR", _("Protecao continua ativa em segundo plano"),
                              QtWidgets.QSystemTrayIcon.Information, 2000)

    def _setup_tray(self):
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        icon = QtGui.QIcon(icon_path) if os.path.exists(icon_path) else QtGui.QIcon()
        self.tray = QtWidgets.QSystemTrayIcon(icon, self)
        self.tray.setToolTip(_("Protected by DefendR"))
        menu = QtWidgets.QMenu()
        show_action = menu.addAction(_("Open DefendR"))
        show_action.triggered.connect(self.show)
        menu.addSeparator()
        self.tray_status = menu.addAction(_("Protected by DefendR"))
        self.tray_status.setEnabled(False)
        menu.addSeparator()
        self.tray_game = menu.addAction("🎮  " + _("Game Mode") + ": OFF")
        self.tray_game.triggered.connect(self._toggle_game_mode_tray)
        menu.addSeparator()
        quit_action = menu.addAction(_("Quit"))
        quit_action.triggered.connect(self._quit_app)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda r: self.show() if r == QtWidgets.QSystemTrayIcon.DoubleClick else None)
        self.tray.show()

    def _toggle_game_mode_tray(self):
        if self.game_mode.active:
            self.game_mode.active = False
            self.tray_game.setText("🎮  Game Mode: OFF")
        else:
            self.game_mode.active = True
            self.tray_game.setText("🎮  Game Mode: ON")

    def _tray_clicked(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.DoubleClick:
            self.show(); self.raise_(); self.activateWindow()

    def _quit_app(self):
        self.netmon.stop(); self.rt_protector.stop(); self.ransomware.stop()
        self.usb_scanner.stop(); self.game_mode.stop(); self.webcam_protector.stop()
        self.engine.scanning = False
        self.monitor_timer.stop()
        self.hide(); self.tray.hide()
        QtCore.QTimer.singleShot(100, QtWidgets.QApplication.quit)

    def _switch_page(self, key):
        pages = {"dashboard":0,"scanner":1,"realtime":2,"firewall":3,"network":4,
                 "processes":5,"quarantine":6,"tools":7,"settings":8}
        idx = pages.get(key, 0)
        self.content_stack.setCurrentIndex(idx)
        if key == "network": self._update_dns()

    # ===================== UI SETUP =====================
    def _setup_ui(self):
        self.setStyleSheet(f"QMainWindow {{ background: {DARK_BG}; }} QToolTip {{ background: {DARK_CARD}; color: {TEXT}; border: 1px solid {BORDER}; font-size: 12px; }}")
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QHBoxLayout(central)
        main_layout.setContentsMargins(0,0,0,0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QtWidgets.QFrame()
        sidebar.setFixedWidth(190)
        sidebar.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {DARK_MID}, stop:1 {DARK_BG}); border-right: 1px solid {BORDER};")
        sidebar_layout = QtWidgets.QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0,0,0,0)
        sidebar_layout.setSpacing(0)

        # Logo
        logo_frame = QtWidgets.QFrame()
        logo_frame.setStyleSheet("background: transparent;")
        logo_frame.setMinimumHeight(80)
        logo_layout = QtWidgets.QVBoxLayout(logo_frame)
        logo_layout.setAlignment(QtCore.Qt.AlignCenter)
        logo_icon = QtWidgets.QLabel("⚔")
        logo_icon.setStyleSheet(f"font-size: 30px; color: {ACCENT_LIGHT}; background: transparent;")
        logo_icon.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(logo_icon)
        logo_text = QtWidgets.QLabel("DefendR")
        logo_text.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {ACCENT_LIGHT}; background: transparent; letter-spacing: 2px;")
        logo_text.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(logo_text)
        ver_text = QtWidgets.QLabel("v2.0")
        ver_text.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent;")
        ver_text.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(ver_text)
        sidebar_layout.addWidget(logo_frame)

        # Nav buttons
        self.nav_btns = []
        nav_items = [
            ("dashboard","📊","Dashboard"),
            ("scanner","🔍","Scanner"),
            ("realtime","🛡","Real-Time"),
            ("firewall","🔒","Firewall"),
            ("network","🌐","Network"),
            ("processes","⚙","Processes"),
            ("quarantine","📦","Quarantine"),
            ("tools","🧰","Tools"),
            ("settings","🔧","Settings"),
        ]
        nav_group = QtWidgets.QButtonGroup()
        for key, icon, label in nav_items:
            btn = SidebarButton(label, icon)
            btn.clicked.connect(lambda checked, k=key: self._switch_page(k))
            nav_group.addButton(btn)
            sidebar_layout.addWidget(btn)
            self.nav_btns.append(btn)
        sidebar_layout.addStretch()

        # Protection status
        self.protect_frame = QtWidgets.QFrame()
        self.protect_frame.setStyleSheet("background: transparent; padding: 8px;")
        pf_layout = QtWidgets.QVBoxLayout(self.protect_frame)
        self.protect_indicator = QtWidgets.QLabel("●  Protected")
        self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {GREEN}; background: transparent;")
        self.protect_indicator.setAlignment(QtCore.Qt.AlignCenter)
        pf_layout.addWidget(self.protect_indicator)
        self.protect_count = QtWidgets.QLabel("0 threats blocked")
        self.protect_count.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent;")
        self.protect_count.setAlignment(QtCore.Qt.AlignCenter)
        pf_layout.addWidget(self.protect_count)
        sidebar_layout.addWidget(self.protect_frame)
        main_layout.addWidget(sidebar)

        # Content
        self.content_stack = QtWidgets.QStackedWidget()
        self.content_stack.setStyleSheet(f"background: {DARK_BG};")
        main_layout.addWidget(self.content_stack, 1)

        self._build_dashboard()
        self._build_scanner()
        self._build_realtime()
        self._build_firewall()
        self._build_network()
        self._build_processes()
        self._build_quarantine()
        self._build_tools()
        self._build_settings()

        self.nav_btns[0].setChecked(True)

    def _page_widget(self):
        w = QtWidgets.QWidget()
        w.setStyleSheet(f"background: {DARK_BG};")
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(16,16,16,16)
        layout.setSpacing(10)
        return w, layout

    def _page_header(self, layout, title, subtitle=""):
        h = QtWidgets.QLabel(title)
        h.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {ACCENT_LIGHT}; background: transparent;")
        layout.addWidget(h)
        if subtitle:
            s = QtWidgets.QLabel(subtitle)
            s.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
            layout.addWidget(s)

    def _btn(self, text, handler, color=ACCENT):
        btn = QtWidgets.QPushButton(text)
        btn.setCursor(QtCore.Qt.PointingHandCursor)
        btn.setStyleSheet(f"QPushButton {{ background: {color}; color: white; border: none; border-radius: 5px; padding: 7px 16px; font-size: 11px; font-family: Consolas; }} QPushButton:hover {{ background: {ACCENT_DARK}; }}")
        btn.clicked.connect(handler)
        return btn

    # ===== DASHBOARD =====
    def _build_dashboard(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("nav_dashboard"), "System overview and real-time protection status")
        # Stats
        stats_frame = QtWidgets.QWidget()
        stats_frame.setStyleSheet("background: transparent;")
        stats_layout = QtWidgets.QHBoxLayout(stats_frame)
        stats_layout.setSpacing(10)
        self.stat_cards = {}
        stat_defs = [
            ("cpu","🖥","CPU",ACCENT_LIGHT),("mem","💾","Memory",CYAN),
            ("procs","⚙","Processes",YELLOW),("alerts","🚨","Alerts",RED),
            ("scanned","📁","Scanned",GREEN),("threats","🛡","Threats",ACCENT),
        ]
        for key, icon, label, color in stat_defs:
            card = StatCard(label, icon, color)
            stats_layout.addWidget(card)
            self.stat_cards[key] = card
        layout.addWidget(stats_frame)

        # Quick actions row
        action_frame = QtWidgets.QWidget()
        action_frame.setStyleSheet("background: transparent;")
        action_layout = QtWidgets.QHBoxLayout(action_frame)
        action_layout.setSpacing(8)
        for text, handler in [("🔍 Quick Scan", lambda: self._switch_page("scanner")),
                               ("🛡 Firewall", lambda: self._switch_page("firewall")),
                               ("📦 Quarantine", lambda: self._switch_page("quarantine")),
                               ("🔧 Update Signatures", self._manual_update)]:
            action_layout.addWidget(self._btn(text, handler))
        action_layout.addStretch()
        layout.addWidget(action_frame)

        # Alerts
        alert_frame = QtWidgets.QFrame()
        alert_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        alert_layout = QtWidgets.QVBoxLayout(alert_frame)
        alert_header = QtWidgets.QLabel("📋  Security Events")
        alert_header.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {ACCENT_LIGHT}; background: transparent;")
        alert_layout.addWidget(alert_header)
        self.alert_list = QtWidgets.QListWidget()
        self.alert_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 6px; color: {TEXT}; font-size: 11px; }} QListWidget::item {{ padding: 5px 8px; border-bottom: 1px solid {DARK_MID}; }}")
        alert_layout.addWidget(self.alert_list)
        layout.addWidget(alert_frame, 1)
        self.content_stack.addWidget(w)

    # ===== SCANNER =====
    def _build_scanner(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔍  File Scanner"), "Scan files/directories, USB auto-scan, scheduled scans")
        btn_frame = QtWidgets.QWidget()
        btn_frame.setStyleSheet("background: transparent;")
        btn_layout = QtWidgets.QHBoxLayout(btn_frame)
        for text, handler in [("📁 Scan File", self._scan_file),("📂 Scan Folder", self._scan_dir),
                               ("⏹ Stop", self._stop_scan),("🗑 Clear", self._clear_scan),
                               ("📀 Scan USB", self._scan_usb_manual)]:
            btn_layout.addWidget(self._btn(text, handler))
        btn_layout.addStretch()
        layout.addWidget(btn_frame)

        self.scan_progress = QtWidgets.QProgressBar()
        self.scan_progress.setStyleSheet(f"QProgressBar {{ background: {DARK_MID}; border: 1px solid {BORDER}; border-radius: 6px; height: 16px; text-align: center; font-size: 10px; color: {TEXT}; }} QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {ACCENT_LIGHT}); border-radius: 5px; }}")
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)
        self.scan_status = QtWidgets.QLabel("Ready")
        self.scan_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        layout.addWidget(self.scan_status)

        self.scan_tree = QtWidgets.QTreeWidget()
        self.scan_tree.setHeaderLabels(["Risk","File","Reason"])
        self.scan_tree.setColumnWidth(0,90); self.scan_tree.setColumnWidth(2,250)
        self.scan_tree.setStyleSheet(f"QTreeWidget {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px; color: {TEXT}; font-size: 11px; }} QTreeWidget::item {{ padding: 3px; border-bottom: 1px solid {DARK_MID}; }} QHeaderView::section {{ background: {DARK_MID}; color: {ACCENT_LIGHT}; border: none; padding: 5px; font-size: 11px; }}")
        layout.addWidget(self.scan_tree, 1)
        self.content_stack.addWidget(w)

    # ===== REAL-TIME =====
    def _build_realtime(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🛡  Real-Time Protection"), "File system monitoring + Anti-Ransomware + Web Blocker + Anti-Phishing")

        # RT toggle
        rt_frame = QtWidgets.QFrame()
        rt_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        rt_l = QtWidgets.QVBoxLayout(rt_frame)
        rt_l.addWidget(QtWidgets.QLabel("File System Monitor"))
        self.rt_toggle = self._btn(_("▶ Start Real-Time Protection"), self._toggle_rt)
        rt_l.addWidget(self.rt_toggle)
        self.rt_status = QtWidgets.QLabel(_("Status: Stopped"))
        self.rt_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        rt_l.addWidget(self.rt_status)
        layout.addWidget(rt_frame)

        # Ransomware
        rw_frame = QtWidgets.QFrame()
        rw_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        rw_l = QtWidgets.QVBoxLayout(rw_frame)
        rw_l.addWidget(QtWidgets.QLabel("Anti-Ransomware"))
        self.rw_toggle = self._btn(_("▶ Start Ransomware Detection"), self._toggle_rw)
        rw_l.addWidget(self.rw_toggle)
        self.rw_status = QtWidgets.QLabel(_("Status: Stopped"))
        self.rw_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        rw_l.addWidget(self.rw_status)
        layout.addWidget(rw_frame)

        # Webcam Protection
        wc_frame = QtWidgets.QFrame()
        wc_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        wc_l = QtWidgets.QVBoxLayout(wc_frame)
        wc_l.addWidget(QtWidgets.QLabel("Webcam Protection"))
        wc_l.addWidget(QtWidgets.QLabel("Monitors /dev/video* for unauthorized access"))
        wc_btn_row = QtWidgets.QHBoxLayout()
        self.wc_toggle = self._btn(_("▶ Start Webcam Monitor"), self._toggle_webcam)
        wc_btn_row.addWidget(self.wc_toggle)
        self.wc_block_btn = self._btn(_("🔴 Block Webcam"), self._webcam_block_device)
        wc_btn_row.addWidget(self.wc_block_btn)
        self.wc_unblock_btn = self._btn(_("🟢 Unblock Webcam"), self._webcam_unblock_device)
        wc_btn_row.addWidget(self.wc_unblock_btn)
        wc_l.addLayout(wc_btn_row)
        self.wc_status = QtWidgets.QLabel(_("Status: Stopped"))
        self.wc_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        wc_l.addWidget(self.wc_status)
        self.wc_list = QtWidgets.QListWidget()
        self.wc_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; max-height: 80px; }}")
        wc_l.addWidget(self.wc_list)
        layout.addWidget(wc_frame)

        # Web Blocker
        wb_frame = QtWidgets.QFrame()
        wb_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        wb_l = QtWidgets.QVBoxLayout(wb_frame)
        wb_l.addWidget(QtWidgets.QLabel("Web Blocker (hosts file)"))
        wb_input_row = QtWidgets.QHBoxLayout()
        self.wb_input = QtWidgets.QLineEdit()
        self.wb_input.setPlaceholderText("domain.com")
        self.wb_input.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; padding: 5px;")
        wb_input_row.addWidget(self.wb_input)
        wb_input_row.addWidget(self._btn(_("Block"), self._web_block))
        wb_input_row.addWidget(self._btn(_("Unblock"), self._web_unblock))
        wb_l.addLayout(wb_input_row)
        self.wb_list = QtWidgets.QListWidget()
        self.wb_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; max-height: 120px; }}")
        wb_l.addWidget(self.wb_list)
        self._refresh_web_block()
        layout.addWidget(wb_frame)

        # Anti-Phishing
        ap_frame = QtWidgets.QFrame()
        ap_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        ap_l = QtWidgets.QVBoxLayout(ap_frame)
        ap_l.addWidget(QtWidgets.QLabel("Anti-Phishing URL Checker"))
        url_row = QtWidgets.QHBoxLayout()
        self.ap_input = QtWidgets.QLineEdit()
        self.ap_input.setPlaceholderText("https://suspeitosite.com")
        self.ap_input.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; padding: 5px;")
        url_row.addWidget(self.ap_input)
        url_row.addWidget(self._btn(_("Check URL"), self._check_phishing))
        ap_l.addLayout(url_row)
        self.ap_result = QtWidgets.QLabel("")
        self.ap_result.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        self.ap_result.setWordWrap(True)
        ap_l.addWidget(self.ap_result)
        layout.addWidget(ap_frame)

        # RT alerts
        rt_alert_frame = QtWidgets.QFrame()
        rt_alert_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        rt_al = QtWidgets.QVBoxLayout(rt_alert_frame)
        rt_al.addWidget(QtWidgets.QLabel("📋  Protection Alerts"))
        self.rt_alerts = QtWidgets.QListWidget()
        self.rt_alerts.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; }} QListWidget::item {{ padding: 4px 6px; border-bottom: 1px solid {DARK_MID}; }}")
        rt_al.addWidget(self.rt_alerts)
        layout.addWidget(rt_alert_frame, 1)
        self.content_stack.addWidget(w)

    # ===== FIREWALL =====
    def _build_firewall(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔒  Firewall"), "iptables-based firewall management")
        if not self.firewall.is_available():
            layout.addWidget(QtWidgets.QLabel("⚠ iptables not available. Run with sudo."))
            self.content_stack.addWidget(w); return

        fw_frame = QtWidgets.QFrame()
        fw_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        fw_l = QtWidgets.QVBoxLayout(fw_frame)
        fw_l.addWidget(QtWidgets.QLabel("Firewall Control"))
        fw_btn_row = QtWidgets.QHBoxLayout()
        fw_btn_row.addWidget(self._btn(_("🛡 Enable Firewall"), self._fw_enable))
        fw_btn_row.addWidget(self._btn(_("Disable Firewall"), self._fw_disable))
        fw_btn_row.addWidget(self._btn(_("🔄 Flush Rules"), self._fw_flush))
        fw_l.addLayout(fw_btn_row)
        self.fw_status = QtWidgets.QLabel("Firewall: Disabled")
        self.fw_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        fw_l.addWidget(self.fw_status)
        layout.addWidget(fw_frame)

        # Port blocking
        port_frame = QtWidgets.QFrame()
        port_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        port_l = QtWidgets.QVBoxLayout(port_frame)
        port_l.addWidget(QtWidgets.QLabel("Port Management"))
        port_row = QtWidgets.QHBoxLayout()
        self.port_input = QtWidgets.QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g. 4444)")
        self.port_input.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; padding: 5px; max-width: 100px;")
        port_row.addWidget(self.port_input)
        port_row.addWidget(self._btn(_("Block Port"), self._fw_block_port))
        port_row.addWidget(self._btn(_("Allow Port"), self._fw_allow_port))
        port_l.addLayout(port_row)
        layout.addWidget(port_frame)

        # Rules display
        rules_frame = QtWidgets.QFrame()
        rules_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        rules_l = QtWidgets.QVBoxLayout(rules_frame)
        rules_l.addWidget(QtWidgets.QLabel("Current Rules"))
        self.fw_rules = QtWidgets.QListWidget()
        self.fw_rules.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; font-family: monospace; }} QListWidget::item {{ padding: 3px 6px; }}")
        rules_l.addWidget(self.fw_rules)
        rules_l.addWidget(self._btn(_("🔄 Refresh Rules"), self._fw_refresh))
        layout.addWidget(rules_frame, 1)
        self.content_stack.addWidget(w)

    # ===== NETWORK =====
    def _build_network(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🌐  Network"), "Monitor + Inspector + VPN")
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px; }} QTabBar::tab {{ background: {DARK_MID}; color: {TEXT_DIM}; padding: 6px 14px; border: 1px solid {BORDER}; border-bottom: none; border-radius: 4px 4px 0 0; font-size: 11px; }} QTabBar::tab:selected {{ background: {DARK_CARD}; color: {ACCENT_LIGHT}; }}")

        # Tab 1: Network Monitor
        mon_w = QtWidgets.QWidget()
        mon_l = QtWidgets.QVBoxLayout(mon_w)
        toggle_frame = QtWidgets.QWidget()
        toggle_frame.setStyleSheet("background: transparent;")
        toggle_layout = QtWidgets.QHBoxLayout(toggle_frame)
        self.net_status = QtWidgets.QLabel("●  Monitoring: OFF")
        self.net_status.setStyleSheet(f"font-size: 13px; color: {TEXT_DIM}; background: transparent;")
        toggle_layout.addWidget(self.net_status)
        self.net_toggle = self._btn(_("▶ Start"), self._toggle_net)
        toggle_layout.addWidget(self.net_toggle)
        toggle_layout.addStretch()
        mon_l.addWidget(toggle_frame)

        info_frame = QtWidgets.QWidget()
        info_frame.setStyleSheet("background: transparent;")
        info_layout = QtWidgets.QHBoxLayout(info_frame)
        info_layout.setSpacing(10)
        # ARP
        arp_card = QtWidgets.QFrame()
        arp_card.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        arp_l = QtWidgets.QVBoxLayout(arp_card)
        arp_l.addWidget(QtWidgets.QLabel("ARP Table"))
        self.arp_table = QtWidgets.QTableWidget(0,3)
        self.arp_table.setHorizontalHeaderLabels(["IP","MAC","Interface"])
        self.arp_table.setStyleSheet(f"QTableWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; }} QHeaderView::section {{ background: {DARK_MID}; color: {ACCENT_LIGHT}; border: none; padding: 3px; }}")
        self.arp_table.horizontalHeader().setStretchLastSection(True)
        arp_l.addWidget(self.arp_table)
        info_layout.addWidget(arp_card)
        # DNS
        dns_card = QtWidgets.QFrame()
        dns_card.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        dns_l = QtWidgets.QVBoxLayout(dns_card)
        dns_l.addWidget(QtWidgets.QLabel("DNS Servers"))
        self.dns_label = QtWidgets.QLabel("Loading...")
        self.dns_label.setStyleSheet(f"font-size: 11px; color: {TEXT}; background: transparent; padding: 6px;")
        self.dns_label.setWordWrap(True)
        dns_l.addWidget(self.dns_label)
        info_layout.addWidget(dns_card)
        # Conns
        conn_card = QtWidgets.QFrame()
        conn_card.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        conn_l = QtWidgets.QVBoxLayout(conn_card)
        conn_l.addWidget(QtWidgets.QLabel("Active Connections"))
        self.conn_label = QtWidgets.QLabel("--")
        self.conn_label.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {ACCENT}; background: transparent;")
        self.conn_label.setAlignment(QtCore.Qt.AlignCenter)
        conn_l.addWidget(self.conn_label)
        info_layout.addWidget(conn_card)
        mon_l.addWidget(info_frame)

        net_alert_frame = QtWidgets.QFrame()
        net_alert_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        net_al = QtWidgets.QVBoxLayout(net_alert_frame)
        net_al.addWidget(QtWidgets.QLabel("🚨  Network Alerts"))
        self.net_alerts = QtWidgets.QListWidget()
        self.net_alerts.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; }} QListWidget::item {{ padding: 4px 6px; border-bottom: 1px solid {DARK_MID}; }}")
        net_al.addWidget(self.net_alerts)
        mon_l.addWidget(net_alert_frame, 1)
        tabs.addTab(mon_w, "Monitor")

        # Tab 2: Network Inspector
        ins_w = QtWidgets.QWidget()
        ins_l = QtWidgets.QVBoxLayout(ins_w)
        ins_l.addWidget(self._btn(_("🔍 ARP Scan Network"), self._arp_scan))
        ins_l.addWidget(self._btn(_("📡 Router Info"), self._router_info))
        self.inspector_results = QtWidgets.QPlainTextEdit()
        self.inspector_results.setReadOnly(True)
        self.inspector_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; font-size: 11px; font-family: monospace; padding: 6px;")
        ins_l.addWidget(self.inspector_results, 1)
        tabs.addTab(ins_w, "Inspector")

        # Tab 3: WiFi Inspector
        wifi_w = QtWidgets.QWidget()
        wifi_l = QtWidgets.QVBoxLayout(wifi_w)
        wifi_btn_row = QtWidgets.QHBoxLayout()
        wifi_btn_row.addWidget(self._btn(_("📡 Scan Router"), self._wifi_scan))
        self.wifi_monitor_btn = self._btn(_("▶ Start Continuous Monitor"), self._wifi_start_monitor)
        wifi_btn_row.addWidget(self.wifi_monitor_btn)
        wifi_l.addLayout(wifi_btn_row)
        wifi_l.addWidget(QtWidgets.QLabel("Scans router for open ports and security issues"))
        self.wifi_results = QtWidgets.QPlainTextEdit()
        self.wifi_results.setReadOnly(True)
        self.wifi_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; font-size: 11px; font-family: monospace; padding: 6px;")
        wifi_l.addWidget(self.wifi_results, 1)
        self.wifi_device_list = QtWidgets.QListWidget()
        self.wifi_device_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; max-height: 100px; }}")
        wifi_l.addWidget(self.wifi_device_list)
        tabs.addTab(wifi_w, "WiFi Inspector")

        # Tab 4: VPN
        vpn_w = QtWidgets.QWidget()
        vpn_l = QtWidgets.QVBoxLayout(vpn_w)
        if self.vpn.is_available():
            vpn_l.addWidget(QtWidgets.QLabel("OpenVPN Manager"))
            vpn_btn_row = QtWidgets.QHBoxLayout()
            vpn_btn_row.addWidget(self._btn(_("📂 Add Config"), self._vpn_add))
            vpn_btn_row.addWidget(self._btn(_("▶ Connect"), self._vpn_connect))
            vpn_btn_row.addWidget(self._btn(_("⏹ Disconnect"), self._vpn_disconnect))
            vpn_l.addLayout(vpn_btn_row)
            self.vpn_status = QtWidgets.QLabel("VPN: Disconnected")
            self.vpn_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
            vpn_l.addWidget(self.vpn_status)
            self.vpn_list = QtWidgets.QListWidget()
            self.vpn_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 11px; }}")
            vpn_l.addWidget(self.vpn_list, 1)
            self._refresh_vpn_list()
        else:
            vpn_l.addWidget(QtWidgets.QLabel("⚠ OpenVPN not installed. Run: sudo apt install openvpn"))
        tabs.addTab(vpn_w, "VPN")

        # Tab 5: DNS over HTTPS
        dns_w = QtWidgets.QWidget()
        dns_l = QtWidgets.QVBoxLayout(dns_w)
        dns_l.addWidget(QtWidgets.QLabel("DNS-over-HTTPS Configuration"))
        for provider_name in self.dns_over_https.providers:
            btn = self._btn(f"Set {provider_name}", lambda p=provider_name: self._dns_set(p))
            dns_l.addWidget(btn)
        dns_l.addWidget(self._btn(_("Reset to Default"), self._dns_reset))
        self.dns_status = QtWidgets.QLabel(f"Current: {', '.join(self.dns_over_https.get_current_dns())}")
        self.dns_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent; padding: 6px;")
        self.dns_status.setWordWrap(True)
        dns_l.addWidget(self.dns_status)
        dns_l.addWidget(self._btn(_("🔒 Enable DNSSEC"), self._dns_enable_dnssec))
        dns_l.addStretch()
        tabs.addTab(dns_w, "DNS")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(w)

    # ===== PROCESSES =====
    def _build_processes(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("⚙  Process Monitor"), "Monitor running processes for suspicious activity")
        btn_frame = QtWidgets.QWidget()
        btn_frame.setStyleSheet("background: transparent;")
        btn_layout = QtWidgets.QHBoxLayout(btn_frame)
        btn_layout.addWidget(self._btn(_("🔄 Refresh"), self._refresh_procs))
        btn_layout.addStretch()
        layout.addWidget(btn_frame)
        self.proc_table = QtWidgets.QTableWidget(0,6)
        self.proc_table.setHorizontalHeaderLabels(["PID","Name","CPU%","MEM%","Conns","Status"])
        self.proc_table.setStyleSheet(f"QTableWidget {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px; color: {TEXT}; font-size: 11px; }} QHeaderView::section {{ background: {DARK_MID}; color: {ACCENT_LIGHT}; border: none; padding: 4px; font-size: 11px; }} QTableWidget::item {{ padding: 3px; }}")
        self.proc_table.setAlternatingRowColors(True)
        self.proc_table.setStyleSheet(self.proc_table.styleSheet()+f"\nQTableWidget{{alternate-background-color:{DARK_MID};}}")
        self.proc_table.horizontalHeader().setStretchLastSection(True)
        self.proc_table.setColumnWidth(0,60); self.proc_table.setColumnWidth(1,180)
        self.proc_table.setColumnWidth(2,60); self.proc_table.setColumnWidth(3,60); self.proc_table.setColumnWidth(4,60)
        layout.addWidget(self.proc_table, 1)
        self.content_stack.addWidget(w)

    # ===== QUARANTINE =====
    def _build_quarantine(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("📦  Quarantine"), "View and manage quarantined files")
        q_btn_frame = QtWidgets.QWidget()
        q_btn_frame.setStyleSheet("background: transparent;")
        q_btn_l = QtWidgets.QHBoxLayout(q_btn_frame)
        q_btn_l.addWidget(self._btn(_("🔄 Refresh"), self._refresh_quarantine))
        q_btn_l.addWidget(self._btn(_("🗑 Delete All"), self._quarantine_delete_all))
        q_btn_l.addStretch()
        layout.addWidget(q_btn_frame)

        self.q_table = QtWidgets.QTableWidget(0,5)
        self.q_table.setHorizontalHeaderLabels(["ID","Original Path","Date","Size","Actions"])
        self.q_table.setStyleSheet(f"QTableWidget {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px; color: {TEXT}; font-size: 11px; }} QHeaderView::section {{ background: {DARK_MID}; color: {ACCENT_LIGHT}; border: none; padding: 4px; }} QPushButton {{ background: {ACCENT}; color: white; border: none; border-radius: 3px; padding: 3px 8px; font-size: 10px; }}")
        self.q_table.horizontalHeader().setStretchLastSection(True)
        self.q_table.setColumnWidth(0,100); self.q_table.setColumnWidth(1,250); self.q_table.setColumnWidth(2,140); self.q_table.setColumnWidth(3,60)
        layout.addWidget(self.q_table, 1)
        self._refresh_quarantine()
        self.content_stack.addWidget(w)

    # ===== TOOLS =====
    def _build_tools(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🧰  Tools"), "Sandbox, Rootkit Detection, Password Manager, Scheduler")
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px; }} QTabBar::tab {{ background: {DARK_MID}; color: {TEXT_DIM}; padding: 6px 14px; border: 1px solid {BORDER}; border-bottom: none; border-radius: 4px 4px 0 0; font-size: 11px; }} QTabBar::tab:selected {{ background: {DARK_CARD}; color: {ACCENT_LIGHT}; }}")

        # Sandbox
        sand_w = QtWidgets.QWidget()
        sand_l = QtWidgets.QVBoxLayout(sand_w)
        if self.sandbox.available:
            sand_l.addWidget(QtWidgets.QLabel(f"Sandbox: {self.sandbox.sandbox_type} available"))
            sand_row = QtWidgets.QHBoxLayout()
            sand_row.addWidget(self._btn(_("📁 Select File & Run"), self._sandbox_run))
            sand_l.addLayout(sand_row)
        else:
            sand_l.addWidget(QtWidgets.QLabel("⚠ No sandbox tool found. Install firejail: sudo apt install firejail"))
        tabs.addTab(sand_w, "Sandbox")

        # Rootkit
        rk_w = QtWidgets.QWidget()
        rk_l = QtWidgets.QVBoxLayout(rk_w)
        rk_l.addWidget(self._btn(_("🔍 Run Rootkit Scan"), self._rootkit_scan))
        self.rk_results = QtWidgets.QPlainTextEdit()
        self.rk_results.setReadOnly(True)
        self.rk_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; font-size: 11px; font-family: monospace; padding: 6px;")
        rk_l.addWidget(self.rk_results, 1)
        tabs.addTab(rk_w, "Rootkit Detector")

        # Password Manager
        pwd_w = QtWidgets.QWidget()
        pwd_l = QtWidgets.QVBoxLayout(pwd_w)
        pwd_top = QtWidgets.QHBoxLayout()
        self.pwd_unlock_btn = self._btn(_("🔓 Unlock Vault"), self._pwd_unlock)
        pwd_top.addWidget(self.pwd_unlock_btn)
        pwd_top.addWidget(self._btn(_("🔒 Lock"), self._pwd_lock))
        pwd_top.addStretch()
        pwd_l.addLayout(pwd_top)

        pwd_form = QtWidgets.QFrame()
        pwd_form.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px;")
        pwd_form_l = QtWidgets.QVBoxLayout(pwd_form)
        pwd_form_l.addWidget(QtWidgets.QLabel("New Entry"))
        fg = QtWidgets.QGridLayout()
        fg.addWidget(QtWidgets.QLabel("Site:"),0,0); self.pwd_site = QtWidgets.QLineEdit(); fg.addWidget(self.pwd_site,0,1)
        fg.addWidget(QtWidgets.QLabel("User:"),1,0); self.pwd_user = QtWidgets.QLineEdit(); fg.addWidget(self.pwd_user,1,1)
        fg.addWidget(QtWidgets.QLabel("Pass:"),2,0); self.pwd_pass = QtWidgets.QLineEdit(); fg.addWidget(self.pwd_pass,2,1)
        self.pwd_site.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:3px;padding:4px;")
        self.pwd_user.setStyleSheet(self.pwd_site.styleSheet()); self.pwd_pass.setStyleSheet(self.pwd_site.styleSheet())
        pwd_form_l.addLayout(fg)
        pwd_form_l.addWidget(self._btn(_("💾 Save Entry"), self._pwd_add))
        pwd_l.addWidget(pwd_form)
        self.pwd_list = QtWidgets.QListWidget()
        self.pwd_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 11px; }}")
        pwd_l.addWidget(self.pwd_list, 1)
        self._refresh_pwd()
        tabs.addTab(pwd_w, "Password Manager")

        # Scheduler
        sched_w = QtWidgets.QWidget()
        sched_l = QtWidgets.QVBoxLayout(sched_w)
        sched_l.addWidget(QtWidgets.QLabel("Scheduled Scans"))
        sched_form = QtWidgets.QHBoxLayout()
        self.sched_name = QtWidgets.QLineEdit(); self.sched_name.setPlaceholderText("Name")
        self.sched_path = QtWidgets.QLineEdit(); self.sched_path.setPlaceholderText("Path to scan")
        self.sched_hours = QtWidgets.QSpinBox(); self.sched_hours.setRange(1,168); self.sched_hours.setValue(24); self.sched_hours.setPrefix("Every "); self.sched_hours.setSuffix("h")
        for wgt in [self.sched_name, self.sched_path, self.sched_hours]:
            wgt.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:3px;padding:4px;")
        sched_form.addWidget(self.sched_name)
        sched_form.addWidget(self.sched_path)
        sched_form.addWidget(self.sched_hours)
        sched_form.addWidget(self._btn(_("➕ Add"), self._sched_add))
        sched_l.addLayout(sched_form)
        self.sched_list = QtWidgets.QListWidget()
        self.sched_list.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 11px; }}")
        sched_l.addWidget(self.sched_list, 1)
        sched_l.addWidget(self._btn(_("🔄 Refresh"), self._sched_refresh))
        self._sched_refresh()
        tabs.addTab(sched_w, "Scheduler")

        # Data Shredder
        shred_w = QtWidgets.QWidget()
        shred_l = QtWidgets.QVBoxLayout(shred_w)
        shred_l.addWidget(QtWidgets.QLabel("Secure File Shredder"))
        shred_l.addWidget(QtWidgets.QLabel("Overwrites files with random data before deletion"))
        shred_row = QtWidgets.QHBoxLayout()
        shred_row.addWidget(self._btn(_("📁 Shred File"), self._shred_file))
        shred_row.addWidget(self._btn(_("📂 Shred Folder"), self._shred_folder))
        shred_l.addLayout(shred_row)
        std_row = QtWidgets.QHBoxLayout()
        std_row.addWidget(QtWidgets.QLabel("Standard:"))
        self.shred_standard = QtWidgets.QComboBox()
        for key in self.shredder.standards:
            self.shred_standard.addItem(key, key)
        self.shred_standard.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:3px;padding:3px;")
        self.shred_standard.currentIndexChanged.connect(self._shred_standard_changed)
        std_row.addWidget(self.shred_standard)
        std_row.addWidget(self._btn(_("🧹 Wipe Free Space"), self._shred_free_space))
        shred_l.addLayout(std_row)
        self.shred_progress = QtWidgets.QProgressBar()
        self.shred_progress.setStyleSheet(f"QProgressBar {{ background: {DARK_MID}; border: 1px solid {BORDER}; border-radius: 4px; height: 14px; }} QProgressBar::chunk {{ background: {RED}; border-radius: 3px; }}")
        self.shred_progress.hide()
        shred_l.addWidget(self.shred_progress)
        self.shred_status = QtWidgets.QLabel("")
        self.shred_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        shred_l.addWidget(self.shred_status)
        shred_l.addStretch()
        tabs.addTab(shred_w, "Shredder")

        # Cleanup
        clean_w = QtWidgets.QWidget()
        clean_l = QtWidgets.QVBoxLayout(clean_w)
        clean_l.addWidget(QtWidgets.QLabel("System Cleanup"))
        clean_l.addWidget(QtWidgets.QLabel("Clean APT cache, logs, temp files, caches, trash"))
        clean_l.addWidget(self._btn(_("🧹 Run Cleanup"), self._run_cleanup))
        clean_l.addWidget(self._btn(_("👁 Preview Cleanup"), self._cleanup_preview))
        self.clean_progress = QtWidgets.QProgressBar()
        self.clean_progress.setStyleSheet(f"QProgressBar {{ background: {DARK_MID}; border: 1px solid {BORDER}; border-radius: 4px; height: 14px; }} QProgressBar::chunk {{ background: {GREEN}; border-radius: 3px; }}")
        self.clean_progress.hide()
        clean_l.addWidget(self.clean_progress)
        self.clean_status = QtWidgets.QLabel("")
        self.clean_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        clean_l.addWidget(self.clean_status)
        self.clean_results = QtWidgets.QListWidget()
        self.clean_results.setStyleSheet(f"QListWidget {{ background: {DARK_BG}; border: 1px solid {BORDER}; border-radius: 4px; color: {TEXT}; font-size: 10px; }}")
        clean_l.addWidget(self.clean_results, 1)
        tabs.addTab(clean_w, "Cleanup")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(w)

    # ===== SETTINGS =====
    def _build_settings(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔧  Settings"), "Configure DefendR behavior")
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 6px; }} QTabBar::tab {{ background: {DARK_MID}; color: {TEXT_DIM}; padding: 6px 14px; border: 1px solid {BORDER}; border-bottom: none; border-radius: 4px 4px 0 0; font-size: 11px; }} QTabBar::tab:selected {{ background: {DARK_CARD}; color: {ACCENT_LIGHT}; }}")

        # General
        gen_w = QtWidgets.QWidget()
        gen_l = QtWidgets.QVBoxLayout(gen_w)

        prot_frame = QtWidgets.QFrame()
        prot_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        prot_l = QtWidgets.QVBoxLayout(prot_frame)
        prot_l.addWidget(QtWidgets.QLabel("Protection"))
        self.protect_cb = QtWidgets.QCheckBox("Enable real-time protection")
        self.protect_cb.setChecked(True)
        self.protect_cb.setStyleSheet(f"QCheckBox {{ color: {TEXT}; font-size: 12px; }} QCheckBox::indicator {{ width: 16px; height: 16px; }}")
        self.protect_cb.toggled.connect(self._toggle_protection)
        prot_l.addWidget(self.protect_cb)
        info = QtWidgets.QLabel("Pentesting tools are automatically whitelisted.\nOnly truly malicious files are flagged.")
        info.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent; padding: 4px 0;")
        prot_l.addWidget(info)
        gen_l.addWidget(prot_frame)

        # Signatures
        sig_frame = QtWidgets.QFrame()
        sig_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        sig_l = QtWidgets.QVBoxLayout(sig_frame)
        sig_l.addWidget(QtWidgets.QLabel("Signatures & Updates"))
        sig_row = QtWidgets.QHBoxLayout()
        sig_row.addWidget(self._btn(_("🔄 Check for Updates"), self._manual_update))
        self.sig_count = QtWidgets.QLabel(f"Signatures: {self.sig_updater.get_signature_count()}")
        self.sig_count.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        sig_row.addWidget(self.sig_count)
        sig_row.addStretch()
        sig_l.addLayout(sig_row)
        self.update_status = QtWidgets.QLabel("")
        self.update_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        sig_l.addWidget(self.update_status)
        gen_l.addWidget(sig_frame)

        # Game Mode
        gm_frame = QtWidgets.QFrame()
        gm_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        gm_l = QtWidgets.QVBoxLayout(gm_frame)
        gm_l.addWidget(QtWidgets.QLabel("Game Mode"))
        self.gm_cb = QtWidgets.QCheckBox("Auto-detect fullscreen games and suppress notifications")
        self.gm_cb.setStyleSheet(f"QCheckBox {{ color: {TEXT}; font-size: 12px; }}")
        self.gm_cb.toggled.connect(lambda v: self.game_mode.start() if v else self.game_mode.stop())
        gm_l.addWidget(self.gm_cb)
        gen_l.addWidget(gm_frame)

        # Software Updates
        su_frame = QtWidgets.QFrame()
        su_frame.setStyleSheet(f"background: {DARK_CARD}; border: 1px solid {BORDER}; border-radius: 8px;")
        su_l = QtWidgets.QVBoxLayout(su_frame)
        su_l.addWidget(QtWidgets.QLabel("Software Updater"))
        su_l.addWidget(QtWidgets.QLabel("Check for outdated system packages and pip packages"))
        su_btn_row = QtWidgets.QHBoxLayout()
        su_btn_row.addWidget(self._btn(_("🔍 Check for Updates"), self._check_soft_updates))
        self.su_install_btn = self._btn(_("📥 Install All Updates"), self._su_install_all)
        su_btn_row.addWidget(self.su_install_btn)
        su_l.addLayout(su_btn_row)
        self.su_status = QtWidgets.QLabel("")
        self.su_status.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        su_l.addWidget(self.su_status)
        self.su_results = QtWidgets.QPlainTextEdit()
        self.su_results.setReadOnly(True)
        self.su_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; font-size: 10px; font-family: monospace; padding: 4px; max-height: 120px;")
        su_l.addWidget(self.su_results)
        gen_l.addWidget(su_frame)
        tabs.addTab(gen_w, "General")

        # Whitelist
        wl_w = QtWidgets.QWidget()
        wl_l = QtWidgets.QVBoxLayout(wl_w)
        wl_title = QtWidgets.QLabel("Pentest Tool Whitelist")
        wl_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {ACCENT_LIGHT}; background: transparent;")
        wl_l.addWidget(wl_title)
        self.wl_edit = QtWidgets.QPlainTextEdit()
        self.wl_edit.setPlainText("\n".join(sorted(self.engine.whitelist)))
        self.wl_edit.setStyleSheet(f"QPlainTextEdit {{ background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; font-size: 11px; padding: 6px; }}")
        wl_l.addWidget(self.wl_edit)
        wl_l.addWidget(self._btn("💾 Save Whitelist", self._save_wl))
        tabs.addTab(wl_w, "Whitelist")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(w)

    # ===================== MONITORS =====================
    def _start_monitors(self):
        self.monitor_timer = QtCore.QTimer()
        self.monitor_timer.timeout.connect(self._update_stats)
        self.monitor_timer.start(4000)
        self._update_dns()
        self._refresh_procs()
        # Auto-start background protections
        self.rt_protector.start()
        self.rt_toggle.setText("⏹ Stop Real-Time Protection")
        self.rt_status.setText(_("Status: Active"))
        self.ransomware.start()
        self.rw_toggle.setText("⏹ Stop Ransomware Detection")
        self.rw_status.setText(_("Status: Active"))
        self.usb_scanner.start()

    def _update_stats(self):
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.3)
            mem = psutil.virtual_memory().percent
            procs = len(psutil.pids())
            self.stat_cards["cpu"].set_value(f"{cpu:.0f}%")
            self.stat_cards["mem"].set_value(f"{mem:.0f}%")
            self.stat_cards["procs"].set_value(str(procs))
            try:
                net_conns = psutil.net_connections(kind="tcp")
                nconns = len([c for c in net_conns if c.status == "ESTABLISHED"])
                self.conn_label.setText(str(nconns))
            except (psutil.AccessDenied, PermissionError): pass
            except: pass
            threats = self.stat_cards["threats"].value_lbl.text()
            self.tray.setToolTip(f"DefendR - Proteção Ativa\nCPU: {cpu:.0f}% | RAM: {mem:.0f}%\nAmeaças: {threats}")
        except: pass

    def _update_dns(self):
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf") as f:
                    servers = [l.split()[1] for l in f if l.startswith("nameserver")]
                self.dns_label.setText("\n".join(servers) if servers else "None configured")
        except: pass

    # ===================== SCANNER =====================
    def _scan_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to scan")
        if path: self._do_scan(path)
    def _scan_dir(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if path: self._do_scan(path)
    def _scan_usb_manual(self):
        for d in ["/media","/run/media","/mnt"]:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    fp = os.path.join(d,f)
                    if os.path.ismount(fp):
                        self._do_scan(fp)
                        return
        self.scan_status.setText("No USB mounts found")

    def _do_scan(self, path):
        self.scan_tree.clear()
        self.scan_progress.setValue(0)
        self.scan_progress.show()
        self.scan_status.setText(f"Scanning: {path}")
        thread = ScanWorker(self.engine, path)
        thread.finished.connect(lambda results: self._scan_done(results))
        thread.start()
        self._scan_thread = thread

    def _scan_done(self, results):
        self.scan_progress.hide()
        self.scan_status.setText(f"Done. Malicious: {len(results['malicious'])}, Suspicious: {len(results['suspicious'])}, Pentest: {len(results['pentest'])}, Safe: {results['safe']}")
        total = results["safe"] + len(results["malicious"])+len(results["suspicious"])+len(results["pentest"])
        cur = int(self.stat_cards["scanned"].value_lbl.text() or "0")
        self.stat_cards["scanned"].set_value(str(cur+total))
        for r in results["malicious"]:
            self._add_scan_item("MALICIOUS", r["path"], r["reason"], RED)
        for r in results["suspicious"]:
            self._add_scan_item("SUSPICIOUS", r["path"], r["reason"], YELLOW)
        for r in results["pentest"]:
            self._add_scan_item("PENTEST", r["path"], r["reason"], CYAN)
        if not any([results["malicious"],results["suspicious"],results["pentest"]]):
            self._add_scan_item("SAFE", _("No threats found"), "All files are clean", GREEN)

    def _add_scan_item(self, risk, path, reason, color):
        item = QtWidgets.QTreeWidgetItem([risk, textwrap.shorten(path, 80), reason])
        for i in range(3): item.setForeground(i, QtGui.QColor(color))
        item.setToolTip(1, path)
        self.scan_tree.addTopLevelItem(item)

    def _stop_scan(self):
        self.engine.scanning = False
        self.scan_progress.hide()
        self.scan_status.setText("Scan stopped")
    def _clear_scan(self):
        self.scan_tree.clear()
        self.scan_status.setText("Ready")

    # ===================== NETWORK =====================
    def _toggle_net(self):
        if self.netmon.monitoring:
            self.netmon.stop()
            self.net_status.setText("●  Monitoring: OFF")
            self.net_status.setStyleSheet(f"font-size: 13px; color: {TEXT_DIM}; background: transparent;")
            self.net_toggle.setText("▶ Start")
        else:
            self.netmon.start()
            self.net_status.setText("●  Monitoring: ON")
            self.net_status.setStyleSheet(f"font-size: 13px; color: {GREEN}; background: transparent;")
            self.net_toggle.setText("⏹ Stop")

    def _on_net_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.net_alerts.insertItem(0, item)
        if self.net_alerts.count() > 200: self.net_alerts.takeItem(self.net_alerts.count()-1)
        ditem = QtWidgets.QListWidgetItem(f"[NET][{level}] {msg}")
        ditem.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, ditem)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)

    def _on_net_data(self, data):
        if data.get("type") == "arp":
            self.arp_table.setRowCount(len(data["data"]))
            for i,(ip,(hw,iface)) in enumerate(data["data"].items()):
                self.arp_table.setItem(i,0,QtWidgets.QTableWidgetItem(ip))
                self.arp_table.setItem(i,1,QtWidgets.QTableWidgetItem(hw))
                self.arp_table.setItem(i,2,QtWidgets.QTableWidgetItem(iface))

    # ===================== REALTIME =====================
    def _toggle_rt(self):
        if self.rt_protector.active:
            self.rt_protector.stop()
            self.rt_toggle.setText("▶ Start Real-Time Protection")
            self.rt_status.setText(_("Status: Stopped"))
        else:
            self.rt_protector.start()
            self.rt_toggle.setText("⏹ Stop Real-Time Protection")
            self.rt_status.setText(_("Status: Active"))

    def _on_rt_alert(self, risk, path, reason):
        item = QtWidgets.QListWidgetItem(f"[{risk.upper()}] {path}: {reason}")
        color = RED if risk == "malicious" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        if self.rt_alerts.count() > 100: self.rt_alerts.takeItem(self.rt_alerts.count()-1)
        ditem = QtWidgets.QListWidgetItem(f"[RT][{risk.upper()}] {reason}")
        ditem.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, ditem)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
        if risk == "malicious":
            cur = int(self.stat_cards["threats"].value_lbl.text() or "0")
            self.stat_cards["threats"].set_value(str(cur + 1))

    # ===================== RANSOMEWARE =====================
    def _toggle_rw(self):
        if self.ransomware.monitoring:
            self.ransomware.stop()
            self.rw_toggle.setText("▶ Start Ransomware Detection")
            self.rw_status.setText(_("Status: Stopped"))
        else:
            self.ransomware.start()
            self.rw_toggle.setText("⏹ Stop Ransomware Detection")
            self.rw_status.setText(_("Status: Active"))

    def _on_ransomware_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[RANSOM]{msg}"))

    # ===================== WEB BLOCKER =====================
    def _web_block(self):
        dom = self.wb_input.text().strip()
        if not dom: return
        ok, msg = self.web_blocker.block_domain(dom)
        self._show_msg(msg)
        if ok: self._refresh_web_block()
    def _web_unblock(self):
        dom = self.wb_input.text().strip()
        if not dom: return
        ok, msg = self.web_blocker.unblock_domain(dom)
        self._show_msg(msg)
        if ok: self._refresh_web_block()
    def _refresh_web_block(self):
        self.wb_list.clear()
        for d in self.web_blocker.get_blocked():
            self.wb_list.addItem(d)

    # ===================== ANTI-PHISHING =====================
    def _check_phishing(self):
        url = self.ap_input.text().strip()
        if not url: return
        result = self.anti_phish.check_url(url)
        risk_color = RED if result["risk"]=="high" else (YELLOW if result["risk"]=="medium" else GREEN)
        txt = f"Domain: {result['domain']}\nRisk: {result['risk'].upper()} (Score: {result['score']})\n"
        if result["reasons"]: txt += f"Reasons: {', '.join(result['reasons'])}\n"
        if result["risk"] == "high":
            txt += "⚠ This URL appears to be a phishing site!\n"
            self.anti_phish.add_phishing(result["domain"])
        self.ap_result.setText(txt)
        self.ap_result.setStyleSheet(f"font-size: 11px; color: {risk_color}; background: transparent; padding: 4px; border: 1px solid {BORDER}; border-radius: 4px;")

    # ===================== FIREWALL =====================
    def _fw_enable(self):
        ok, msg = self.firewall.enable()
        self.fw_status.setText(f"Firewall: {'Enabled' if ok else 'Error'}")
        self._show_msg(msg)
    def _fw_disable(self):
        ok, msg = self.firewall.disable()
        self.fw_status.setText("Firewall: Disabled")
        self._show_msg(msg)
    def _fw_flush(self):
        ok, msg = self.firewall.flush()
        self.fw_status.setText("Firewall: Disabled (flushed)")
        self._show_msg(msg)
    def _fw_block_port(self):
        port = self.port_input.text().strip()
        if port.isdigit():
            ok, msg = self.firewall.block_port(int(port))
            self._show_msg(msg)
    def _fw_allow_port(self):
        port = self.port_input.text().strip()
        if port.isdigit():
            ok, msg = self.firewall.allow_port(int(port))
            self._show_msg(msg)
    def _fw_refresh(self):
        self.fw_rules.clear()
        rules = self.firewall.list_rules()
        for r in rules: self.fw_rules.addItem(r)

    # ===================== PROCESSES =====================
    def _refresh_procs(self):
        self.proc_table.setRowCount(0)
        procs = self.engine.get_processes()
        self.proc_table.setRowCount(len(procs))
        for i, p in enumerate(procs):
            self.proc_table.setItem(i,0,QtWidgets.QTableWidgetItem(str(p["pid"])))
            self.proc_table.setItem(i,1,QtWidgets.QTableWidgetItem(p["name"][:30]))
            self.proc_table.setItem(i,2,QtWidgets.QTableWidgetItem(f"{p['cpu']:.1f}"))
            self.proc_table.setItem(i,3,QtWidgets.QTableWidgetItem(f"{p['mem']:.2f}"))
            self.proc_table.setItem(i,4,QtWidgets.QTableWidgetItem(str(p["conns"])))
            status = "OK"; color = TEXT
            if p["suspicious"]: status = "SUSPICIOUS"; color = RED
            elif p["pentest"]: status = "ALLOWED"; color = CYAN
            item = QtWidgets.QTableWidgetItem(status)
            item.setForeground(QtGui.QColor(color))
            self.proc_table.setItem(i,5,item)

    # ===================== QUARANTINE =====================
    def _refresh_quarantine(self):
        self.q_table.setRowCount(0)
        items = self.quarantine.list_quarantined()
        self.q_table.setRowCount(len(items))
        for i, (qid, info) in enumerate(items):
            self.q_table.setItem(i,0,QtWidgets.QTableWidgetItem(qid[:8]))
            self.q_table.setItem(i,1,QtWidgets.QTableWidgetItem(textwrap.shorten(info.get("original",""),60)))
            self.q_table.setItem(i,2,QtWidgets.QTableWidgetItem(info.get("date","")[:19]))
            self.q_table.setItem(i,3,QtWidgets.QTableWidgetItem(f"{info.get('size',0)}B"))
            btn_w = QtWidgets.QWidget()
            btn_l = QtWidgets.QHBoxLayout(btn_w); btn_l.setContentsMargins(2,2,2,2)
            r_btn = QtWidgets.QPushButton("Restore")
            r_btn.setStyleSheet(f"QPushButton {{ background: {GREEN}; color: white; border: none; border-radius: 3px; padding: 3px 6px; font-size: 10px; }}")
            r_btn.clicked.connect(lambda _, q=qid: self._quarantine_restore(q))
            btn_l.addWidget(r_btn)
            d_btn = QtWidgets.QPushButton("Delete")
            d_btn.setStyleSheet(f"QPushButton {{ background: {RED}; color: white; border: none; border-radius: 3px; padding: 3px 6px; font-size: 10px; }}")
            d_btn.clicked.connect(lambda _, q=qid: self._quarantine_delete(q))
            btn_l.addWidget(d_btn)
            self.q_table.setCellWidget(i,4,btn_w)

    def _quarantine_restore(self, qid):
        ok, msg = self.quarantine.restore(qid)
        self._show_msg(msg)
        self._refresh_quarantine()
    def _quarantine_delete(self, qid):
        ok, msg = self.quarantine.delete_permanently(qid)
        self._show_msg(msg)
        self._refresh_quarantine()
    def _quarantine_delete_all(self):
        for qid in list(self.quarantine.metadata.keys()):
            self.quarantine.delete_permanently(qid)
        self._refresh_quarantine()

    # ===================== TOOLS =====================
    def _sandbox_run(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to run in sandbox")
        if path:
            ok, msg = self.sandbox.run_in_sandbox(path)
            self._show_msg(msg)

    def _rootkit_scan(self):
        self.rk_results.setPlainText("Running rootkit scan...")
        QtCore.QTimer.singleShot(100, self._do_rootkit)
    def _do_rootkit(self):
        results = self.rootkit.full_scan()
        if not results:
            self.rk_results.setPlainText("✅ No rootkits detected.\nSystem appears clean.")
            return
        txt = "⚠ Rootkit Scan Results:\n" + "="*40 + "\n"
        for k, v in results.items():
            txt += f"\n{k}: {v}\n"
        self.rk_results.setPlainText(txt)

    def _on_rootkit_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        item.setForeground(QtGui.QColor(RED if level == "HIGH" else YELLOW))
        self.alert_list.insertItem(0, item)

    # Password Manager
    def _pwd_unlock(self):
        if self.pwd_mgr.unlocked:
            self._refresh_pwd()
            return
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Master Password", "Enter master password:", QtWidgets.QLineEdit.Password)
        if ok and pwd:
            if self.pwd_mgr.unlock(pwd):
                self.pwd_unlock_btn.setText("🔓 Unlocked")
                self._refresh_pwd()
            else:
                self._show_msg("Wrong password")
    def _pwd_lock(self):
        self.pwd_mgr.lock()
        self.pwd_unlock_btn.setText("🔓 Unlock Vault")
        self.pwd_list.clear()
    def _pwd_add(self):
        if not self.pwd_mgr.unlocked:
            self._show_msg("Unlock vault first"); return
        site = self.pwd_site.text().strip()
        user = self.pwd_user.text().strip()
        pwd = self.pwd_pass.text().strip()
        if site and user and pwd:
            self.pwd_mgr.add_entry(site, user, pwd)
            self._show_msg("Entry saved")
            self.pwd_site.clear(); self.pwd_user.clear(); self.pwd_pass.clear()
            self._refresh_pwd()
    def _refresh_pwd(self):
        self.pwd_list.clear()
        if not self.pwd_mgr.unlocked:
            self.pwd_list.addItem("🔒 Vault locked - click Unlock")
            return
        for e in self.pwd_mgr.get_entries():
            item = QtWidgets.QListWidgetItem(f"{e['site']:20s} | {e['username']:20s} | {e.get('created','')[:16]}")
            item.setData(QtCore.Qt.UserRole, e["id"])
            self.pwd_list.addItem(item)

    # Scheduler
    def _sched_add(self):
        name = self.sched_name.text().strip() or "Scheduled Scan"
        path = self.sched_path.text().strip() or os.path.expanduser("~")
        hours = self.sched_hours.value()
        self.scheduler.add_task(name, path, hours)
        self._show_msg(f"Task '{name}' added (every {hours}h)")
        self._sched_refresh()
    def _sched_refresh(self):
        self.sched_list.clear()
        for t in self.scheduler.tasks:
            last = t.get("last_run","never")[:19] if t.get("last_run") else "never"
            status = "✅" if t.get("enabled") else "⏸"
            self.sched_list.addItem(f"{status} {t.get('name','?')} | Every {t.get('interval','?')}h | Path: {t.get('path','?')[:40]} | Last: {last}")
    def _on_scheduled_scan(self, task_id):
        for t in self.scheduler.tasks:
            if t["id"] == task_id:
                self._do_scan(t["path"])
                self._show_msg(f"Scheduled scan started: {t['name']}")
                break

    # Signature Updates
    def _manual_update(self):
        self.update_status.setText("Checking for updates...")
        QtCore.QTimer.singleShot(100, self._do_update)
    def _do_update(self):
        n = self.sig_updater.check_update()
        self.sig_count.setText(f"Signatures: {self.sig_updater.get_signature_count()}")
        self.update_status.setText(f"Updated {n} signatures" if n else "No updates available")
    def _on_update_status(self, msg):
        self.update_status.setText(msg)

    # Game Mode
    def _on_game_mode(self, active):
        self.tray_game.setText(f"🎮  Game Mode: {'ON' if active else 'OFF'}")
        if active:
            self.tray.showMessage("DefendR", "🎮 Game Mode activated - notifications suppressed",
                                  QtWidgets.QSystemTrayIcon.Information, 2000)

    # USB Scanner
    def _on_usb_scan(self, mount):
        self.scan_status.setText(f"USB mounted: {mount} - scanning...")
    def _on_usb_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[USB][{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, item)

    # VPN
    def _vpn_add(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select OpenVPN config", filter="Config files (*.ovpn *.conf)")
        if path:
            ok, msg = self.vpn.add_config(path)
            self._show_msg(msg)
            self._refresh_vpn_list()
    def _vpn_connect(self):
        items = self.vpn_list.selectedItems()
        if not items: self._show_msg("Select a config first"); return
        config = items[0].data(QtCore.Qt.UserRole)
        if config:
            ok, msg = self.vpn.connect(config)
            self.vpn_status.setText(f"VPN: {msg}")
            self._show_msg(msg)
    def _vpn_disconnect(self):
        ok, msg = self.vpn.disconnect()
        self.vpn_status.setText("VPN: Disconnected")
        self._show_msg(msg)
    def _refresh_vpn_list(self):
        self.vpn_list.clear()
        for c in self.vpn.get_configs():
            item = QtWidgets.QListWidgetItem(os.path.basename(c))
            item.setData(QtCore.Qt.UserRole, c)
            self.vpn_list.addItem(item)

    # Network Inspector
    def _arp_scan(self):
        self.inspector_results.setPlainText("Running ARP scan (requires root + scapy)...")
        QtCore.QTimer.singleShot(100, lambda: self.net_inspector.arp_scan())
    def _router_info(self):
        self.inspector_results.setPlainText("Gathering router info...")
        QtCore.QTimer.singleShot(100, self._do_router_info)
    def _do_router_info(self):
        info = self.net_inspector.router_info()
        txt = "📡 Router Info:\n" + "="*40 + "\n"
        for k, v in info.items():
            if isinstance(v, list):
                txt += f"{k}:\n"
                for item in v: txt += f"  - {item}\n"
            else:
                txt += f"{k}: {v}\n"
        self.inspector_results.setPlainText(txt)
    def _on_inspect_result(self, rtype, data):
        if rtype == "arp_scan":
            if isinstance(data, list):
                txt = f"🔍 ARP Scan Results ({len(data)} devices):\n" + "="*40 + "\n"
                for d in data: txt += f"{d['ip']:15s} {d['mac']}\n"
                self.inspector_results.setPlainText(txt)
            else:
                self.inspector_results.setPlainText(f"Error: {data}")
        elif rtype == "error":
            self.inspector_results.setPlainText(f"Error: {data}")

    # ===================== SETTINGS =====================
    def _toggle_protection(self, enabled):
        self.engine.protection_active = enabled
        if enabled:
            self.protect_indicator.setText("●  Protected")
            self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {GREEN}; background: transparent;")
        else:
            self.protect_indicator.setText("●  Disabled")
            self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {RED}; background: transparent;")

    def _save_wl(self):
        lines = self.wl_edit.toPlainText().strip().split("\n")
        self.engine.whitelist = set(l.strip() for l in lines if l.strip())
        self.engine.save_config()
        self._show_msg(f"Whitelist saved ({len(self.engine.whitelist)} entries)")

    def _show_msg(self, msg):
        self.tray.showMessage("DefendR", msg, QtWidgets.QSystemTrayIcon.Information, 3000)

    # ===================== WEBCAM =====================
    def _toggle_webcam(self):
        if self.webcam_protector.monitoring:
            self.webcam_protector.stop()
            self.wc_toggle.setText("▶ Start Webcam Monitor")
            self.wc_status.setText(_("Status: Stopped"))
        else:
            self.webcam_protector.start()
            self.wc_toggle.setText("⏹ Stop Webcam Monitor")
            self.wc_status.setText(_("Status: Active"))

    def _on_webcam_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[WEBCAM][{level}] {msg}")
        item.setForeground(QtGui.QColor(YELLOW))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[WEBCAM] {msg}"))
    def _on_webcam_block(self, msg):
        self.wc_list.addItem(msg)
    def _webcam_block_device(self):
        ok, msg = self.webcam_protector.block_webcam()
        self._show_msg(msg)
    def _webcam_unblock_device(self):
        ok, msg = self.webcam_protector.unblock_webcam()
        self._show_msg(msg)

    # ===================== WIFI =====================
    def _wifi_scan(self):
        self.wifi_results.setPlainText("Scanning router (takes up to 60s)...")
        QtCore.QTimer.singleShot(100, self.wifi_inspector.scan_router)
    def _on_wifi_result(self, rtype, data):
        if rtype == "wifi_scan":
            if "error" in data:
                self.wifi_results.setPlainText(f"Error: {data['error']}\n\nTip: run with sudo and install nmap")
                return
            txt = f"📡 WiFi Router Scan\n{'='*40}\n"
            txt += f"Gateway: {data.get('gateway','?')}\n"
            txt += f"Open Ports: {', '.join(data.get('open_ports',['none']))}\n"
            if data.get("warnings"):
                txt += f"\n⚠ Security Issues:\n"
                for w in data["warnings"]: txt += f"  - {w}\n"
            txt += f"\nFull nmap output:\n{data.get('nmap_output','')[:2000]}"
            self.wifi_results.setPlainText(txt)
    def _on_wifi_device(self, msg):
        self.wifi_device_list.addItem(msg)
    def _wifi_start_monitor(self):
        if self.wifi_inspector.monitoring:
            self.wifi_inspector.monitoring = False
            self.wifi_monitor_btn.setText("▶ Start Continuous Monitor")
        else:
            self.wifi_inspector.start_monitoring()
            self.wifi_monitor_btn.setText("⏹ Stop Monitoring")

    # ===================== SHREDDER =====================
    def _shred_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding...")
            QtCore.QTimer.singleShot(100, lambda: self.shredder.shred(path))
    def _shred_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding folder...")
            QtCore.QTimer.singleShot(100, lambda: self.shredder.shred_directory(path))
    def _on_shred_progress(self, val, msg):
        self.shred_progress.setValue(val)
        self.shred_status.setText(msg)
    def _on_shred_done(self, ok, msg):
        self.shred_progress.hide()
        self.shred_status.setText(msg)
        self._show_msg(msg)

    # ===================== SOFTWARE UPDATER =====================
    def _check_soft_updates(self):
        self.su_status.setText("Checking for updates...")
        self.su_results.setPlainText("")
        QtCore.QTimer.singleShot(100, self._do_soft_check)
    def _do_soft_check(self):
        results = self.soft_updater.check_updates()
        if results:
            txt = ""
            if results.get("system"):
                txt += f"System ({len(results['system'])}):\n"
                for p in results["system"][:30]: txt += f"  {p}\n"
                if len(results["system"]) > 30: txt += f"  ... and {len(results['system'])-30} more\n"
            if results.get("pip"):
                txt += f"\nPip ({len(results['pip'])}):\n"
                for p in results["pip"][:20]: txt += f"  {p}\n"
                if len(results["pip"]) > 20: txt += f"  ... and {len(results['pip'])-20} more\n"
            if not txt: txt = "All packages up to date"
            self.su_results.setPlainText(txt)
    def _on_soft_update(self, msg):
        self.su_status.setText(msg)
    def _on_soft_progress(self, val, msg):
        self.su_status.setText(msg)

    # ===================== DNS =====================
    def _dns_set(self, provider):
        ok, msg = self.dns_over_https.set_dns(provider)
        self.dns_status.setText(f"Current: {', '.join(self.dns_over_https.get_current_dns())}")
        self._show_msg(msg)
    def _dns_reset(self):
        ok, msg = self.dns_over_https.reset_dns()
        self.dns_status.setText(f"Current: {', '.join(self.dns_over_https.get_current_dns())}")
        self._show_msg(msg)
    def _dns_enable_dnssec(self):
        ok, msg = self.dns_over_https.enable_dnssec()
        self._show_msg(msg)

    # ===================== CLEANUP =====================
    def _run_cleanup(self):
        self.clean_progress.setValue(0)
        self.clean_progress.show()
        self.clean_status.setText("Cleaning...")
        self.clean_results.clear()
        QtCore.QTimer.singleShot(100, self.cleanup_mgr.run_cleanup)
    def _on_cleanup_progress(self, val, msg):
        self.clean_progress.setValue(val)
        self.clean_status.setText(msg)
    def _on_cleanup_done(self, ok, msg):
        self.clean_progress.hide()
        self.clean_status.setText(msg)
        self._show_msg(msg)
    def _cleanup_preview(self):
        self.clean_results.clear()
        self.clean_status.setText("Gathering preview...")
        QtCore.QTimer.singleShot(100, lambda: self.cleanup_mgr.preview())
    def _on_cleanup_preview(self, results):
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
        self.clean_status.setText(f"Preview: {self.clean_results.count()} items, {self._fmt_size(total)}")
    def _fmt_size(self, bytes_):
        if not bytes_: return "0 B"
        for unit in ["B","KB","MB","GB","TB"]:
            if bytes_ < 1024: return f"{bytes_:.1f} {unit}"
            bytes_ /= 1024
        return f"{bytes_:.1f} PB"

    # ===================== SHREDDER =====================
    def _shred_standard_changed(self, idx):
        key = self.shred_standard.itemData(idx)
        self.shredder.set_standard(key)
    def _shred_free_space(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select drive/partition to wipe free space")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Wiping free space...")
            QtCore.QTimer.singleShot(100, lambda: self.shredder.wipe_free_space(path))

    # ===================== SOFTWARE UPDATER =====================
    def _su_install_all(self):
        self.su_status.setText("Installing updates...")
        self.su_results.setPlainText("")
        QtCore.QTimer.singleShot(100, lambda: self.soft_updater.install_all())

# ===================== WIFI INSPECTOR =====================
class WiFiInspector(QtCore.QObject):
    result_signal = QtCore.pyqtSignal(str, object)
    device_signal = QtCore.pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.scanning = False
        self.monitoring = False
        self.known_devices = {}
    def scan_router(self):
        self.scanning = True
        results = {"gateway": "?", "open_ports": [], "warnings": [], "info": [], "firmware": "?"}
        try:
            r = subprocess.run(["ip","route"], capture_output=True, text=True, timeout=5)
            gateway = None
            for line in r.stdout.split("\n"):
                if "default" in line:
                    parts = line.split(); gateway = parts[2]; break
            if not gateway:
                results["error"]="No gateway found"
                self.result_signal.emit("wifi_scan", results)
                return results
            results["gateway"] = gateway
            nmap_r = subprocess.run(["nmap","-sT","-p","21,22,23,53,80,443,445,500,1723,1900,5351,8080,8443,49152-49156","--open","-n","-oG","-",gateway], capture_output=True, text=True, timeout=90)
            results["nmap_output"] = nmap_r.stdout
            open_ports = re.findall(r"(\d+)/open", nmap_r.stdout)
            results["open_ports"] = open_ports
            port_risks = {"21":"FTP (unencrypted file transfer)","23":"Telnet (insecure remote access)","53":"DNS (possible DNS poisoning)","445":"SMB (vulnerable to EternalBlue)","500":"ISAKMP (VPN weak configs)","1723":"PPTP (outdated VPN protocol)","1900":"UPnP (device discovery, potential exploits)","5351":"NAT-PMP (router firewall bypass)"}
            for p in open_ports:
                if p in port_risks: results["warnings"].append(port_risks[p])
            if "80" in open_ports and "443" not in open_ports:
                results["warnings"].append("HTTP without HTTPS (login creds sent in clear text)")
            try:
                import urllib.request
                default_creds = [("admin","admin"),("admin","password"),("admin","1234"),("root","root"),("root","admin"),("user","user"),("guest","guest")]
                for user, pwd in default_creds:
                    try:
                        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                        req = urllib.request.Request(f"http://{gateway}/", headers={"Authorization":f"Basic {auth}"})
                        resp = urllib.request.urlopen(req, timeout=3)
                        if resp.status == 200:
                            results["warnings"].append(f"Router uses default login: {user}/{pwd}")
                            break
                    except: pass
                pub = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
                results["public_ip"] = pub
            except: pass
        except Exception as e:
            results["error"]=str(e)
        self.scanning = False
        self.result_signal.emit("wifi_scan", results)
        return results
    def start_monitoring(self):
        self.monitoring = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    def stop_monitoring(self):
        self.monitoring = False
    def _monitor_loop(self):
        while self.monitoring:
            try:
                devices = {}
                if os.path.exists("/proc/net/arp"):
                    with open("/proc/net/arp") as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                                devices[parts[0]] = parts[3]
                for ip, mac in devices.items():
                    if ip not in self.known_devices:
                        self.known_devices[ip] = mac
                        self.device_signal.emit(f"New device on network: {ip} ({mac})")
                    elif self.known_devices[ip] != mac:
                        self.device_signal.emit(f"Device {ip} changed MAC: {self.known_devices[ip]} -> {mac}")
                        self.known_devices[ip] = mac
                time.sleep(30)
            except: time.sleep(30)

# ===================== DATA SHREDDER =====================
class DataShredder(QtCore.QObject):
    progress_signal = QtCore.pyqtSignal(int, str)
    done_signal = QtCore.pyqtSignal(bool, str)
    def __init__(self):
        super().__init__()
        self.shredding = False
        self.standards = {
            "DoD 5220.22-M (3 passes)": [b"\x00", b"\xff", b"\x00"],
            "DoD 5220.22-M ECE (7 passes)": [b"\x00", b"\xff", b"\x00", b"\xff", b"\x00", b"\xff", b"\x00"],
            "Schneier (7 passes)": [b"\x00", b"\xff", random_bytes(4096), b"\x00", b"\xff", random_bytes(4096), b"\x00"],
            "Gutmann (35 passes)": [random_bytes(4096)] * 35,
            "Nuke (1 pass zeros)": [b"\x00"],
            "Nuke (1 pass random)": [random_bytes(4096)],
        }
        self.current_standard = "DoD 5220.22-M (3 passes)"
    def set_standard(self, name):
        if name in self.standards: self.current_standard = name
    def shred(self, filepath, passes=None):
        self.shredding = True
        if not os.path.exists(filepath): self.done_signal.emit(False, "File not found"); return
        patterns = self.standards[self.current_standard] if passes is None else [random_bytes(4096)]*passes
        try:
            size = os.path.getsize(filepath)
            total = len(patterns)
            for i, pat in enumerate(patterns):
                if not self.shredding: self.done_signal.emit(False, "Cancelled"); return
                with open(filepath, "wb") as f:
                    written = 0
                    while written < size:
                        p = pat() if callable(pat) else pat
                        chunk = p * (4096 // len(p) + 1) if len(p) > 0 else p
                        f.write(chunk[:4096]); written += 4096
                    f.flush(); os.fsync(f.fileno())
                self.progress_signal.emit(int((i+1)/total*100), f"Pass {i+1}/{total} ({self.current_standard})")
            os.remove(filepath)
            self.done_signal.emit(True, f"Shredded ({self.current_standard}): {os.path.basename(filepath)}")
        except Exception as e: self.done_signal.emit(False, str(e))
        finally: self.shredding = False
    def shred_directory(self, dirpath, passes=None):
        self.shredding = True
        if not os.path.isdir(dirpath): self.done_signal.emit(False, "Directory not found"); return
        patterns = self.standards[self.current_standard] if passes is None else [random_bytes(4096)]*passes
        try:
            files = [os.path.join(root,f) for root,dirs,fnames in os.walk(dirpath) for f in fnames]
            total = len(files)
            for i, fp in enumerate(files):
                if not self.shredding: self.done_signal.emit(False, "Cancelled"); return
                self.progress_signal.emit(int((i+1)/total*100), f"Shredding {os.path.basename(fp)}")
                size = os.path.getsize(fp)
                for pat in patterns:
                    with open(fp, "wb") as f:
                        written = 0
                        while written < size:
                            p = pat() if callable(pat) else pat
                            chunk = p * (4096 // len(p) + 1) if len(p) > 0 else p
                            f.write(chunk[:4096]); written += 4096
                        f.flush(); os.fsync(f.fileno())
                os.remove(fp)
            shutil.rmtree(dirpath, ignore_errors=True)
            self.done_signal.emit(True, f"Shredded {total} files ({self.current_standard})")
        except Exception as e: self.done_signal.emit(False, str(e))
        finally: self.shredding = False
    def wipe_free_space(self, path="/"):
        self.shredding = True
        try:
            tf = tempfile.NamedTemporaryFile(dir=path, prefix="defendr_wipe_", delete=False)
            tfname = tf.name; tf.close()
            size = 0
            chunk = os.urandom(1024*1024)
            with open(tfname, "wb") as f:
                while self.shredding:
                    try: f.write(chunk); size += len(chunk)
                    except: break
            os.remove(tfname)
            self.done_signal.emit(True, f"Free space wiped: {size/1024/1024:.0f}MB overwritten")
        except Exception as e: self.done_signal.emit(False, str(e))
        finally: self.shredding = False

def random_bytes(n):
    return lambda: os.urandom(n)

# ===================== SOFTWARE UPDATER =====================
class SoftwareUpdater(QtCore.QObject):
    update_signal = QtCore.pyqtSignal(str)
    progress_signal = QtCore.pyqtSignal(int, str)
    def __init__(self):
        super().__init__()
        self.checking = False
    def check_updates(self):
        self.checking = True
        results = {"system": [], "security": [], "pip": [], "flatpak": [], "snap": [], "total": 0}
        try:
            r = subprocess.run(["apt","list","--upgradable"], capture_output=True, text=True, timeout=60)
            for line in r.stdout.split("\n")[1:]:
                if line.strip() and "/" in line:
                    parts = line.split()
                    pkg = parts[0].split("/")[0]
                    ver_info = f"{parts[1]} -> {parts[2]}" if len(parts) >= 3 else ""
                    results["system"].append(f"{pkg} {ver_info}")
                    if any(kw in pkg.lower() for kw in ["openssl","libssl","openssh","linux-","systemd","glibc","kernel","sudo","curl","wget","bash"]):
                        results["security"].append(pkg)
            results["total"] += len(results["system"])
        except: pass
        try:
            r = subprocess.run(["pip3","list","--outdated","--format=columns"], capture_output=True, text=True, timeout=30)
            for line in r.stdout.split("\n")[2:]:
                parts = line.split()
                if len(parts) >= 3: results["pip"].append(f"{parts[0]} ({parts[1]} -> {parts[2]})")
            results["total"] += len(results["pip"])
        except: pass
        try:
            r = subprocess.run(["flatpak","update","--dry-run"], capture_output=True, text=True, timeout=60)
            updates = re.findall(r"^\s+(\S+)\s+", r.stdout, re.MULTILINE)
            results["flatpak"] = [u for u in updates if u.startswith(("org.","com.","net."))]
            results["total"] += len(results["flatpak"])
        except: pass
        try:
            r = subprocess.run(["snap","refresh","--list"], capture_output=True, text=True, timeout=30)
            for line in r.stdout.split("\n")[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1: results["snap"].append(parts[0])
            results["total"] += len(results["snap"])
        except: pass
        self.checking = False
        sec = len(results["security"])
        msg = f"{results['total']} updates: {len(results['system'])} apt"
        if sec: msg += f" ({sec} security)"
        if results["pip"]: msg += f", {len(results['pip'])} pip"
        if results["flatpak"]: msg += f", {len(results['flatpak'])} flatpak"
        if results["snap"]: msg += f", {len(results['snap'])} snap"
        self.update_signal.emit(msg)
        return results
    def install_all(self):
        try:
            self.progress_signal.emit(0, "Updating system packages...")
            subprocess.run(["sudo","apt","upgrade","-y"], capture_output=True, text=True, timeout=300)
            self.progress_signal.emit(50, "Updating pip packages...")
            subprocess.run(["pip3","install","--upgrade","pip"], capture_output=True, timeout=60)
            self.progress_signal.emit(75, "Updating flatpak...")
            subprocess.run(["flatpak","update","-y"], capture_output=True, timeout=120)
            self.progress_signal.emit(100, "All updates installed")
            self.update_signal.emit("System updated successfully")
        except Exception as e: self.update_signal.emit(f"Update failed: {str(e)[:60]}")

# ===================== WEBCAM PROTECTOR =====================
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
            except: pass
        return users
    def block_webcam(self, hard=False):
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
        except Exception as e: return f"Block failed: {e}"
    def unblock_webcam(self):
        try:
            if self.blocked:
                subprocess.run(["sudo","modprobe","uvcvideo"], capture_output=True, timeout=10)
                for d in os.listdir("/dev"):
                    if d.startswith("video"):
                        subprocess.run(["sudo","chmod","666",f"/dev/{d}"], capture_output=True, timeout=5)
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
            except: time.sleep(5)

# ===================== DNS OVER HTTPS =====================
class DNSOverHTTPS:
    def __init__(self):
        self.providers = {
            "Cloudflare (1.1.1.1 + DoT)": {"ipv4": "1.1.1.1", "ipv6": "2606:4700:4700::1111", "doh": "https://cloudflare-dns.com/dns-query", "dot": "1dot1dot1dot1.cloudflare-dns.com"},
            "Quad9 (9.9.9.9 + DoT)": {"ipv4": "9.9.9.9", "ipv6": "2620:fe::fe", "doh": "https://dns.quad9.net/dns-query", "dot": "dns.quad9.net"},
            "Google (8.8.8.8 + DoT)": {"ipv4": "8.8.8.8", "ipv6": "2001:4860:4860::8888", "doh": "https://dns.google/dns-query", "dot": "dns.google"},
            "Mullvad (100.64.0.1, no-log)": {"ipv4": "194.242.2.2", "ipv6": "2a07:e340::2", "doh": "https://dns.mullvad.net/dns-query", "dot": "dns.mullvad.net"},
        }
        self.current = None
    def test_dns(self, ip):
        try:
            r = subprocess.run(["ping","-c1","-W2",ip], capture_output=True, timeout=5)
            return r.returncode == 0
        except: return False
    def set_dns(self, provider_key):
        if provider_key not in self.providers: return False, "Unknown provider"
        p = self.providers[provider_key]
        if not self.test_dns(p["ipv4"]): return False, f"DNS server {p['ipv4']} unreachable"
        try:
            resolvectl_ok = subprocess.run(["which","resolvectl"], capture_output=True, timeout=2).returncode == 0
            if resolvectl_ok:
                for iface in ["eth0","wlan0","wlp*"]:
                    subprocess.run(["resolvectl","dns",iface,p["ipv4"]], capture_output=True, timeout=5)
                    subprocess.run(["resolvectl","dnsovertls",iface,"yes"], capture_output=True, timeout=5)
                    if "ipv6" in p: subprocess.run(["resolvectl","dns",iface,p["ipv6"]], capture_output=True, timeout=5)
                subprocess.run(["resolvectl","default-route","eth0","true"], capture_output=True, timeout=5)
            else:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(f"# DefendR DNS-over-TLS: {provider_key}\n")
                    f.write(f"nameserver {p['ipv4']}\n")
                    if "ipv6" in p: f.write(f"nameserver {p['ipv6']}\n")
                    f.write("options use-vc timeout:2 attempts:1\n")
                    f.write("options edns0 trust-ad\n")
            self.current = provider_key
            return True, f"DNS set to {provider_key} with DoT"
        except PermissionError: return False, "Need root (sudo)"
        except Exception as e: return False, str(e)
    def reset_dns(self):
        try:
            resolvectl_ok = subprocess.run(["which","resolvectl"], capture_output=True, timeout=2).returncode == 0
            if resolvectl_ok: subprocess.run(["resolvectl","revert"], capture_output=True, timeout=5)
            else:
                with open("/etc/resolv.conf", "w") as f:
                    f.write("# Generated by NetworkManager\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n")
            self.current = None
            return True, "DNS reset to defaults"
        except PermissionError: return False, "Need root (sudo)"
        except Exception as e: return False, str(e)
    def enable_dnssec(self):
        try:
            resolvectl_ok = subprocess.run(["which","resolvectl"], capture_output=True, timeout=2).returncode == 0
            if resolvectl_ok:
                subprocess.run(["resolvectl","dnssec","yes"], capture_output=True, timeout=5)
                return True, "DNSSEC validation enabled"
            return False, "resolvectl not available"
        except Exception as e: return False, str(e)
    def get_current_dns(self):
        try:
            servers = []
            r = subprocess.run(["resolvectl","dns"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    if ":" in line and not line.startswith("Global"): servers.append(line.strip())
            if not servers:
                with open("/etc/resolv.conf") as f:
                    servers = [l.split()[1] for l in f if l.startswith("nameserver")]
            return servers if servers else ["No DNS configured"]
        except: return ["Error reading DNS"]

# ===================== CLEANUP MANAGER =====================
class CleanupManager(QtCore.QObject):
    progress_signal = QtCore.pyqtSignal(int, str)
    done_signal = QtCore.pyqtSignal(bool, str)
    preview_signal = QtCore.pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self.cleaning = False
    def preview(self):
        self.cleaning = True
        results = []
        checks = [
            ("APT cache", self._size_apt), ("Old kernels", self._old_kernels),
            ("System logs", self._size_logs), ("User cache", self._size_cache),
            ("Browser cache", self._size_browsers), ("npm cache", self._size_npm),
            ("Docker images", self._size_docker), ("Flatpak cache", self._size_flatpak),
            ("Pip cache", self._size_pip), ("Thumbnails", self._size_thumbnails),
            ("Trash", self._size_trash), ("Temp files", self._size_tmp),
            ("Broken symlinks", self._broken_symlinks), ("Empty dirs", self._empty_dirs),
        ]
        for name, func in checks:
            if not self.cleaning: break
            try:
                info = func()
                if info: results.append(info)
            except: pass
        self.cleaning = False
        self.preview_signal.emit(results)
        return results
    def run_cleanup(self):
        self.cleaning = True
        freed = 0; items = []
        tasks = [
            ("APT cache", self._clean_apt), ("Old kernels", self._clean_old_kernels),
            ("System logs", self._clean_logs), ("User cache", self._clean_cache),
            ("Browser cache", self._clean_browsers), ("npm cache", self._clean_npm),
            ("Docker cleanup", self._clean_docker), ("Flatpak cache", self._clean_flatpak),
            ("Pip cache", self._clean_pip), ("Thumbnails", self._clean_thumbnails),
            ("Trash", self._clean_trash), ("Temp files", self._clean_tmp),
            ("Broken symlinks", self._clean_broken_symlinks), ("Empty dirs", self._clean_empty_dirs),
        ]
        for i, (name, func) in enumerate(tasks):
            if not self.cleaning: break
            self.progress_signal.emit(int((i+1)/len(tasks)*100), f"Cleaning {name}...")
            try:
                size = func()
                if size > 0: items.append(f"{name}: {self._fmt(size)}")
                freed += size
            except: pass
        self.cleaning = False
        msg = f"Freed {self._fmt(freed)}" if freed > 0 else "Nothing to clean"
        self.done_signal.emit(True, msg)
        return freed, items
    def _fmt(self, b):
        for u in ["B","KB","MB","GB"]:
            if b < 1024: return f"{b:.1f}{u}"
            b /= 1024
        return f"{b:.1f}TB"
    def _dir_size(self, path):
        try:
            if not os.path.exists(path): return 0
            r = subprocess.run(["du","-sb",path], capture_output=True, text=True, timeout=30)
            return int(r.stdout.split()[0]) if r.stdout else 0
        except: return 0
    def _size_apt(self):
        s = self._dir_size("/var/cache/apt/archives")
        return ("APT cache", s, f"Debian packages: {self._fmt(s)}") if s > 0 else None
    def _size_logs(self):
        s = self._dir_size("/var/log")
        return ("System logs", s, f"Log files: {self._fmt(s)}") if s > 0 else None
    def _size_cache(self):
        s = self._dir_size(os.path.expanduser("~/.cache"))
        return ("User cache", s, f"~/.cache: {self._fmt(s)}") if s > 0 else None
    def _size_browsers(self):
        s = 0
        for b in ["~/.cache/chromium","~/.cache/google-chrome","~/.cache/mozilla/firefox","~/.cache/Brave-Browser"]:
            s += self._dir_size(os.path.expanduser(b))
        return ("Browser cache", s, f"Browser cache: {self._fmt(s)}") if s > 0 else None
    def _size_npm(self):
        s = self._dir_size(os.path.expanduser("~/.npm"))
        return ("npm cache", s, f"npm: {self._fmt(s)}") if s > 0 else None
    def _size_docker(self):
        try:
            r = subprocess.run(["docker","system","df","--format","{{.Size}}"], capture_output=True, text=True, timeout=30)
            m = re.search(r"([\d.]+)\s*(GB|MB)", r.stdout)
            if m: s = float(m.group(1)) * (1024**3 if m.group(2)=="GB" else 1024**2)
            else: s = 0
            return ("Docker", s, f"Docker: {self._fmt(s)}") if s > 0 else None
        except: return None
    def _size_flatpak(self):
        s = self._dir_size(os.path.expanduser("~/.local/share/flatpak"))
        return ("Flatpak cache", s, f"Flatpak: {self._fmt(s)}") if s > 0 else None
    def _size_pip(self):
        try:
            r = subprocess.run(["pip3","cache","info"], capture_output=True, text=True, timeout=15)
            m = re.search(r"(\d+)\s*(bytes|kB|MB|GB)", r.stdout)
            if m:
                mult = {"bytes":1,"kB":1024,"MB":1024**2,"GB":1024**3}
                s = int(m.group(1)) * mult.get(m.group(2), 1)
                return ("Pip cache", s, f"pip: {self._fmt(s)}")
        except: pass
        return None
    def _size_thumbnails(self):
        for d in [os.path.expanduser("~/.thumbnails"), os.path.expanduser("~/.cache/thumbnails")]:
            s = self._dir_size(d)
            if s > 0: return ("Thumbnails", s, f"{self._fmt(s)} cache thumbs")
        return None
    def _size_trash(self):
        s = self._dir_size(os.path.expanduser("~/.local/share/Trash/files"))
        return ("Trash", s, f"Trash: {self._fmt(s)}") if s > 0 else None
    def _size_tmp(self):
        s = self._dir_size("/tmp")
        return ("Temp files", s, f"/tmp: {self._fmt(s)}") if s > 0 else None
    def _old_kernels(self):
        try:
            r = subprocess.run(["dpkg","--list"], capture_output=True, text=True, timeout=30)
            kernels = re.findall(r"linux-image-(\d+\.\d+\.\d+-\d+)", r.stdout)
            current = subprocess.run(["uname","-r"], capture_output=True, text=True, timeout=5).stdout.strip()
            old = [k for k in set(kernels) if k not in current and not current.startswith(k)]
            if old: return ("Old kernels", len(old)*200*1024*1024, f"{len(old)} old kernels (~{len(old)*200}MB)")
        except: pass
        return None
    def _broken_symlinks(self):
        broken = 0
        try:
            for d in ["/usr/bin","/usr/lib","/etc","/opt"]:
                for root, dirs, files in os.walk(d):
                    for f in files:
                        fp = os.path.join(root, f)
                        if os.path.islink(fp) and not os.path.exists(fp): broken += 1
        except: pass
        return ("Broken symlinks", broken*4096, f"{broken} broken links") if broken > 0 else None
    def _empty_dirs(self):
        count = 0
        for d in ["/tmp", os.path.expanduser("~/.cache")]:
            for root, dirs, files in os.walk(d):
                if not dirs and not files: count += 1
        return ("Empty dirs", 0, f"{count} empty directories") if count > 0 else None
    def _clean_apt(self):
        try:
            s = self._dir_size("/var/cache/apt/archives")
            subprocess.run(["apt-get","clean"], capture_output=True, timeout=60)
            subprocess.run(["apt-get","autoremove","-y"], capture_output=True, timeout=120)
            return s
        except: return 0
    def _clean_old_kernels(self):
        try:
            r = subprocess.run(["dpkg","--list"], capture_output=True, text=True, timeout=30)
            current = subprocess.run(["uname","-r"], capture_output=True, text=True, timeout=5).stdout.strip()
            kernels = re.findall(r"linux-image-(\d+\.\d+\.\d+-\d+)", r.stdout)
            freed = 0
            for k in set(kernels):
                if k not in current and not current.startswith(k):
                    pkg = f"linux-image-{k}"
                    r2 = subprocess.run(["dpkg","-s",pkg], capture_output=True, text=True, timeout=10)
                    if "ok installed" in r2.stdout:
                        subprocess.run(["sudo","apt-get","remove","-y",pkg], capture_output=True, timeout=60)
                        freed += 200*1024*1024
            return freed
        except: return 0
    def _clean_logs(self):
        freed = 0
        try:
            for f in os.listdir("/var/log"):
                fp = os.path.join("/var/log", f)
                if f.endswith((".log",".gz",".old",".1",".2",".3",".4",".5")) and os.path.isfile(fp):
                    freed += os.path.getsize(fp)
                    if f.endswith(".log"): open(fp,"w").close()
                    else: os.remove(fp)
        except: pass
        return freed
    def _clean_cache(self):
        cache = os.path.expanduser("~/.cache")
        s = self._dir_size(cache)
        for f in os.listdir(cache):
            fp = os.path.join(cache, f)
            try:
                if os.path.isfile(fp): os.remove(fp)
                elif os.path.isdir(fp): shutil.rmtree(fp, ignore_errors=True)
            except: pass
        return s
    def _clean_browsers(self):
        freed = 0
        for pattern in ["~/.cache/chromium","~/.cache/google-chrome","~/.cache/mozilla/firefox","~/.cache/Brave-Browser"]:
            d = os.path.expanduser(pattern)
            if os.path.isdir(d):
                freed += self._dir_size(d)
                shutil.rmtree(d, ignore_errors=True)
        return freed
    def _clean_npm(self):
        npm = os.path.expanduser("~/.npm")
        if not os.path.isdir(npm): return 0
        s = self._dir_size(npm)
        shutil.rmtree(npm, ignore_errors=True)
        return s
    def _clean_docker(self):
        try:
            r = subprocess.run(["docker","system","prune","-f"], capture_output=True, timeout=120, text=True)
            m = re.search(r"Total reclaimed space:\s*([\d.]+)\s*(GB|MB|kB|B)", r.stdout)
            if m:
                mult = {"B":1,"kB":1024,"MB":1024**2,"GB":1024**3}
                return int(float(m.group(1)) * mult.get(m.group(2), 1))
            return 0
        except: return 0
    def _clean_flatpak(self):
        try:
            r = subprocess.run(["flatpak","uninstall","--unused","-y"], capture_output=True, timeout=60)
            m = re.search(r"(\d+)\s*(bytes|kB|MB|GB)", r.stdout)
            if m:
                mult = {"bytes":1,"kB":1024,"MB":1024**2,"GB":1024**3}
                return int(m.group(1)) * mult.get(m.group(2), 1)
        except: pass
        return 0
    def _clean_pip(self):
        try:
            r = subprocess.run(["pip3","cache","purge"], capture_output=True, timeout=30)
            m = re.search(r"(\d+)", r.stdout.split()[-3] if "purged" in r.stdout else "")
            return int(m.group(1))*1024 if m else 0
        except: return 0
    def _clean_thumbnails(self):
        freed = 0
        for d in [os.path.expanduser("~/.thumbnails"), os.path.expanduser("~/.cache/thumbnails")]:
            if os.path.isdir(d):
                freed += self._dir_size(d)
                shutil.rmtree(d, ignore_errors=True)
        return freed
    def _clean_trash(self):
        freed = 0
        trash = os.path.expanduser("~/.local/share/Trash")
        if os.path.isdir(trash):
            for sub in ["files","expunged","info"]:
                fp = os.path.join(trash, sub)
                if os.path.isdir(fp): freed += self._dir_size(fp); shutil.rmtree(fp, ignore_errors=True)
                elif os.path.isfile(fp): freed += os.path.getsize(fp); os.remove(fp)
        return freed
    def _clean_tmp(self):
        freed = self._dir_size("/tmp")
        for f in os.listdir("/tmp"):
            fp = os.path.join("/tmp", f)
            try:
                if os.path.isfile(fp): os.remove(fp)
                elif os.path.isdir(fp): shutil.rmtree(fp, ignore_errors=True)
            except: pass
        return freed
    def _clean_broken_symlinks(self):
        count = 0
        try:
            for d in ["/usr/bin","/usr/lib","/etc","/opt"]:
                for root, dirs, files in os.walk(d):
                    for f in files:
                        fp = os.path.join(root, f)
                        if os.path.islink(fp) and not os.path.exists(fp):
                            try: os.remove(fp); count += 1
                            except: pass
        except: pass
        return count * 4096
    def _clean_empty_dirs(self):
        count = 0
        for d in ["/tmp", os.path.expanduser("~/.cache")]:
            for root, dirs, files in os.walk(d):
                if not dirs and not files:
                    try: os.rmdir(root); count += 1
                    except: pass
        return 0
# ===================== MAIN =====================
def main():
    LOCK_PORT = 48123
    lock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lock_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lock_sock.bind(("127.0.0.1", LOCK_PORT))
        lock_sock.listen(1)
    except OSError:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", LOCK_PORT)); s.sendall(b"raise"); s.close()
        except: pass
        sys.exit(0)

    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(DARK_BG))
    palette.setColor(QtGui.QPalette.Background, QtGui.QColor(DARK_BG))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(DARK_CARD))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor(TEXT))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(TEXT))
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(ACCENT))
    palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("white"))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(ACCENT))
    palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor("white"))
    app.setPalette(palette)
    font = QtGui.QFont("Consolas", 10)
    app.setFont(font)

    splash = SplashScreen()
    app.processEvents()

    window = MainWindow()
    splash.finish(window)
    window.show()

    def listen_raise():
        while True:
            try:
                conn, addr = lock_sock.accept()
                data = conn.recv(1024)
                if data == b"raise":
                    window.raise_(); window.activateWindow(); window.show(); window.tray.show()
                conn.close()
            except: break
    threading.Thread(target=listen_raise, daemon=True).start()

    if os.geteuid() != 0:
        QtCore.QTimer.singleShot(3000, lambda: window.tray.showMessage(
            "DefendR", _("no_root"),
            QtWidgets.QSystemTrayIcon.Information, 3000))

    sys.exit(app.exec())

if __name__ == "__main__":
    if "--sudo" in sys.argv:
        try:
            script = os.path.abspath(__file__)
            args = [a for a in sys.argv if a != "--sudo"]
            os.execvp("pkexec", ["pkexec", sys.executable, script] + args)
        except FileNotFoundError:
            os.execvp("sudo", ["sudo", sys.executable, script] + [a for a in sys.argv if a != "--sudo"])
        except: pass
    if not os.environ.get("DISPLAY"):
        print("DefendR requires a graphical display to run.")
        sys.exit(1)
    main()
