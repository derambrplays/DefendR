# Tools: shredder, software updater, cleanup, password manager, VPN
import os, subprocess, json, random, hashlib, base64, threading, shutil, re, uuid
from pathlib import Path
import tempfile
from PyQt5 import QtCore
from defendr.constants import *
from defendr.filelock import file_lock, safe_json_read, safe_json_write

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
                    except Exception: break
            os.remove(tfname)
            self.done_signal.emit(True, f"Free space wiped: {size/1024/1024:.0f}MB overwritten")
        except Exception as e: self.done_signal.emit(False, str(e))
        finally: self.shredding = False

def random_bytes(n):
    return lambda: os.urandom(n)

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
            r = subprocess.run(["apt","list","--upgradable"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=60)
            for line in r.stdout.split("\n")[1:]:
                if line.strip() and "/" in line:
                    parts = line.split()
                    pkg = parts[0].split("/")[0]
                    ver_info = f"{parts[1]} -> {parts[2]}" if len(parts) >= 3 else ""
                    results["system"].append(f"{pkg} {ver_info}")
                    if any(kw in pkg.lower() for kw in ["openssl","libssl","openssh","linux-","systemd","glibc","kernel","sudo","curl","wget","bash"]):
                        results["security"].append(pkg)
            results["total"] += len(results["system"])
        except Exception: pass
        try:
            r = subprocess.run(["pip3","list","--outdated","--format=columns"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=30)
            for line in r.stdout.split("\n")[2:]:
                parts = line.split()
                if len(parts) >= 3: results["pip"].append(f"{parts[0]} ({parts[1]} -> {parts[2]})")
            results["total"] += len(results["pip"])
        except Exception: pass
        try:
            r = subprocess.run(["flatpak","update","--dry-run"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=60)
            updates = re.findall(r"^\s+(\S+)\s+", r.stdout, re.MULTILINE)
            results["flatpak"] = [u for u in updates if u.startswith(("org.","com.","net."))]
            results["total"] += len(results["flatpak"])
        except Exception: pass
        try:
            r = subprocess.run(["snap","refresh","--list"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=30)
            for line in r.stdout.split("\n")[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1: results["snap"].append(parts[0])
            results["total"] += len(results["snap"])
        except Exception: pass
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
            subprocess.run(["sudo","apt","upgrade","-y"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=300)
            self.progress_signal.emit(50, "Updating pip packages...")
            subprocess.run(["pip3","install","--upgrade","pip"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=60)
            self.progress_signal.emit(75, "Updating flatpak...")
            subprocess.run(["flatpak","update","-y"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=120)
            self.progress_signal.emit(100, "All updates installed")
            self.update_signal.emit("System updated successfully")
        except Exception as e: self.update_signal.emit(f"Update failed: {str(e)[:60]}")

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
            except Exception: pass
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
            except Exception: pass
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
        except Exception: return 0
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
        except Exception: return None
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
        except Exception: pass
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
        except Exception: pass
        return None
    def _broken_symlinks(self):
        broken = 0
        try:
            for d in ["/usr/bin","/usr/lib","/etc","/opt"]:
                for root, dirs, files in os.walk(d):
                    for f in files:
                        fp = os.path.join(root, f)
                        if os.path.islink(fp) and not os.path.exists(fp): broken += 1
        except Exception: pass
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
        except Exception: return 0
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
        except Exception: return 0
    def _clean_logs(self):
        freed = 0
        try:
            for f in os.listdir("/var/log"):
                fp = os.path.join("/var/log", f)
                if f.endswith((".log",".gz",".old",".1",".2",".3",".4",".5")) and os.path.isfile(fp):
                    freed += os.path.getsize(fp)
                    if f.endswith(".log"): open(fp,"w").close()
                    else: os.remove(fp)
        except Exception: pass
        return freed
    def _clean_cache(self):
        cache = os.path.expanduser("~/.cache")
        s = self._dir_size(cache)
        for f in os.listdir(cache):
            fp = os.path.join(cache, f)
            try:
                if os.path.isfile(fp): os.remove(fp)
                elif os.path.isdir(fp): shutil.rmtree(fp, ignore_errors=True)
            except Exception: pass
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
        except Exception: return 0
    def _clean_flatpak(self):
        try:
            r = subprocess.run(["flatpak","uninstall","--unused","-y"], capture_output=True, timeout=60)
            m = re.search(r"(\d+)\s*(bytes|kB|MB|GB)", r.stdout)
            if m:
                mult = {"bytes":1,"kB":1024,"MB":1024**2,"GB":1024**3}
                return int(m.group(1)) * mult.get(m.group(2), 1)
        except Exception: pass
        return 0
    def _clean_pip(self):
        try:
            r = subprocess.run(["pip3","cache","purge"], capture_output=True, timeout=30)
            m = re.search(r"(\d+)", r.stdout.split()[-3] if "purged" in r.stdout else "")
            return int(m.group(1))*1024 if m else 0
        except Exception: return 0
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
            except Exception: pass
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
                            except Exception: pass
        except Exception: pass
        return count * 4096
    def _clean_empty_dirs(self):
        count = 0
        for d in ["/tmp", os.path.expanduser("~/.cache")]:
            for root, dirs, files in os.walk(d):
                if not dirs and not files:
                    try: os.rmdir(root); count += 1
                    except Exception: pass
        return 0

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
            except Exception: pass
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
            r = subprocess.run(["which","openvpn"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=2)
            self.openvpn_ok = r.returncode == 0
        except Exception: self.openvpn_ok = False
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
            except Exception: self.process.kill()
            self.process = None
        self.connected = False
        self.status_signal.emit("Disconnected")
        return True, "Disconnected"
