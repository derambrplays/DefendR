# Engine: file scanning and threat detection
import os, json, threading, time, hashlib, io
from pathlib import Path
from datetime import datetime
from defendr.constants import CONFIG_DIR, PENTEST_WHITELIST, MALICIOUS_SIGS, SUSPICIOUS_EXTS, SUSPICIOUS_STRINGS
from defendr.filelock import file_lock, safe_json_read, safe_json_write

class DefendREngine:
    def __init__(self):
        self.whitelist = set(PENTEST_WHITELIST)
        self.malicious_sigs = list(MALICIOUS_SIGS)
        self.suspicious_strings = list(SUSPICIOUS_STRINGS)
        self.config_file = os.path.join(CONFIG_DIR, "config.json")
        self.load_config()
        self.scanning = False
        self.protection_active = True
        self.scan_level = "medium"

    def load_config(self):
        data = safe_json_read(self.config_file)
        if data:
            self.whitelist.update(data.get("whitelist", []))

    def save_config(self):
        safe_json_write(self.config_file, {"whitelist": list(self.whitelist)})

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
            ext = fpath.suffix.lower()
            if self.is_pentest(str(fpath)):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size}

            level = self.scan_level
            max_size = {"light": 10*1024*1024, "medium": 100*1024*1024, "heavy": 1024*1024*1024}.get(level, 100*1024*1024)
            if size == 0 or size > max_size:
                return None

            if level == "light":
                if ext not in SUSPICIOUS_EXTS:
                    return None
                with open(fpath, "rb") as f:
                    header = f.read(16)
                for sig, desc in self.malicious_sigs:
                    if header.startswith(sig):
                        return {"path": str(fpath), "risk": "malicious", "reason": desc, "size": size}
                return None

            if level == "medium":
                if ext not in SUSPICIOUS_EXTS:
                    return None
                with open(fpath, "rb") as f:
                    header = f.read(16)
                    for sig, desc in self.malicious_sigs:
                        if header.startswith(sig):
                            return {"path": str(fpath), "risk": "malicious", "reason": desc, "size": size}
                    f.seek(0)
                    content = f.read(min(size, 8192))
                    found = [s for s in self.suspicious_strings if s in content]
                    if len(found) >= 3:
                        return {"path": str(fpath), "risk": "suspicious",
                                "reason": f"Flagged: {', '.join(s.decode() for s in found[:4])}", "size": size}
                return None

            if level == "heavy":
                with open(fpath, "rb") as f:
                    header = f.read(16)
                    for sig, desc in self.malicious_sigs:
                        if header.startswith(sig):
                            return {"path": str(fpath), "risk": "malicious", "reason": desc, "size": size}
                    f.seek(0)
                    read_size = min(size, 1024*1024)
                    content = f.read(read_size)
                    found = [s for s in self.suspicious_strings if s in content]
                    suspicious_count = len(found)
                    if ext in SUSPICIOUS_EXTS:
                        threshold = 2
                    else:
                        threshold = 5
                    if suspicious_count >= threshold:
                        return {"path": str(fpath), "risk": "suspicious",
                                "reason": f"Flagged: {', '.join(s.decode() for s in found[:6])}", "size": size}
                    import re
                    entropy_score = _estimate_entropy(content)
                    if entropy_score > 7.5 and size > 1024*1024:
                        return {"path": str(fpath), "risk": "suspicious",
                                "reason": f"High entropy ({entropy_score:.1f}) - possible packed malware", "size": size}
                return None
            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0}

    def get_processes(self):
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                try:
                    pinfo = p.info
                    name = str(pinfo.get("name") or "?").encode("utf-8", errors="replace").decode("utf-8", errors="replace")
                    try:
                        conns = len(p.connections())
                    except (psutil.AccessDenied, PermissionError):
                        conns = -1
                    except Exception:
                        conns = 0
                    cpu = pinfo["cpu_percent"]
                    if cpu is None:
                        try:
                            cpu = p.cpu_percent()
                        except Exception:
                            cpu = 0.0
                    mem = pinfo["memory_percent"]
                    if mem is None:
                        mem = 0.0
                    procs.append({
                        "pid": pinfo["pid"], "name": name,
                        "cpu": cpu or 0, "mem": mem or 0,
                        "conns": conns,
                        "suspicious": name and any(s in name.lower() for s in SUSPICIOUS_PROCESSES),
                        "pentest": name and self.is_pentest(name),
                    })
                except Exception:
                    pass
            return procs
        except Exception:
            return []

def _estimate_entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((count/total) * (count/total).bit_length() for count in byte_counts.values())
    return abs(entropy)
