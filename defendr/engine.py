# Engine: file scanning and threat detection
import concurrent.futures
import json
import math
import os
import threading
import time
from collections import Counter
from pathlib import Path

from defendr.constants import (
    CONFIG_DIR, PENTEST_WHITELIST, FILE_MAGIC_BYTES, MALWARE_PATTERNS,
    SUSPICIOUS_EXTS, SUSPICIOUS_STRINGS, SUSPICIOUS_PROCESSES, SYSTEM_PATHS,
)
from defendr.clamav_sigs import load_clamav_patterns
from defendr.filelock import safe_json_read, safe_json_write

SIGNATURE_DB_URL = "https://raw.githubusercontent.com/derambrplays/DefendR/main/signatures.json"
SIGNATURE_DB_PATH = os.path.join(CONFIG_DIR, "signatures.json")
VT_API_URL = "https://www.virustotal.com/api/v3/files/{file_hash}"


def _shannon_entropy(data):
    if not data:
        return 0.0
    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in byte_counts.values() if c)
    return entropy


def _file_walk(path):
    p = Path(path)
    if p.is_dir():
        yield from p.rglob("*")
    else:
        yield p


class DefendREngine:
    def __init__(self):
        self.whitelist = set(PENTEST_WHITELIST)
        self.file_magic = list(FILE_MAGIC_BYTES)
        self.malware_patterns = list(MALWARE_PATTERNS)
        self.suspicious_strings = list(SUSPICIOUS_STRINGS)
        self.sigs_ext = list(SUSPICIOUS_EXTS)
        self._remote_patterns = []
        self._clamav_patterns = []
        self.config_file = os.path.join(CONFIG_DIR, "config.json")
        self.load_config()
        self._download_signatures()
        self._load_clamav()
        self.scanning = False
        self.protection_active = True
        self.scan_level = "medium"

    def _download_signatures(self):
        try:
            import urllib.request
            req = urllib.request.Request(
                SIGNATURE_DB_URL,
                headers={"User-Agent": "DefendR/2.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            patterns = data.get("patterns", [])
            self._remote_patterns = [(p["bytes"].encode("latin-1"), p["name"]) for p in patterns]
            with open(SIGNATURE_DB_PATH, "w") as f:
                json.dump({"patterns": [{"bytes": p[0].decode("latin-1"), "name": p[1]} for p in self._remote_patterns]}, f)
        except Exception:
            if os.path.isfile(SIGNATURE_DB_PATH):
                try:
                    with open(SIGNATURE_DB_PATH) as f:
                        data = json.load(f)
                    self._remote_patterns = [(p["bytes"].encode("latin-1"), p["name"]) for p in data.get("patterns", [])]
                except Exception:
                    self._remote_patterns = []

    def _load_clamav(self):
        pats = load_clamav_patterns()
        if pats:
            self._clamav_patterns = pats

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

    def _is_system_path(self, path):
        p = os.path.abspath(path)
        for sp in SYSTEM_PATHS:
            if p.startswith(sp):
                return True
        return False

    def scan_path(self, path, progress_cb=None, result_cb=None):
        self.scanning = True
        results = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": []}
        try:
            files = list(_file_walk(path))
            total = len(files)
            lock = threading.Lock()

            def scan_one(f):
                if not self.scanning:
                    return None
                if not f.is_file():
                    return None
                r = self._scan_file(f)
                if r:
                    with lock:
                        results[r["risk"]].append(r)
                    if result_cb:
                        result_cb(r)
                else:
                    with lock:
                        results["safe"] += 1
                return r

            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
                for i, _ in enumerate(pool.map(scan_one, files)):
                    if progress_cb and total > 0:
                        progress_cb(int((i + 1) / total * 100), f"{i + 1}/{total}")
        finally:
            self.scanning = False
            if progress_cb:
                progress_cb(100, "Done")
        return results

    def scan_rapido(self, path, progress_cb=None, result_cb=None):
        return self._scan_with_patterns(path, progress_cb, result_cb)

    def scan_completo(self, path, progress_cb=None, result_cb=None):
        results = self._scan_with_patterns(path, progress_cb, result_cb)
        vt_key = os.environ.get("VT_API_KEY") or ""
        if vt_key:
            self._check_virustotal(results, vt_key)
        return results

    def _scan_with_patterns(self, path, progress_cb=None, result_cb=None):
        self.scanning = True
        results = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": []}
        try:
            files = list(_file_walk(path))
            total = len(files)
            lock = threading.Lock()
            all_pats = self.malware_patterns + self._clamav_patterns + self._remote_patterns

            def scan_one(f):
                if not self.scanning or not f.is_file():
                    return
                r = self._scan_rapido_file(f, all_pats)
                if r:
                    with lock:
                        results[r["risk"]].append(r)
                    if result_cb:
                        result_cb(r)
                else:
                    with lock:
                        results["safe"] += 1

            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
                for i, _ in enumerate(pool.map(scan_one, files)):
                    if progress_cb and total > 0:
                        progress_cb(int((i + 1) / total * 100), f"{i + 1}/{total}")
        finally:
            self.scanning = False
            if progress_cb:
                progress_cb(100, "Done")
        return results

    def _scan_rapido_file(self, fpath, all_pats):
        try:
            size = fpath.stat().st_size
            ext = fpath.suffix.lower()
            if self.is_pentest(str(fpath)):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size}
            if size == 0 or size > 100 * 1024 * 1024:
                return None
            with open(fpath, "rb") as f:
                header = f.read(16)
                f.seek(0)
                content = f.read(min(size, 1024 * 1024))
            match_reasons = []
            for sig, desc in all_pats:
                if sig in content:
                    match_reasons.append(desc)
                    if len(match_reasons) >= 4:
                        break
            found = [s for s in self.suspicious_strings if s in content]
            threshold = 2 if ext in SUSPICIOUS_EXTS else 5
            if len(found) >= threshold:
                match_reasons.append(", ".join(s.decode() for s in found[:6]))
            if len(match_reasons) >= 2:
                return {"path": str(fpath), "risk": "malicious", "reason": "; ".join(match_reasons[:4]), "size": size}
            if len(match_reasons) == 1:
                return {"path": str(fpath), "risk": "suspicious", "reason": match_reasons[0], "size": size}
            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0}

    def _check_virustotal(self, results, api_key):
        import hashlib, urllib.request
        infected = results.get("malicious", [])
        for entry in infected:
            try:
                with open(entry["path"], "rb") as f:
                    h = hashlib.sha256(f.read()).hexdigest()
                req = urllib.request.Request(
                    VT_API_URL.format(file_hash=h),
                    headers={"x-apikey": api_key},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                if malicious_count >= 3:
                    entry["risk"] = "malicious"
                    entry["reason"] = f"VirusTotal: {malicious_count} engines detected"
                elif malicious_count > 0:
                    entry["risk"] = "suspicious"
                    entry["reason"] = f"VirusTotal: {malicious_count} engines detected (low confidence)"
            except Exception:
                pass

    def _scan_file(self, fpath):
        try:
            size = fpath.stat().st_size
            ext = fpath.suffix.lower()
            if self.is_pentest(str(fpath)):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size}

            level = self.scan_level
            max_size = {"light": 10 * 1024 * 1024, "medium": 100 * 1024 * 1024, "heavy": 1024 * 1024 * 1024}.get(
                level, 100 * 1024 * 1024
            )
            if size == 0 or size > max_size:
                return None

            if level == "light":
                if ext not in SUSPICIOUS_EXTS:
                    return None
                with open(fpath, "rb") as f:
                    header = f.read(16)
                for sig, desc in self.file_magic:
                    if header.startswith(sig):
                        return {"path": str(fpath), "risk": "suspicious", "reason": desc, "size": size}
                return None

            if level == "medium":
                if ext not in SUSPICIOUS_EXTS:
                    return None
                with open(fpath, "rb") as f:
                    header = f.read(16)
                    f.seek(0)
                    content = f.read(min(size, 8192))
                match_reasons = []
                for sig, desc in self.file_magic:
                    if header.startswith(sig):
                        match_reasons.append(desc)
                found = [s for s in self.suspicious_strings if s in content]
                if len(found) >= 3:
                    match_reasons.append(", ".join(s.decode() for s in found[:4]))
                if match_reasons:
                    return {
                        "path": str(fpath),
                        "risk": "suspicious",
                        "reason": "Flagged: " + "; ".join(match_reasons[:3]),
                        "size": size,
                    }
                return None

            if level == "heavy":
                if self._is_system_path(str(fpath)):
                    return None

                with open(fpath, "rb") as f:
                    header = f.read(16)
                    f.seek(0)
                    read_size = min(size, 1024 * 1024)
                    content = f.read(read_size)

                match_reasons = []
                all_patterns = self.file_magic + self.malware_patterns + self._remote_patterns
                for sig, desc in all_patterns:
                    if sig in content:
                        match_reasons.append(desc)

                found = [s for s in self.suspicious_strings if s in content]
                str_found = len(found)

                threshold = 2 if ext in SUSPICIOUS_EXTS else 5
                if str_found >= threshold:
                    match_reasons.append(", ".join(s.decode() for s in found[:6]))

                if len(match_reasons) >= 2:
                    return {
                        "path": str(fpath),
                        "risk": "malicious",
                        "reason": "; ".join(match_reasons[:4]),
                        "size": size,
                    }
                if len(match_reasons) == 1:
                    return {
                        "path": str(fpath),
                        "risk": "suspicious",
                        "reason": match_reasons[0],
                        "size": size,
                    }

                entropy_score = _shannon_entropy(content)
                if entropy_score > 7.5 and size > 5 * 1024 * 1024 and ext in SUSPICIOUS_EXTS:
                    return {
                        "path": str(fpath),
                        "risk": "suspicious",
                        "reason": f"High entropy ({entropy_score:.1f}) - possible packed malware",
                        "size": size,
                    }
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
                    name = str(pinfo.get("name") or "?").encode("utf-8", errors="replace").decode(
                        "utf-8", errors="replace"
                    )
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
                        "pid": pinfo["pid"],
                        "name": name,
                        "cpu": cpu or 0,
                        "mem": mem or 0,
                        "conns": conns,
                        "suspicious": bool(name and any(s in name.lower() for s in SUSPICIOUS_PROCESSES)),
                        "pentest": bool(name and self.is_pentest(name)),
                    })
                except Exception:
                    pass
            return procs
        except Exception:
            return []
