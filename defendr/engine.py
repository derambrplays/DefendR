# Engine: file scanning and threat detection
import concurrent.futures
import hashlib
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
    DEFAULT_EXCLUDE,
)
from defendr.clamav_sigs import load_clamav_patterns
from defendr.filelock import safe_json_read, safe_json_write
from defendr.heuristic import analyze_file_advanced
from defendr.hashes import sha256_file, get_hash_verdict
from defendr.lang import _
from defendr.reputation import ReputationClient
from defendr.joguin_ia import JoguinIA

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


def _normalize_exclude(exclude):
    result = []
    for e in exclude:
        if e.startswith("/"):
            e = e.rstrip("/") + "/"
        result.append(e)
    return result


def _file_walk(path, exclude=None):
    exclude = _normalize_exclude(exclude or [])
    NOISE_DIRS = {"node_modules", ".git", "__pycache__", ".cache", ".npm", ".yarn"}
    if not os.path.isdir(path):
        p = Path(path)
        if not any(str(p).startswith(e) for e in exclude):
            yield p
        return
    for root, dirs, files in os.walk(path, followlinks=False):
        root_s = root + "/"
        if any(root_s.startswith(e) or root == e.rstrip("/") for e in exclude):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in NOISE_DIRS]
        dirs[:] = [d for d in dirs if not any(
            os.path.join(root, d).startswith(e) for e in exclude)]
        for f in files:
            fpath = os.path.join(root, f)
            if any(fpath.startswith(e) for e in exclude):
                continue
            yield Path(fpath)


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
        self._defendr_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.protection_active = True
        self.scan_level = "medium"
        self.rep_client = ReputationClient()
        self.use_reputation = True
        self.use_heuristic = True
        self.joguin = JoguinIA()
        self._start_heartbeat()

    def stop(self):
        self.scanning = False
        self._hb_running = False

    def ai_learn_feedback(self, filepath, was_correct):
        file_hash = sha256_file(filepath)
        if was_correct:
            self.joguin.learn(filepath, "malicious", file_hash=file_hash, user_agreed=True)
        else:
            self.joguin.learn_mistake(filepath, file_hash=file_hash)

    def _start_heartbeat(self):
        self._hb_running = True
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def _heartbeat_loop(self):
        time.sleep(5)
        while self._hb_running:
            self.rep_client.register()
            for _ in range(3600):
                if not self._hb_running:
                    return
                time.sleep(1)

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
        self.config_data = data or {}

    def save_config(self):
        self.config_data["whitelist"] = list(self.whitelist)
        safe_json_write(self.config_file, self.config_data)

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
            lock = threading.Lock()

            def scan_one(f):
                try:
                    if not self.scanning or not f.is_file():
                        return
                    r = self._scan_file(f)
                    if r:
                        with lock:
                            key = r.get("risk", "unknown")
                            if key == "error":
                                results["errors"].append(r)
                            elif key in results:
                                results[key].append(r)
                        if result_cb:
                            result_cb(r)
                    else:
                        with lock:
                            results["safe"] += 1
                except Exception:
                    pass

            scanned = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
                futs = []
                for f in _file_walk(path):
                    if not self.scanning:
                        break
                    futs.append(pool.submit(scan_one, f))
                    if len(futs) >= 500:
                        for done in concurrent.futures.as_completed(futs):
                            scanned += 1
                            if progress_cb and scanned % 200 == 0:
                                progress_cb(scanned, f"{scanned}")
                        futs = []
                for done in concurrent.futures.as_completed(futs):
                    scanned += 1
                    if progress_cb and scanned % 200 == 0:
                        progress_cb(scanned, f"{scanned}")
        finally:
            self.scanning = False
            if progress_cb:
                progress_cb(scanned, f"Done - {scanned}")
        return results

    def scan_rapido(self, path, progress_cb=None, result_cb=None, exclude_extra=None):
        return self._scan_with_patterns(path, progress_cb, result_cb, exclude_extra=exclude_extra, mode="rapido")

    def scan_completo(self, path, progress_cb=None, result_cb=None, exclude_extra=None):
        results = self._scan_with_patterns(path, progress_cb, result_cb, exclude_extra=exclude_extra, mode="completo")
        vt_key = os.environ.get("VT_API_KEY") or ""
        if vt_key:
            self._check_virustotal(results, vt_key)
        return results

    def scan_with_level(self, path, level="light", progress_cb=None, result_cb=None, exclude_extra=None):
        return self._scan_with_patterns(path, progress_cb, result_cb, exclude_extra=exclude_extra, mode=level)

    def _count_files(self, path, exclude, progress_cb=None):
        total = 0
        checked = 0
        try:
            for root, dirs, files in os.walk(path, followlinks=False):
                if not self.scanning:
                    return -1
                root_s = root + "/"
                if any(root_s.startswith(e) or root == e for e in exclude):
                    dirs[:] = []
                    continue
                dirs[:] = [d for d in dirs if not any(
                    os.path.join(root, d).startswith(e) for e in exclude)]
                total += len(files)
                checked += 1
                if progress_cb and checked % 5000 == 0:
                    progress_cb(-1, f"Counting... {total} files found")
        except Exception:
            pass
        return total

    def _scan_with_patterns(self, path, progress_cb=None, result_cb=None, exclude_extra=None, mode="rapido"):
        self.scanning = True
        results = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": []}
        scanned = 0
        try:
            defendr_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            exclude = [defendr_dir] + list(SYSTEM_PATHS) + list(DEFAULT_EXCLUDE) + (exclude_extra or [])
            lock = threading.Lock()
            all_pats = self.malware_patterns + self._clamav_patterns + self._remote_patterns
            if mode == "completo" or mode == "heavy":
                scan_func = self._scan_full_file
            elif mode == "medium":
                scan_func = self._scan_medium_file
            elif mode == "light" or mode == "rapido":
                scan_func = self._scan_light_file

            if progress_cb:
                progress_cb(-1, _("Counting files..."))
            total = self._count_files(path, exclude, progress_cb)
            if total < 0:
                return results
            if progress_cb:
                progress_cb(0, "0%% (0/%d)" % total)

            def scan_one(f):
                try:
                    if not self.scanning or not f.is_file():
                        return
                    r = scan_func(f, all_pats)
                    if r:
                        with lock:
                            key = r.get("risk", "unknown")
                            if key == "error":
                                results["errors"].append(r)
                            elif key in results:
                                results[key].append(r)
                        if result_cb:
                            result_cb(r)
                    else:
                        with lock:
                            results["safe"] += 1
                except Exception:
                    pass

            scanned = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
                futs = []
                for f in _file_walk(path, exclude=exclude):
                    if not self.scanning:
                        break
                    futs.append(pool.submit(scan_one, f))
                    if len(futs) >= 500:
                        for done in concurrent.futures.as_completed(futs):
                            scanned += 1
                            if progress_cb and scanned % 100 == 0:
                                pct = int(scanned * 100 / total) if total > 0 else 0
                                progress_cb(pct, "%d%% (%d/%d)" % (pct, scanned, total))
                        futs = []
                for done in concurrent.futures.as_completed(futs):
                    scanned += 1
                    if progress_cb and scanned % 100 == 0:
                        pct = int(scanned * 100 / total) if total > 0 else 0
                        progress_cb(pct, "%d%% (%d/%d)" % (pct, scanned, total))
                if progress_cb and scanned > 0:
                    pct = int(scanned * 100 / total) if total > 0 else 0
                    progress_cb(pct, "%d%% (%d/%d)" % (pct, scanned, total))
        finally:
            self.scanning = False
            if progress_cb:
                progress_cb(100, "Done - %d files" % scanned)
        return results

    def _read_chunks(self, fpath, size, full=False):
        if not full:
            with open(fpath, "rb") as f:
                header = f.read(16)
                f.seek(0)
                content = f.read(min(size, 1024 * 1024))
            return header, content
        chunks = []
        with open(fpath, "rb") as f:
            header = f.read(16)
            f.seek(0)
            chunk_size = min(size, 1024 * 1024)
            chunks.append(f.read(chunk_size))
            if size > 10 * 1024 * 1024:
                mid = size // 2
                f.seek(mid)
                chunks.append(f.read(min(chunk_size, size - mid)))
                end = max(size - chunk_size, 0)
                f.seek(end)
                chunks.append(f.read(min(chunk_size, size - end)))
        return header, b"".join(chunks)

    THREAT_CLASSES = {
        "EICAR": "test",
        "Metasploit": "trojan",
        "meterpreter": "trojan",
        "Msfvenom": "trojan",
        "cobaltstrike": "trojan",
        "mimikatz": "spyware",
        "Invoke-Mimikatz": "spyware",
        "ReflectiveLoader": "injection",
        "bypass": "hacktool",
        "amsi": "hacktool",
        "Invoke-": "hacktool",
        "keylog": "spyware",
        "reverse_shell": "trojan",
        "backdoor": "trojan",
        "ransomware": "ransomware",
        "DownloadString": "trojan",
        "DownloadFile": "trojan",
    }

    def _classify_threat(self, match_reasons):
        for reason in match_reasons:
            for keyword, ctype in self.THREAT_CLASSES.items():
                if keyword.lower() in reason.lower():
                    return ctype
        return "unknown"

    def _scan_rapido_file(self, fpath, all_pats):
        try:
            fpath_str = str(fpath)
            if fpath_str.startswith(self._defendr_dir):
                return None
            if fpath_str.lower() in self.whitelist:
                return None
            size = fpath.stat().st_size
            name = fpath.name.lower()
            if self.is_pentest(fpath_str):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size, "type": "pentest"}
            if size == 0:
                return None

            suspicious_name = any(s.decode().lower() in name for s in self.suspicious_strings)
            if suspicious_name:
                self.joguin.learn(str(fpath), "suspicious")
                return {"path": str(fpath), "risk": "suspicious", "reason": "Nome sugestivo", "size": size, "type": "name"}
            self.joguin.learn(str(fpath), "safe")
            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0, "type": "error"}

    def _scan_light_file(self, fpath, all_pats):
        try:
            fpath_str = str(fpath)
            if fpath_str.startswith(self._defendr_dir):
                return None
            if fpath_str.lower() in self.whitelist:
                return None
            size = fpath.stat().st_size
            name = fpath.name.lower()
            if self.is_pentest(fpath_str):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size, "type": "pentest"}
            if size == 0:
                return None

            suspicious_name = any(s.decode().lower() in name for s in self.suspicious_strings)
            if suspicious_name:
                return {"path": str(fpath), "risk": "suspicious", "reason": "Nome sugestivo", "size": size, "type": "name"}

            # Read first 2MB for pattern matching
            header, content = self._read_chunks(fpath, min(size, 2 * 1024 * 1024))
            match_reasons = []
            for sig, desc in all_pats:
                if sig in content:
                    match_reasons.append(desc)
                    if len(match_reasons) >= 2:
                        break
            if match_reasons:
                return {"path": str(fpath), "risk": "suspicious", "reason": "; ".join(match_reasons), "size": size, "type": "pattern"}
            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0, "type": "error"}

    def _scan_medium_file(self, fpath, all_pats):
        try:
            fpath_str = str(fpath)
            if fpath_str.startswith(self._defendr_dir):
                return None
            if fpath_str.lower() in self.whitelist:
                return None
            size = fpath.stat().st_size
            name = fpath.name.lower()
            if self.is_pentest(fpath_str):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size, "type": "pentest"}
            if size == 0:
                return None

            if size > 100 * 1024 * 1024:
                return None

            suspicious_name = any(s.decode().lower() in name for s in self.suspicious_strings)
            if suspicious_name:
                return {"path": str(fpath), "risk": "suspicious", "reason": "Nome sugestivo", "size": size, "type": "name"}

            # Read entire file for full pattern matching
            header, content = self._read_chunks(fpath, size, full=True)
            match_reasons = []
            for sig, desc in all_pats:
                if sig in content:
                    match_reasons.append(desc)
                    if len(match_reasons) >= 4:
                        break
            found = [s for s in self.suspicious_strings if s in content]
            str_found = len(found)
            ext = fpath.suffix.lower()
            threshold = 2 if ext in SUSPICIOUS_EXTS else 5
            if str_found >= threshold:
                match_reasons.append(", ".join(s.decode() for s in found[:6]))

            if match_reasons:
                risk = "malicious" if len(match_reasons) >= 2 else "suspicious"
                threat_type = self._classify_threat(match_reasons)
                return {"path": str(fpath), "risk": risk, "reason": "; ".join(match_reasons[:4]), "size": size, "type": threat_type}
            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0, "type": "error"}

    def _scan_full_file(self, fpath, all_pats):
        try:
            fpath_str = str(fpath)
            if fpath_str.startswith(self._defendr_dir):
                return None
            if fpath_str.lower() in self.whitelist:
                return None
            size = fpath.stat().st_size
            ext = fpath.suffix.lower()
            if self.is_pentest(fpath_str):
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size, "type": "pentest"}
            if self._is_system_path(str(fpath)):
                return None
            if size == 0:
                return None

            # 1. Hash check
            file_hash = sha256_file(str(fpath))
            if file_hash:
                verdict, mal_name = get_hash_verdict(file_hash)
                if verdict:
                    self.joguin.learn(str(fpath), verdict, file_hash=file_hash)
                    return {"path": str(fpath), "risk": verdict, "reason": f"Known {mal_name} (hash match)", "size": size, "type": "hash"}

            # 2. Pattern matching (multi-chunk)
            header, content = self._read_chunks(fpath, size, full=True)
            match_reasons = []
            for sig, desc in all_pats:
                if sig in content:
                    match_reasons.append(desc)
                    if len(match_reasons) >= 4:
                        break
            is_elf = header.startswith(b"\x7f\x45\x4c\x46")
            is_pe = header.startswith(b"\x4d\x5a")
            found = [s for s in self.suspicious_strings if s in content]
            str_found = len(found)
            threshold = 2 if ext in SUSPICIOUS_EXTS or is_pe else 5
            if str_found >= threshold:
                match_reasons.append(", ".join(s.decode() for s in found[:6]))

            # 3.5 AI analysis
            ai_result = self.joguin.analyze(str(fpath), file_hash=file_hash, header=header, content=content)
            if ai_result["risk"] in ("malicious", "suspicious") and ai_result["confidence"] >= 50:
                match_reasons.append(f"IA: {ai_result['confidence']}% confianca")

            # 4. Heuristic analysis (more thorough for full scan)
            heur_results, heur_score = analyze_file_advanced(str(fpath))
            if heur_score >= 20:
                match_reasons.append(f"Heuristic: {heur_score}/100")
                for hr in heur_results[:3]:
                    if hr not in match_reasons:
                        match_reasons.append(hr)

            # 5. Entropy for packed files
            entropy_score = _shannon_entropy(content)
            if entropy_score > 7.5 and size > 5 * 1024 * 1024 and ext in SUSPICIOUS_EXTS:
                match_reasons.append(f"High entropy ({entropy_score:.1f}) - possible packed malware")

            # 6. Report to cloud
            if self.use_reputation and file_hash and match_reasons:
                self.rep_client.report(file_hash, "malicious", fpath.name)

            if match_reasons:
                threat_type = self._classify_threat(match_reasons)
                risk = "malicious" if len(match_reasons) >= 2 else "suspicious"
                result = {"path": str(fpath), "risk": risk, "reason": "; ".join(match_reasons[:4]), "size": size, "type": threat_type}
                self.joguin.learn(str(fpath), risk, file_hash=file_hash, header=header, content=content)
                return result
            self.joguin.learn(str(fpath), "safe", file_hash=file_hash, header=header, content=content)
            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0, "type": "error"}

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
                return {"path": str(fpath), "risk": "pentest", "reason": "Pentest tool (whitelisted)", "size": size, "type": "pentest"}

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
                        return {"path": str(fpath), "risk": "suspicious", "reason": desc, "size": size, "type": "magic"}
                return None

            if level == "medium":
                if ext not in SUSPICIOUS_EXTS:
                    return None
                header, content = self._read_chunks(fpath, min(size, 8192))
                content = content[:8192]
                match_reasons = []
                is_elf = header.startswith(b"\x7f\x45\x4c\x46")
                is_pe = header.startswith(b"\x4d\x5a")
                for sig, desc in self.malware_patterns:
                    if sig in content:
                        if desc not in match_reasons:
                            match_reasons.append(desc)
                            if len(match_reasons) >= 3:
                                break
                found = [s for s in self.suspicious_strings if s in content]
                if len(found) >= 2:
                    match_reasons.append(", ".join(s.decode() for s in found[:4]))
                if match_reasons:
                    return {
                        "path": str(fpath),
                        "risk": "suspicious",
                        "reason": "Flagged: " + "; ".join(match_reasons[:3]),
                        "size": size,
                        "type": "pattern",
                    }
                return None

            if level == "heavy":
                if self._is_system_path(str(fpath)):
                    return None

                header, content = self._read_chunks(fpath, size)

                match_reasons = []
                all_patterns = self.malware_patterns + self._clamav_patterns + self._remote_patterns
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
                        "type": "malicious",
                    }
                if len(match_reasons) == 1:
                    return {
                        "path": str(fpath),
                        "risk": "suspicious",
                        "reason": match_reasons[0],
                        "size": size,
                        "type": "suspicious",
                    }

                entropy_score = _shannon_entropy(content)
                if entropy_score > 7.5 and size > 5 * 1024 * 1024 and ext in SUSPICIOUS_EXTS:
                    return {
                        "path": str(fpath),
                        "risk": "suspicious",
                        "reason": f"High entropy ({entropy_score:.1f}) - possible packed malware",
                        "size": size,
                        "type": "packed",
                    }
                return None

            return None
        except (PermissionError, OSError):
            return None
        except Exception as e:
            return {"path": str(fpath), "risk": "error", "reason": str(e), "size": 0, "type": "error"}

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
