import json
import math
import os
import struct
import time
from collections import defaultdict, Counter
from pathlib import Path

from defendr.constants import CONFIG_DIR
from defendr.heuristic import _shannon_entropy
from defendr.hashes import sha256_file

KNOWLEDGE_FILE = os.path.join(CONFIG_DIR, "joguin_knowledge.json")

SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread": "process_injection",
    "VirtualAllocEx": "memory_injection",
    "WriteProcessMemory": "memory_injection",
    "QueueUserAPC": "apc_injection",
    "SetWindowsHookEx": "keylogging",
    "NtUnmapViewOfSection": "process_hollowing",
    "GetAsyncKeyState": "keylogging",
    "GetForegroundWindow": "window_monitoring",
    "keybd_event": "input_simulation",
    "socket": "network",
    "connect": "network",
    "recv": "data_reception",
    "send": "data_transmission",
    "WSAStartup": "network_init",
    "RegSetValueEx": "registry_persistence",
    "RegCreateKeyEx": "registry_persistence",
    "CreateService": "service_install",
    "OpenSCManager": "service_access",
    "WinExec": "command_exec",
    "ShellExecute": "shell_exec",
    "URLDownloadToFile": "download",
    "InternetOpen": "internet_init",
    "InternetOpenUrl": "url_access",
    "HttpSendRequest": "http_request",
    "CryptEncrypt": "crypto",
    "CryptDecrypt": "crypto",
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "NtQueryInformationProcess": "anti_debug",
    "MiniDumpWriteDump": "memory_dump",
    "AdjustTokenPrivileges": "privilege_escalation",
    "LookupPrivilegeValue": "privilege_escalation",
    "CreateProcessWithLogon": "credential_access",
    "CryptUnprotectData": "credential_access",
    "WmiExecQuery": "wmi",
    "CoInitializeSecurity": "com_hijack",
    "GetProcAddress": "dynamic_resolution",
    "LoadLibrary": "dynamic_loading",
    "VirtualProtect": "memory_protection",
    "HeapCreate": "heap_manipulation",
    "SetWindowsHookEx": "hook_installation",
    "CallNextHookEx": "hook_installation",
    "NtSetInformationProcess": "process_hiding",
    "NtQuerySystemInformation": "system_recon",
    "GetAdaptersInfo": "network_recon",
    "GetExtendedTcpTable": "network_recon",
    "WTSEnumerateSessions": "session_recon",
    "ClipCursor": "input_capture",
    "BlockInput": "input_capture",
    "GetDC": "screen_capture",
    "BitBlt": "screen_capture",
    "CreateDesktop": "desktop_manipulation",
    "SwitchDesktop": "desktop_manipulation",
}

SUSPICIOUS_PE_SECTIONS = {
    ".upx", ".packed", ".themida", ".vmp", ".enigma",
    ".aspack", ".crypted", ".morphine", ".y0da", ".y0da'",
    ".mpress", ".nsp0", ".nsp1", ".nsp2", ".psh",
    ".sxdata", ".tls", ".00cfg", ".rdata\x00\x00\x00\x00zp",
    ".adata", ".blk", ".bss\x00\x00\x00\x00\x00\x00xyz",
}


def _xp_for_level(level):
    return sum((l * 120 + (l - 1) * 60) for l in range(1, level))


def _level_from_xp(xp):
    level = 1
    while _xp_for_level(level + 1) <= xp:
        level += 1
    return level


def _pe_imports(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return []
    if len(data) < 64 or data[:2] != b"\x4d\x5a":
        return []
    pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
    if pe_off + 24 + 112 > len(data) or data[pe_off:pe_off+4] != b"PE\x00\x00":
        return []
    opt = pe_off + 24
    magic = struct.unpack("<H", data[opt:opt+2])[0]
    if magic not in (0x10b, 0x20b):
        return []
    ns = struct.unpack("<H", data[pe_off+6:pe_off+8])[0]
    ohs = struct.unpack("<H", data[pe_off+20:pe_off+22])[0]
    sec_off = pe_off + 24 + ohs
    ndirs = struct.unpack("<I", data[opt+92:opt+96])[0]
    if ndirs < 2:
        return []
    import_rva = struct.unpack("<I", data[opt+96:opt+100])[0]
    if import_rva == 0:
        return []
    sections = []
    for i in range(ns):
        s = sec_off + i * 40
        if s + 40 > len(data):
            break
        va = struct.unpack("<I", data[s+12:s+16])[0]
        vs = struct.unpack("<I", data[s+8:s+12])[0]
        ra = struct.unpack("<I", data[s+20:s+24])[0]
        sections.append((va, vs, ra))
    def rva2off(rva):
        for va, vs, ra in sections:
            if va <= rva < va + vs:
                return ra + (rva - va)
        return None
    imp_off = rva2off(import_rva)
    if imp_off is None:
        return []
    imports = []
    for di in range(100):
        ds = imp_off + di * 20
        if ds + 20 > len(data):
            break
        thunk = struct.unpack("<I", data[ds:ds+4])[0]
        if thunk == 0:
            break
        name_rva = struct.unpack("<I", data[ds+12:ds+16])[0]
        no = rva2off(name_rva)
        if no and no + 2 <= len(data):
            end = data.find(b"\x00", no)
            if end > no:
                dll = data[no:end].decode("ascii", errors="replace")
            toff = rva2off(thunk)
            if toff:
                for ti in range(500):
                    es = toff + ti * 4
                    if es + 4 > len(data):
                        break
                    t = struct.unpack("<I", data[es:es+4])[0]
                    if t == 0:
                        break
                    if t & 0x80000000:
                        continue
                    frva = t & 0x7fffffff
                    fo = rva2off(frva)
                    if fo and fo + 2 <= len(data):
                        fe = data.find(b"\x00", fo + 2)
                        if fe > fo + 2:
                            fn = data[fo+2:fe].decode("ascii", errors="replace").strip()
                            if fn:
                                imports.append(f"{dll}.{fn}")
    return imports


def _suspicious_sections(filepath):
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return results
    if len(data) < 64 or data[:2] != b"\x4d\x5a":
        return results
    pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
    if pe_off + 4 > len(data) or data[pe_off:pe_off+4] != b"PE\x00\x00":
        return results
    ns = struct.unpack("<H", data[pe_off+6:pe_off+8])[0]
    ohs = struct.unpack("<H", data[pe_off+20:pe_off+22])[0]
    sec_off = pe_off + 24 + ohs
    for i in range(min(ns, 40)):
        s = sec_off + i * 40
        if s + 40 > len(data):
            break
        name = data[s:s+8].rstrip(b"\x00").decode("ascii", errors="replace").lower()
        if name in SUSPICIOUS_PE_SECTIONS:
            results.append(name)
    return results


def _section_entropies(filepath):
    entropies = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return entropies
    if len(data) < 64 or data[:2] != b"\x4d\x5a":
        return entropies
    pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
    if pe_off + 4 > len(data) or data[pe_off:pe_off+4] != b"PE\x00\x00":
        return entropies
    ns = struct.unpack("<H", data[pe_off+6:pe_off+8])[0]
    ohs = struct.unpack("<H", data[pe_off+20:pe_off+22])[0]
    sec_off = pe_off + 24 + ohs
    for i in range(min(ns, 40)):
        s = sec_off + i * 40
        if s + 40 > len(data):
            break
        vs = struct.unpack("<I", data[s+8:s+12])[0]
        ra = struct.unpack("<I", data[s+20:s+24])[0]
        if ra > 0 and vs > 0 and ra + vs <= len(data):
            entropies.append(_shannon_entropy(data[ra:ra+vs]))
    return entropies


def _pe_compile_epoch(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read(0x100)
        if len(data) < 64 or data[:2] != b"\x4d\x5a":
            return None
        pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
        if pe_off + 8 > len(data):
            return None
        ts_raw = struct.unpack("<I", data[pe_off + 8:pe_off + 12])[0]
        if ts_raw == 0:
            return None
        return ts_raw
    except Exception:
        return None


def _has_rich_header(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read(4096)
        if data[:2] != b"\x4d\x5a":
            return False
        idx = data.find(b"Rich")
        if idx == -1:
            return False
        before = data[idx - 4:idx]
        xor_key = before[0] ^ ord("R")
        return all(b ^ xor_key == c for b, c in zip(before, b"Rich"))
    except Exception:
        return False


def _count_tls_callbacks(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if len(data) < 64 or data[:2] != b"\x4d\x5a":
            return 0
        pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
        if pe_off + 24 + 112 > len(data) or data[pe_off:pe_off+4] != b"PE\x00\x00":
            return 0
        opt = pe_off + 24
        magic = struct.unpack("<H", data[opt:opt+2])[0]
        if magic not in (0x10b, 0x20b):
            return 0
        ohs = struct.unpack("<H", data[pe_off+20:pe_off+22])[0]
        sec_off = pe_off + 24 + ohs
        ns = struct.unpack("<H", data[pe_off+6:pe_off+8])[0]
        ndirs = struct.unpack("<I", data[opt+92:opt+96])[0]
        if ndirs < 9:
            return 0
        tls_rva = struct.unpack("<I", data[opt + 96 + 8 * 9:opt + 96 + 8 * 9 + 4])[0]
        if tls_rva == 0:
            return 0
        sections = []
        for i in range(ns):
            s = sec_off + i * 40
            if s + 40 > len(data):
                break
            va = struct.unpack("<I", data[s+12:s+16])[0]
            vs = struct.unpack("<I", data[s+8:s+12])[0]
            ra = struct.unpack("<I", data[s+20:s+24])[0]
            sections.append((va, vs, ra))
        def rva2off(rva):
            for va, vs, ra in sections:
                if va <= rva < va + vs:
                    return ra + (rva - va)
            return None
        tls_off = rva2off(tls_rva)
        if tls_off is None or tls_off + 16 > len(data):
            return 0
        if magic == 0x10b:
            callbacks_va = struct.unpack("<I", data[tls_off+12:tls_off+16])[0]
        else:
            callbacks_va = struct.unpack("<Q", data[tls_off+24:tls_off+32])[0]
        cb_off = rva2off(callbacks_va & 0xffffffff)
        if cb_off is None:
            return 0
        count = 0
        for i in range(256):
            pos = cb_off + i * (4 if magic == 0x10b else 8)
            if pos + (4 if magic == 0x10b else 8) > len(data):
                break
            if magic == 0x10b:
                cb = struct.unpack("<I", data[pos:pos+4])[0]
            else:
                cb = struct.unpack("<Q", data[pos:pos+8])[0]
            if cb == 0:
                break
            count += 1
        return count
    except Exception:
        return 0


def _hash_similarity(hash1, hash2):
    if not hash1 or not hash2:
        return 0
    same = sum(1 for a, b in zip(hash1, hash2) if a == b)
    return same / max(len(hash1), len(hash2))


FEATURE_KEYS = [
    "size_bucket", "entropy_bucket", "ext_type", "is_pe",
    "imports_bucket", "sus_strings_bucket", "sections_bucket",
    "path_variety", "is_hidden", "null_ratio_bucket", "entropy_range_bucket",
    "long_strings_bucket",
    "compile_epoch_bucket", "rich_header", "tls_callbacks_bucket",
    "entropy_variance_bucket",
]


def _extract_features(filepath, file_hash=None, header=None, content=None):
    features = {}
    try:
        sz = os.path.getsize(filepath)
        if sz < 1024:
            features["size_bucket"] = "tiny"
        elif sz < 51200:
            features["size_bucket"] = "small"
        elif sz < 1048576:
            features["size_bucket"] = "medium"
        elif sz < 10485760:
            features["size_bucket"] = "large"
        else:
            features["size_bucket"] = "huge"
    except Exception:
        features["size_bucket"] = "unknown"

    ext = Path(filepath).suffix.lower()
    if ext in (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".com"):
        features["ext_type"] = "executable"
    elif ext in (".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf", ".rtf"):
        features["ext_type"] = "document"
    elif ext in (".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".py", ".pl", ".rb", ".php"):
        features["ext_type"] = "script"
    elif ext in (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"):
        features["ext_type"] = "archive"
    elif ext in (".png", ".jpg", ".gif", ".mp4", ".mp3", ".svg", ".webp"):
        features["ext_type"] = "media"
    elif ext == "":
        features["ext_type"] = "none"
    else:
        features["ext_type"] = "other"

    if header is None:
        try:
            with open(filepath, "rb") as f:
                header_data = f.read(16)
        except Exception:
            header_data = b""
    else:
        header_data = header[:16]
    features["is_pe"] = "yes" if header_data[:2] == b"\x4d\x5a" else "no"

    if content is None:
        try:
            with open(filepath, "rb") as f:
                entropy_data = f.read(65536)
        except Exception:
            entropy_data = b""
    else:
        entropy_data = content[:65536]
    entropy = _shannon_entropy(entropy_data) if entropy_data else 0
    if entropy < 3.0:
        features["entropy_bucket"] = "low"
    elif entropy < 5.5:
        features["entropy_bucket"] = "medium"
    elif entropy < 7.0:
        features["entropy_bucket"] = "high"
    else:
        features["entropy_bucket"] = "very_high"

    if entropy_data:
        nulls = entropy_data.count(b"\x00")
        null_ratio = nulls / max(1, len(entropy_data))
        if null_ratio < 0.01:
            features["null_ratio_bucket"] = "very_low"
        elif null_ratio < 0.05:
            features["null_ratio_bucket"] = "low"
        elif null_ratio < 0.15:
            features["null_ratio_bucket"] = "medium"
        elif null_ratio < 0.3:
            features["null_ratio_bucket"] = "high"
        else:
            features["null_ratio_bucket"] = "very_high"
    else:
        features["null_ratio_bucket"] = "unknown"

    if features["is_pe"] == "yes":
        se = _section_entropies(filepath)
        if se:
            e_min, e_max = min(se), max(se)
            erange = e_max - e_min
            if erange < 1.0:
                features["entropy_range_bucket"] = "flat"
            elif erange < 3.0:
                features["entropy_range_bucket"] = "narrow"
            elif erange < 5.0:
                features["entropy_range_bucket"] = "moderate"
            else:
                features["entropy_range_bucket"] = "wide"
            avg_sec_entropy = sum(se) / len(se)
            if avg_sec_entropy > 7.0:
                features["high_sec_entropy"] = "yes"
            else:
                features["high_sec_entropy"] = "no"
        else:
            features["entropy_range_bucket"] = "unknown"
            features["high_sec_entropy"] = "no"
    else:
        features["entropy_range_bucket"] = "none"
        features["high_sec_entropy"] = "no"

    imports = _pe_imports(filepath) if features["is_pe"] == "yes" else []
    sus_cats = defaultdict(int)
    for imp in imports:
        func = imp.split(".")[-1] if "." in imp else imp
        cat = SUSPICIOUS_IMPORTS.get(func) or SUSPICIOUS_IMPORTS.get(func.lower())
        if cat:
            sus_cats[cat] += 1
    n_cats = len(sus_cats)
    if n_cats == 0:
        features["imports_bucket"] = "none"
    elif n_cats <= 2:
        features["imports_bucket"] = "few"
    elif n_cats <= 5:
        features["imports_bucket"] = "several"
    else:
        features["imports_bucket"] = "many"

    sections = _suspicious_sections(filepath) if features["is_pe"] == "yes" else []
    n_sec = len(sections)
    if n_sec == 0:
        features["sections_bucket"] = "none"
    elif n_sec <= 1:
        features["sections_bucket"] = "one"
    else:
        features["sections_bucket"] = "multiple"

    try:
        if content is None:
            with open(filepath, "rb") as f:
                scan_content = f.read(min(sz, 65536))
        else:
            scan_content = content[:65536]
        sus_strs = [
            b"cmd.exe /c", b"powershell -", b"bypass", b"amsi",
            b"Invoke-", b"WScript.Shell", b"FileSystemObject",
            b"reverse_shell", b"backdoor", b"rootkit",
            b"keylog", b"portscan", b"DownloadString",
            b"DownloadFile", b"Start-Process",
            b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            b"ReflectiveLoader", b"meterpreter",
            b"YOUR_FILES_ARE_ENCRYPTED",
            b"crypt", b"BitLocker", b"shadow copy", b"vssadmin",
            b"bcdedit", b"bootkit", b"dropper", b"exploit",
            b"shellcode", b"inject", b"obfuscate", b"xor",
            b"ransom", b"encrypt", b"decrypt", b"CVE-",
            b"Persist", b"RunKey", b"Startup",
        ]
        found = sum(1 for s in sus_strs if s in scan_content)
    except Exception:
        found = 0
    if found == 0:
        features["sus_strings_bucket"] = "none"
    elif found <= 2:
        features["sus_strings_bucket"] = "few"
    elif found <= 5:
        features["sus_strings_bucket"] = "several"
    else:
        features["sus_strings_bucket"] = "many"

    long_count = 0
    try:
        txt = scan_content.decode("utf-8", errors="replace")
        import re
        tokens = re.findall(r'\S+', txt)
        long_count = sum(1 for t in tokens if len(t) > 50)
    except Exception:
        pass
    if long_count == 0:
        features["long_strings_bucket"] = "none"
    elif long_count <= 3:
        features["long_strings_bucket"] = "few"
    elif long_count <= 10:
        features["long_strings_bucket"] = "several"
    else:
        features["long_strings_bucket"] = "many"

    name = Path(filepath).name.lower()
    hidden = name.startswith(".") or (os.name == "nt" and bool(os.stat(filepath).st_file_attributes & 2)) if hasattr(os.stat_result, "st_file_attributes") else name.startswith(".")
    features["is_hidden"] = "yes" if hidden else "no"

    fpath_lower = filepath.lower()
    dl_dirs = ["download", "transferência", "temp", "tmp", "desktop", "área de trabalho"]
    in_dl = any(d in fpath_lower for d in dl_dirs)
    features["path_variety"] = "download" if in_dl else "other"

    if features["is_pe"] == "yes":
        epoch = _pe_compile_epoch(filepath)
        if epoch is None:
            features["compile_epoch_bucket"] = "none"
        else:
            if epoch < 1262304000:
                features["compile_epoch_bucket"] = "old"
            elif epoch < 1483228800:
                features["compile_epoch_bucket"] = "mid"
            else:
                features["compile_epoch_bucket"] = "recent"
        features["rich_header"] = "yes" if _has_rich_header(filepath) else "no"
        tls_count = _count_tls_callbacks(filepath)
        if tls_count == 0:
            features["tls_callbacks_bucket"] = "none"
        elif tls_count <= 2:
            features["tls_callbacks_bucket"] = "few"
        elif tls_count <= 5:
            features["tls_callbacks_bucket"] = "several"
        else:
            features["tls_callbacks_bucket"] = "many"
        se = _section_entropies(filepath)
        if se and len(se) > 1:
            mean = sum(se) / len(se)
            var = sum((e - mean) ** 2 for e in se) / len(se)
            std = var ** 0.5
            if std < 0.5:
                features["entropy_variance_bucket"] = "low"
            elif std < 1.5:
                features["entropy_variance_bucket"] = "moderate"
            elif std < 3.0:
                features["entropy_variance_bucket"] = "high"
            else:
                features["entropy_variance_bucket"] = "very_high"
        else:
            features["entropy_variance_bucket"] = "none"
    else:
        features["compile_epoch_bucket"] = "none"
        features["rich_header"] = "no"
        features["tls_callbacks_bucket"] = "none"
        features["entropy_variance_bucket"] = "none"

    return features


SEED_KNOWLEDGE = {
    "size_bucket=small": {"mal": 30, "safe": 60},
    "size_bucket=medium": {"mal": 60, "safe": 120},
    "size_bucket=large": {"mal": 80, "safe": 140},
    "size_bucket=tiny": {"mal": 20, "safe": 70},
    "size_bucket=huge": {"mal": 60, "safe": 160},
    "ext_type=executable": {"mal": 140, "safe": 100},
    "ext_type=script": {"mal": 110, "safe": 40},
    "ext_type=document": {"mal": 40, "safe": 130},
    "ext_type=archive": {"mal": 30, "safe": 70},
    "ext_type=media": {"mal": 8, "safe": 110},
    "ext_type=other": {"mal": 40, "safe": 100},
    "ext_type=none": {"mal": 20, "safe": 25},
    "entropy_bucket=high": {"mal": 100, "safe": 30},
    "entropy_bucket=very_high": {"mal": 140, "safe": 15},
    "entropy_bucket=medium": {"mal": 50, "safe": 110},
    "entropy_bucket=low": {"mal": 15, "safe": 150},
    "is_pe=yes": {"mal": 120, "safe": 80},
    "is_pe=no": {"mal": 50, "safe": 180},
    "imports_bucket=none": {"mal": 40, "safe": 80},
    "imports_bucket=few": {"mal": 80, "safe": 60},
    "imports_bucket=several": {"mal": 150, "safe": 20},
    "imports_bucket=many": {"mal": 200, "safe": 6},
    "sections_bucket=none": {"mal": 50, "safe": 80},
    "sections_bucket=one": {"mal": 100, "safe": 35},
    "sections_bucket=multiple": {"mal": 170, "safe": 8},
    "sus_strings_bucket=none": {"mal": 25, "safe": 100},
    "sus_strings_bucket=few": {"mal": 80, "safe": 50},
    "sus_strings_bucket=several": {"mal": 160, "safe": 15},
    "sus_strings_bucket=many": {"mal": 220, "safe": 4},
    "is_hidden=yes": {"mal": 70, "safe": 30},
    "is_hidden=no": {"mal": 80, "safe": 160},
    "path_variety=download": {"mal": 100, "safe": 70},
    "path_variety=other": {"mal": 60, "safe": 180},
    "null_ratio_bucket=very_low": {"mal": 90, "safe": 30},
    "null_ratio_bucket=low": {"mal": 70, "safe": 60},
    "null_ratio_bucket=medium": {"mal": 50, "safe": 120},
    "null_ratio_bucket=high": {"mal": 30, "safe": 100},
    "null_ratio_bucket=very_high": {"mal": 20, "safe": 80},
    "entropy_range_bucket=wide": {"mal": 120, "safe": 20},
    "entropy_range_bucket=flat": {"mal": 30, "safe": 90},
    "entropy_range_bucket=narrow": {"mal": 60, "safe": 70},
    "entropy_range_bucket=moderate": {"mal": 70, "safe": 100},
    "high_sec_entropy=yes": {"mal": 130, "safe": 25},
    "high_sec_entropy=no": {"mal": 50, "safe": 140},
    "long_strings_bucket=none": {"mal": 30, "safe": 110},
    "long_strings_bucket=few": {"mal": 80, "safe": 60},
    "long_strings_bucket=several": {"mal": 140, "safe": 20},
    "long_strings_bucket=many": {"mal": 200, "safe": 5},
    "compile_epoch_bucket=old": {"mal": 60, "safe": 80},
    "compile_epoch_bucket=mid": {"mal": 100, "safe": 60},
    "compile_epoch_bucket=recent": {"mal": 120, "safe": 50},
    "compile_epoch_bucket=none": {"mal": 40, "safe": 100},
    "rich_header=yes": {"mal": 130, "safe": 30},
    "rich_header=no": {"mal": 60, "safe": 150},
    "tls_callbacks_bucket=none": {"mal": 60, "safe": 120},
    "tls_callbacks_bucket=few": {"mal": 100, "safe": 40},
    "tls_callbacks_bucket=several": {"mal": 150, "safe": 15},
    "tls_callbacks_bucket=many": {"mal": 200, "safe": 5},
    "entropy_variance_bucket=none": {"mal": 50, "safe": 100},
    "entropy_variance_bucket=low": {"mal": 40, "safe": 90},
    "entropy_variance_bucket=moderate": {"mal": 80, "safe": 80},
    "entropy_variance_bucket=high": {"mal": 130, "safe": 25},
    "entropy_variance_bucket=very_high": {"mal": 170, "safe": 10},
}

_LEVEL_UP_MESSAGES = [
    "IA awakening...",
    "Learning patterns...",
    "Building knowledge...",
    "Sharpening instincts...",
    "Memory banks enriched",
    "Threat prediction enhanced",
    "Neural paths optimized",
    "Deep analysis unlocked",
    "Pattern recognition mastered",
    "AI consciousness expanding",
]


class JoguinIA:
    def __init__(self):
        self.weights = defaultdict(lambda: {"mal": 0, "safe": 0})
        self.xp = 0
        self._ai_correct = 0
        self._ai_total = 0
        self.known_hashes = {}
        self._streak = 0
        self._best_streak = 0
        self._last_level = 1
        self._load()
        if not self.weights:
            self._seed()
        self._last_level = self.level

    def _seed(self):
        for key, vals in SEED_KNOWLEDGE.items():
            self.weights[key] = dict(vals)

    def _load(self):
        try:
            if os.path.exists(KNOWLEDGE_FILE):
                with open(KNOWLEDGE_FILE) as f:
                    data = json.load(f)
                self.xp = data.get("xp", 0)
                self._ai_correct = data.get("correct", 0)
                self._ai_total = data.get("total", 0)
                self.known_hashes = data.get("hashes", {})
                self._streak = data.get("streak", 0)
                self._best_streak = data.get("best_streak", 0)
                raw = data.get("weights", {})
                for feat_val, counts in raw.items():
                    self.weights[feat_val] = counts
        except Exception:
            pass

    def _save(self):
        try:
            for key in list(self.weights.keys()):
                w = self.weights[key]
                w["mal"] = max(0, int(w["mal"] * 0.998))
                w["safe"] = max(0, int(w["safe"] * 0.998))
                if w["mal"] == 0 and w["safe"] == 0:
                    del self.weights[key]
            raw = {k: v for k, v in self.weights.items()}
            data = {
                "xp": self.xp,
                "correct": self._ai_correct,
                "total": self._ai_total,
                "hashes": self.known_hashes,
                "weights": raw,
                "streak": self._streak,
                "best_streak": self._best_streak,
            }
            with open(KNOWLEDGE_FILE, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    @property
    def level(self):
        return _level_from_xp(self.xp)

    @property
    def xp_for_next(self):
        return _xp_for_level(self.level + 1) - self.xp

    @property
    def accuracy(self):
        if self._ai_total == 0:
            return 0
        return round(self._ai_correct / self._ai_total * 100, 1)

    @property
    def pct_to_next(self):
        cl = _xp_for_level(self.level)
        nl = _xp_for_level(self.level + 1)
        if nl <= cl:
            return 100
        return min(100, (self.xp - cl) / (nl - cl) * 100)

    @staticmethod
    def _laplace_confidence(mal, safe, alpha=0.5):
        total = mal + safe
        if total == 0:
            return 50.0, total
        p = (mal + alpha) / (total + 2 * alpha)
        return round(p * 100, 1), total

    def _similar_hash_boost(self, file_hash, features):
        if not file_hash or len(self.known_hashes) < 3:
            return 0, 0
        best_sim = 0
        best_verdict = None
        for kh, kv in self.known_hashes.items():
            sim = _hash_similarity(file_hash, kh)
            if sim > best_sim:
                best_sim = sim
                best_verdict = kv
        mal_boost = 0
        safe_boost = 0
        if best_sim >= 0.85 and best_verdict:
            if best_verdict in ("malicious", "suspicious"):
                mal_boost += 60
            else:
                safe_boost += 60
        elif best_sim >= 0.70 and best_verdict:
            if best_verdict in ("malicious", "suspicious"):
                mal_boost += 30
            else:
                safe_boost += 30
        return mal_boost, safe_boost

    def analyze(self, filepath, file_hash=None, header=None, content=None):
        if not os.path.isfile(filepath):
            return {"risk": "unknown", "confidence": 0, "features": {}}
        features = _extract_features(filepath, file_hash=file_hash, header=header, content=content)
        if file_hash is None:
            file_hash = sha256_file(filepath)
        if file_hash and file_hash in self.known_hashes:
            verdict = self.known_hashes[file_hash]
            conf = 95
            return {"risk": verdict, "confidence": conf, "features": features, "hash_known": True}
        mal_score = 0
        safe_score = 0
        for feat, val in features.items():
            key = f"{feat}={val}"
            entry = self.weights.get(key, {"mal": 0, "safe": 0})
            mal_score += entry["mal"]
            safe_score += entry["safe"]
        sim_mal, sim_safe = self._similar_hash_boost(file_hash, features)
        mal_score += sim_mal
        safe_score += sim_safe
        confidence, samples = self._laplace_confidence(mal_score, safe_score)
        if samples == 0:
            risk = "unknown"
            confidence = 0
        elif confidence >= 72:
            risk = "malicious"
        elif confidence >= 48:
            risk = "suspicious"
        else:
            risk = "safe"
            confidence = 100 - confidence
        return {"risk": risk, "confidence": confidence, "features": features, "hash_known": False, "sim_boost": sim_mal > 0 or sim_safe > 0}

    def learn(self, filepath, actual_risk, file_hash=None, header=None, content=None, user_agreed=False):
        features = _extract_features(filepath, file_hash=file_hash, header=header, content=content)
        if file_hash is None:
            file_hash = sha256_file(filepath)
        is_threat = actual_risk in ("malicious", "suspicious")
        for feat, val in features.items():
            key = f"{feat}={val}"
            if is_threat:
                self.weights[key]["mal"] += 1
            else:
                self.weights[key]["safe"] += 1
        if file_hash:
            self.known_hashes[file_hash] = "malicious" if is_threat else "safe"
        ai = self.analyze(filepath, file_hash=file_hash, header=header, content=content)
        ai_risk = ai["risk"]
        if ai_risk == "unknown":
            pass
        elif (ai_risk == actual_risk) or (is_threat and ai_risk in ("malicious", "suspicious")):
            self._ai_correct += 1
            self._streak += 1
            if self._streak > self._best_streak:
                self._best_streak = self._streak
        else:
            self._streak = 0
        self._ai_total += 1

        if is_threat:
            xp_gain = 25
            if ai.get("confidence", 0) >= 70:
                xp_gain += 15
            elif ai.get("confidence", 0) >= 50:
                xp_gain += 8
            bonus_new = 10 if file_hash and file_hash not in self.known_hashes else 0
            xp_gain += bonus_new
            rarity = len(self.known_hashes)
            if rarity < 10:
                xp_gain += 20
            elif rarity < 50:
                xp_gain += 10
        else:
            xp_gain = 3
            if ai.get("confidence", 0) >= 60:
                xp_gain += 3

        if user_agreed:
            xp_gain = int(xp_gain * 1.5)
        if self._streak >= 5:
            xp_gain = int(xp_gain * 1.3)
        elif self._streak >= 10:
            xp_gain = int(xp_gain * 1.5)
        elif self._streak >= 20:
            xp_gain = int(xp_gain * 2.0)

        self.xp += xp_gain

        new_level = self.level
        if new_level > self._last_level:
            level_bonus = new_level * 50
            self.xp += level_bonus
            idx = min(new_level - 1, len(_LEVEL_UP_MESSAGES) - 1)
            msg = _LEVEL_UP_MESSAGES[idx]
            print(f"[IA] Level Up! {new_level} — {msg} (+{level_bonus} XP bonus)")
        self._last_level = new_level
        self._save()

    def learn_mistake(self, filepath, file_hash=None):
        features = _extract_features(filepath, file_hash=file_hash)
        if file_hash is None:
            file_hash = sha256_file(filepath)
        for feat, val in features.items():
            key = f"{feat}={val}"
            self.weights[key]["mal"] = max(0, self.weights[key]["mal"] - 2)
            self.weights[key]["safe"] = max(0, self.weights[key]["safe"] - 1)
        if file_hash and file_hash in self.known_hashes:
            del self.known_hashes[file_hash]
        self.xp = max(0, self.xp - 30)
        self._streak = 0
        self._save()

    def get_stats(self):
        return {
            "level": self.level,
            "xp": self.xp,
            "xp_for_next": self.xp_for_next,
            "pct_to_next": round(self.pct_to_next, 1),
            "accuracy": self.accuracy,
            "total": self._ai_total,
            "correct": self._ai_correct,
            "known_hashes": len(self.known_hashes),
            "patterns": len(self.weights),
            "streak": self._streak,
            "best_streak": self._best_streak,
        }
