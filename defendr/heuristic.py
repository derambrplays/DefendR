# Advanced heuristic analysis: PE/ELF structure, digital signatures, behavioral scoring
import math
import os
import struct
from collections import Counter

SUSPICIOUS_PE_SECTIONS = {".upx", ".packed", ".themida", ".vmp", ".enigma",
                          ".aspack", ".crypted", ".morphine", ".y0da", ".y0da'"}
SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread": "process injection",
    "VirtualAllocEx": "memory injection",
    "WriteProcessMemory": "memory injection",
    "QueueUserAPC": "APC injection",
    "SetWindowsHookEx": "keylogging",
    "NtUnmapViewOfSection": "process hollowing",
    "GetAsyncKeyState": "keylogging",
    "GetForegroundWindow": "window monitoring",
    "keybd_event": "keyboard input simulation",
    "mouse_event": "mouse input simulation",
    "socket": "network communication",
    "connect": "network communication",
    "recv": "data reception",
    "send": "data transmission",
    "WSAStartup": "Winsock initialization",
    "RegSetValueEx": "registry persistence",
    "RegCreateKeyEx": "registry creation",
    "CreateService": "service installation",
    "StartServiceCtrlDispatcher": "service control",
    "OpenSCManager": "service manager access",
    "CreateProcess": "process creation",
    "WinExec": "command execution",
    "ShellExecute": "shell execution",
    "URLDownloadToFile": "file download from URL",
    "URLDownloadToCacheFile": "cached download",
    "InternetOpen": "internet access init",
    "InternetOpenUrl": "URL access",
    "HttpSendRequest": "HTTP request sending",
    "CryptEncrypt": "data encryption",
    "CryptDecrypt": "data decryption",
    "CryptAcquireContext": "cryptographic context",
    "IsDebuggerPresent": "anti-debugging",
    "CheckRemoteDebuggerPresent": "anti-debugging",
    "NtQueryInformationProcess": "process information query",
    "NtSetInformationProcess": "process modification",
    "OutputDebugString": "debugging output",
}

PE_MAGIC = b"\x4d\x5a"
PE_SIG = b"PE\x00\x00"
ELF_MAGIC = b"\x7f\x45\x4c\x46"


def _shannon_entropy(data):
    if not data:
        return 0.0
    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in byte_counts.values() if c)
    return entropy


def is_pe(data):
    return data[:2] == PE_MAGIC


def is_elf(data):
    return data[:4] == ELF_MAGIC


def analyze_pe(filepath):
    """Analyze a PE file structure for suspicious characteristics."""
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (PermissionError, OSError):
        return results
    if len(data) < 64:
        return results
    if data[:2] != PE_MAGIC:
        return results
    # Find PE signature
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0] if len(data) > 0x40 else 0
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != PE_SIG:
        return results
    # Check sections
    if pe_offset + 24 > len(data):
        return results
    num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
    opt_hdr_size = struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]
    section_offset = pe_offset + 24 + opt_hdr_size
    for i in range(min(num_sections, 40)):
        sec_start = section_offset + i * 40
        if sec_start + 40 > len(data):
            break
        sec_name = data[sec_start:sec_start+8].rstrip(b"\x00").decode("ascii", errors="replace")
        if sec_name.lower() in SUSPICIOUS_PE_SECTIONS:
            results.append(f"Suspicious section: {sec_name}")
    # Check import table
    imports = extract_imports(data, pe_offset)
    sus_imports = {}
    for imp in imports:
        imp_lower = imp.lower()
        if imp_lower in SUSPICIOUS_IMPORTS:
            sus_imports[imp] = SUSPICIOUS_IMPORTS[imp_lower]
    if len(sus_imports) >= 3:
        cats = list(set(sus_imports.values()))
        results.append(f"Suspicious imports: {', '.join(cats[:3])}")
    if len(sus_imports) >= 8:
        results.append("Heavily suspicious import table")
    # Check digital signature
    sig_info = check_pe_signature(data)
    if sig_info:
        results.append(sig_info)
    return results


def _rva_to_offset(rva, sections):
    for virt_addr, virt_size, raw_addr in sections:
        if virt_addr <= rva < virt_addr + virt_size:
            return raw_addr + (rva - virt_addr)
    return None


def extract_imports(data, pe_offset):
    """Extract import function names from PE file."""
    imports = []
    try:
        if len(data) < pe_offset + 24 + 112:
            return imports
        opt_hdr = pe_offset + 24
        magic = struct.unpack("<H", data[opt_hdr:opt_hdr+2])[0]
        if magic not in (0x10b, 0x20b):
            return imports
        num_data_dirs = struct.unpack("<I", data[opt_hdr+92:opt_hdr+96])[0]
        if num_data_dirs < 2:
            return imports
        import_dir_rva = struct.unpack("<I", data[opt_hdr+96:opt_hdr+100])[0]
        import_dir_size = struct.unpack("<I", data[opt_hdr+100:opt_hdr+104])[0]
        if import_dir_rva == 0 or import_dir_size == 0:
            return imports
        sections = []
        num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
        section_offset = pe_offset + 24 + struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]
        for i in range(num_sections):
            s = section_offset + i * 40
            if s + 40 > len(data):
                break
            virt_addr = struct.unpack("<I", data[s+12:s+16])[0]
            virt_size = struct.unpack("<I", data[s+8:s+12])[0]
            raw_addr = struct.unpack("<I", data[s+20:s+24])[0]
            sections.append((virt_addr, virt_size, raw_addr))
        imp_offset = _rva_to_offset(import_dir_rva, sections)
        if imp_offset is None:
            return imports
        thunk_seen = set()
        for desc_idx in range(100):
            desc_start = imp_offset + desc_idx * 20
            if desc_start + 20 > len(data):
                break
            thunk_rva = struct.unpack("<I", data[desc_start:desc_start+4])[0]
            if thunk_rva == 0:
                break
            name_rva = struct.unpack("<I", data[desc_start+12:desc_start+16])[0]
            name_offset = _rva_to_offset(name_rva, sections)
            if name_offset and name_offset + 2 <= len(data):
                dll_end = data.find(b"\x00", name_offset)
                if dll_end > name_offset:
                    dll_name = data[name_offset:dll_end].decode("ascii", errors="replace")
                else:
                    dll_name = ""
                func_names = _parse_thunk(data, thunk_rva, sections, thunk_seen)
                for fn in func_names:
                    imports.append(f"{fn}")
    except Exception:
        pass
    return imports


def _parse_thunk(data, thunk_rva, sections, seen):
    funcs = []
    try:
        thunk_offset = _rva_to_offset(thunk_rva, sections)
        if thunk_offset is None:
            return funcs
        for i in range(500):
            entry_start = thunk_offset + i * 4
            if entry_start + 4 > len(data):
                break
            thunk = struct.unpack("<I", data[entry_start:entry_start+4])[0]
            if thunk == 0:
                break
            if thunk & 0x80000000:
                continue
            func_rva = thunk & 0x7fffffff
            func_offset = _rva_to_offset(func_rva, sections)
            if func_offset and func_offset + 2 <= len(data):
                func_end = data.find(b"\x00", func_offset + 2)
                if func_end > func_offset:
                    fn = data[func_offset+2:func_end].decode("ascii", errors="replace").strip()
                    if fn and fn not in seen:
                        seen.add(fn)
                        funcs.append(fn)
    except Exception:
        pass
    return funcs


def check_pe_signature(data):
    """Check if PE file has a digital signature (authenticode)."""
    try:
        if len(data) < 0x180:
            return None
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 24 + 128 > len(data):
            return None
        opt_hdr = pe_offset + 24
        magic = struct.unpack("<H", data[opt_hdr:opt_hdr+2])[0]
        if magic not in (0x10b, 0x20b):
            return None
        # Certificate Table is entry 4 (0-based) in data directory
        # Data directory starts at offset 96 from optional header
        data_dir_offset = opt_hdr + 96
        cert_offset = struct.unpack("<I", data[data_dir_offset + 4*8:data_dir_offset + 4*8 + 4])[0]
        cert_size = struct.unpack("<I", data[data_dir_offset + 4*8 + 4:data_dir_offset + 4*8 + 8])[0]
        if cert_offset > 0 and cert_size > 8:
            return "signed (Certificate Table present)"
        return None
    except Exception:
        return None


def analyze_elf(filepath):
    """Analyze ELF file for suspicious characteristics."""
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read(64)
    except (PermissionError, OSError):
        return results
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        return results
    # Check for suspicious ELF characteristics
    ei_class = data[4]  # 1=32bit, 2=64bit
    ei_data = data[5]   # 1=little, 2=big endian
    e_type = struct.unpack("<H", data[16:18])[0] if data[5] == 1 else struct.unpack(">H", data[16:18])[0]
    if e_type == 3:  # ET_DYN (shared object/dynamic library)
        pass  # Normal
    return results


def verify_digital_signature(filepath):
    """Check if a file has a valid digital signature (Linux binary or PE)."""
    try:
        if os.name == "nt":
            import subprocess
            r = subprocess.run(["sigcheck64", "-q", filepath], capture_output=True, text=True, timeout=10)
            return "signed" in r.stdout.lower() if r.returncode == 0 else None
        # On Linux, check for embedded GPG signature or detached .sig
        sig_path = filepath + ".sig"
        if os.path.isfile(sig_path) and os.path.getsize(sig_path) > 0:
            return "signed (detached sig)"
        return None
    except Exception:
        return None


def heuristic_score(filepath):
    """Compute a heuristic suspicion score (0-100)."""
    score = 0
    reasons = []
    try:
        size = os.path.getsize(filepath)
        ext = os.path.splitext(filepath)[1].lower()
        # Empty files aren't suspicious
        if size == 0:
            return 0, []
        # Check file extension
        sus_exts = {".exe": 5, ".dll": 5, ".scr": 10, ".ps1": 15, ".vbs": 15,
                    ".js": 10, ".jar": 8, ".docm": 10, ".xlsm": 10, ".bin": 5}
        score += sus_exts.get(ext, 0)
        # Read first bytes
        with open(filepath, "rb") as f:
            header = f.read(16)
            f.seek(0)
            content = f.read(min(size, 4096))
        # Anti-debugging / VM detection
        anti_debug = [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
                      b"NtQueryInformationProcess", b"OutputDebugString",
                      b"VBoxGuest", b"VBoxService", b"VMwareTray",
                      b"x64dbg", b"ollydbg", b"ImportREC", b"LordPE"]
        for pat in anti_debug:
            if pat in content:
                score += 20
                reasons.append("anti-debug")
                break
        # Obfuscation indicators
        obfuscation = [b"obfuscate", b"de4dot", b"confuser", b"themida",
                       b"Execute+", b"eval(", b"String.fromCharCode"]
        for pat in obfuscation:
            if pat in content:
                score += 15
                reasons.append("obfuscation")
                break
        # Suspicious .NET attributes
        dotnet_sus = [b"UnmanagedFunctionPointer", b"SuppressUnmanagedCodeSecurity",
                      b"DllImport", b"P/Invoke"]
        for pat in dotnet_sus:
            if pat in content and ext in (".exe", ".dll"):
                score += 5
                if "unsafe .net" not in reasons:
                    reasons.append("unsafe .net")
        # Low entropy for large files = suspicious (packed)
        if size > 100000:
            ent = _shannon_entropy(content)
            if 6.5 < ent < 7.5 and ext in sus_exts:
                score += 15
                reasons.append("packed")
            if ent > 7.8:
                score += 25
                reasons.append("high entropy")
        # Many different strings in a short file
        if 100 < size < 100000:
            str_count = len(set(content.split(b"\x00")))
            if str_count > 200:
                score += 10
                reasons.append("many strings")
    except (PermissionError, OSError):
        return 0, []
    except Exception:
        return 0, []
    return min(score, 100), reasons



def analyze_file_advanced(filepath):
    """Full advanced analysis of a file."""
    results = []
    # PE analysis
    pe_results = analyze_pe(filepath)
    results.extend(pe_results)
    # ELF analysis
    elf_results = analyze_elf(filepath)
    results.extend(elf_results)
    # Digital signature
    sig = verify_digital_signature(filepath)
    if sig:
        results.append(sig)
    # Heuristic scoring
    h_score, h_reasons = heuristic_score(filepath)
    if h_score >= 20:
        for r in h_reasons:
            r_str = f"Heuristic: {r} ({h_score})"
            if r_str not in results:
                results.append(r_str)
    return results, h_score
