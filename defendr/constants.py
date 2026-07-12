# Constants and configuration for DefendR
import os
from pathlib import Path

DARK_BG = "#1c1c1e"
DARK_MID = "#2c2c2e"
DARK_CARD = "#242426"
BORDER = "#3a3a3c"
TEXT = "#f5f5f7"
TEXT_DIM = "#8e8e93"
ACCENT = "#7c4dff"
ACCENT_LIGHT = "#b388ff"
ACCENT_DARK = "#5600e8"
GREEN = "#30d158"
RED = "#ff453a"
YELLOW = "#ffd60a"
CYAN = "#64d2ff"
FONT = "-apple-system, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', 'Segoe UI', system-ui, sans-serif"

QUARANTINE_DIR = os.path.expanduser("~/.defendr_quarantine")
CONFIG_DIR = os.path.expanduser("~/.defendr")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

PENTEST_WHITELIST = frozenset({
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
})

FILE_MAGIC_BYTES = (
    (b"\x4d\x5a\x90\x00", "PE (Windows executable)"),
    (b"\x7f\x45\x4c\x46", "ELF (Linux executable)"),
    (b"\x50\x4b\x03\x04", "ZIP/OLE2 container"),
    (b"\x1f\x8b\x08", "GZip compressed"),
    (b"\x89\x50\x4e\x47", "PNG image"),
    (b"\x25\x50\x44\x46", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound document"),
    (b"\xca\xfe\xba\xbe", "Java class file"),
    (b"\xef\xbb\xbf", "UTF-8 BOM text"),
)
SUSPICIOUS_EXTS = frozenset({".exe", ".dll", ".scr", ".ps1", ".vbs", ".vbe",
                    ".js", ".jse", ".wsf", ".hta", ".bat",
                    ".cmd", ".com", ".pif", ".jar", ".docm", ".xlsm",
                    ".sh", ".py", ".pl", ".rb", ".php", ".elf", ".bin"})

# Real malware YARA-like patterns (not just file types)
MALWARE_PATTERNS = (
    (b"CreateRemoteThread", "Process injection (CreateRemoteThread)"),
    (b"VirtualAllocEx", "Memory allocation (VirtualAllocEx)"),
    (b"WriteProcessMemory", "Process injection (WriteProcessMemory)"),
    (b"QueueUserAPC", "APC injection technique"),
    (b"SetWindowsHookEx", "Keylogging via hook"),
    (b"NtUnmapViewOfSection", "Process hollowing"),
    (b"ReflectiveLoader", "Reflective DLL injection"),
    (b"Metasploit", "Metasploit payload"),
    (b"meterpreter", "Meterpreter payload"),
    (b"shellcode", "Embedded shellcode"),
    (b"Msfvenom", "Msfvenom generated payload"),
    (b"cobaltstrike", "Cobalt Strike beacon"),
    (b"beacon.dll", "C2 beacon DLL"),
    (b"mimikatz", "Mimikatz credential dumper"),
    (b"Invoke-Mimikatz", "PowerShell Mimikatz"),
    (b"Invoke-", "PowerShell offensive script"),
    (b"DownloadString", "PowerShell remote download"),
    (b"DownloadFile", "File download via script"),
    (b"Start-Process -Hidden", "Hidden process execution"),
    (b"WScript.Shell", "Windows Script Host execution"),
    (b"FileSystemObject", "File system access via script"),
    (b"amsi", "AMSI bypass attempt"),
    (b"AMSI", "AMSI bypass attempt"),
    (b"bypass", "Potential bypass technique"),
    (b"powershell -enc", "Encoded PowerShell command"),
    (b"powershell -e ", "Encoded PowerShell command"),
    (b"base64", "Base64 encoded content"),
    (b"FromBase64", "Base64 decoding"),
    (b"cmd.exe /c", "Command execution via cmd"),
    # Linux malware patterns
    (b".connect(", "Network connection (potential reverse shell)"),
    (b"socket", "Socket network operation"),
    (b"subprocess.call", "Process execution via script"),
    (b"subprocess.Popen", "Process execution via script"),
    (b"/bin/sh", "Shell execution"),
    (b"/bin/bash", "Bash execution"),
    (b".locked", "Ransomware extension pattern"),
    (b".encrypted", "Ransomware extension pattern"),
    (b"ransomware", "Ransomware indicator"),
    (b"fork_bomb", "Fork bomb simulation"),
    (b"portscan", "Port scan tool"),
    (b"dos_sim", "DoS simulation script"),
    (b"masscan", "Masscan port scanner"),
    (b"nmap", "Nmap port scanner"),
    (b"hydra", "Hydra brute force tool"),
    (b"medusa", "Medusa brute force tool"),
    (b"reverse_shell", "Reverse shell script"),
    (b"backdoor", "Backdoor indicator"),
    (b"rootkit", "Rootkit indicator"),
    (b"keylog", "Keylogger indicator"),
    (b"sniff", "Packet sniffer"),
    (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "EICAR test malware (padrao internacional)"),
)

# System paths exempt from heavy scanning to reduce noise
SYSTEM_PATHS = frozenset({
    "/usr/lib", "/usr/share", "/usr/include", "/usr/src",
    "/usr/bin", "/usr/sbin", "/opt", "/snap",
    "/var/lib", "/var/cache", "/var/log",
    "/lib", "/lib64", "/lib32",
    "/sys", "/proc", "/dev", "/run",
})
SUSPICIOUS_STRINGS = (
    b"CreateRemoteThread", b"VirtualAllocEx",
    b"WriteProcessMemory", b"GetProcAddress",
    b"ShellExecute", b"WinExec",
    b"cmd.exe /c", b"powershell -",
    b"base64", b"FromBase64",
    b"bypass", b"amsi", b"Invoke-",
    b"DownloadString", b"DownloadFile",
    b"Start-Process -Hidden",
    b"WScript.Shell", b"FileSystemObject",
    b".connect(", b"socket", b"/bin/sh", b"/bin/bash",
    b"subprocess.call", b"subprocess.Popen",
    b".locked", b".encrypted", b"ransomware",
    b"reverse_shell", b"backdoor", b"rootkit",
    b"keylog", b"sniff", b"portscan", b"nmap",
    b"dup2", b"fileno")
SUSPICIOUS_PROCESSES = frozenset({
    "keylogger": "suspicious", "logkeys": "suspicious",
    "xnsniff": "suspicious", "xngrab": "suspicious",
    "wireshark": "network", "tshark": "network",
    "tcpdump": "network", "ettercap": "network",
})

MALICIOUS_DOMAINS = (
    "malware.com", "phishing.com", "trojan-bank.com",
    "fake-login.com", "steal-info.com", "ransomware.cc",
    "c2-server.net", "botnet-c2.com", "evil-domain.org",
)
PHISHING_KEYWORDS = ("login", "secure", "bank", "account", "verify",
                     "update", "confirm", "signin", "webmail", "paypal")

RANSOMWARE_EXTENSIONS = frozenset({".encrypted", ".locked", ".crypt", ".enc",
                         ".cryp1", ".locky", ".wncry", ".wcry",
                         ".onion", ".zepto", ".cerber", ".odin",
                         ".legion", ".ecc", ".exx", ".ezz",
                         ".zzz", ".xyz", ".aaa", ".ccc", ".vvv"})
