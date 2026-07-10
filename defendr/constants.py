# Constants and configuration for DefendR
import os
from pathlib import Path

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

MALICIOUS_SIGS = (
    (b"\x4d\x5a\x90\x00", "PE (Windows executable)"),
    (b"\x7f\x45\x4c\x46", "ELF (Linux executable)"),
    (b"\x50\x4b\x03\x04", "ZIP/OLE2 container"),
    (b"\x1f\x8b\x08", "GZip compressed"),
    (b"\x89\x50\x4e\x47", "PNG image (possible stego)"),
)
SUSPICIOUS_EXTS = frozenset({".exe", ".dll", ".scr", ".ps1", ".vbs", ".vbe",
                    ".js", ".jse", ".wsf", ".hta", ".bat",
                    ".cmd", ".com", ".pif", ".jar", ".docm", ".xlsm"})
SUSPICIOUS_STRINGS = (
    b"CreateRemoteThread", b"VirtualAllocEx",
    b"WriteProcessMemory", b"GetProcAddress",
    b"ShellExecute", b"WinExec",
    b"cmd.exe /c", b"powershell -",
    b"base64", b"FromBase64",
    b"bypass", b"amsi", b"Invoke-",
    b"DownloadString", b"DownloadFile",
    b"Start-Process -Hidden",
    b"WScript.Shell", b"FileSystemObject")
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
