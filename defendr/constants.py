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

__version__ = "2.0.0"
QUARANTINE_DIR = os.path.expanduser("~/.defendr_quarantine")
CONFIG_DIR = os.path.expanduser("~/.defendr")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

PENTEST_WHITELIST = frozenset({
    "metasploit", "msfconsole", "msfvenom", "msf", "msfd", "msfrpc", "msfrpcd", "msfdb",
    "meterpreter",
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
    # Kali Linux extras
    "setoolkit", "set", "social engineering toolkit",
    "wpscan", "dirb", "tcpdump", "arp-scan", "dnsrecon",
    "enum4linux", "smbmap", "evil-winrm", "empire",
    "starkiller", "weevely", "commix", "whatweb",
    "lynis", "rkhunter", "chkrootkit",
    "volatility", "binwalk", "autopsy", "sleuthkit",
    "crunch", "cewl", "fcrackzip",
    "patator", "ncrack", "ophcrack",
    "yersinia", "macof", "dnsiff", "driftnet",
    "urlsnarf", "msgsnarf", "tcpxtract", "ngrep",
    "smbexec", "winexe", "psexec",
    "passing the hash", "pth-toolkit",
    "havoc", "mythic", "covenant",
    "dnsenum", "fierce", "dnsmap",
    "nbtscan", "onesixtyone",
    "snmpwalk", "smtp-user-enum", "swaks",
    "seclists", "rockyou",
    "crowbar", "samdump2",
    "cisco-auditing-tool",
    "hashid", "hash-identifier",
    "foremost", "steghide", "outguess",
    "peepdf", "pdf-parser", "pdfid",
    "exiftool", "mat2",
    "zeek", "bro", "snort", "suricata",
    "yara", "pe-sieve", "hollows-hunter",
    "apktool", "dex2jar", "jadx", "androguard",
    "mobsf", "objection", "frida",
    # Network & Wireless
    "kismet", "horst", "wash", "reaver", "bully",
    "pixiewps", "mdk4", "mdk3",
    "hping3", "nping", "mtr",
    "socat", "sslstrip", "sslsplit",
    "arpspoof", "dnsspoof", "dsniff",
    "macchanger", "iwconfig", "ifconfig", "iw",
    # Post-exploitation
    "powersploit", "powerup", "powerview",
    "bloodhound", "sharphound",
    "kerbrute", "rubeus", "kekeo",
    "pypykatz", "lsassy", "dumper",
    "seatbelt", "winpeas", "linpeas",
    "peas", "privesc", "exploit-suggester",
    "linux-exploit-suggester",
    "windows-exploit-suggester",
    # Web Application
    "acunetix", "appscan", "netsparker",
    "zap", "zed attack proxy",
    "caido", "proxyman",
    "xsstrike", "xsshunter", "xsser",
    "lfi", "rfi", "ssti", "ssrf",
    "csrf", "corsy", "cors-scanner",
    "jwt_tool", "jwt-cracker",
    "graphqlmap", "inql", 
    # Mobile
    "drozer", "mobile-security-framework",
    "adb", "android-sdk",
    # Privilege Escalation
    "gtfobins", "lolbas",
    "suid3num", "unix-privesc-check",
    "traitor", "les.sh",
    # Misc
    "upx", "themida", "vmp", "vmprotect",
    "confuser", "obfuscar",
    "dnspy", "dotpeek", "de4dot",
    "ilspy", "monodis",
    "cheatsheet", "payload", "exploit",
    "nishang", "unicorn",
    "pwncat", "pwncat-cs",
    "badusb", "ducky", "duckencoder",
    "kali", "parrot", "blackarch",
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

# Only high-specificity patterns — no pentest tool names (covered by whitelist)
MALWARE_PATTERNS = (
    (b"ReflectiveLoader", "Reflective DLL injection"),
    (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "EICAR test malware (padrao internacional)"),
    (b"/bin/bash -i >& /dev/tcp/", "Reverse shell (bash)"),
    (b"exec /bin/bash;", "Shell execution"),
    (b"/dev/tcp/", "Network shell connection"),
    (b"mkfifo /tmp/", "FIFO backdoor"),
    (b"nc -e /bin/sh", "Netcat reverse shell"),
    (b"ncat -e /bin/sh", "Ncat reverse shell"),
    (b"socat exec:", "Socat backdoor"),
    (b"bash -i >& /dev/tcp", "Reverse shell"),
    (b"msfvenom -p", "Metasploit payload generation"),
    (b"msfconsole -x", "Metasploit console automation"),
    (b"pwncat", "Pwncat RAT"),
    (b"chmod +s /bin/bash", "Privilege escalation (SUID)"),
    (b"chmod 4777", "SUID binary creation"),
    (b"python3 -c 'import pty", "PTY shell"),
    (b"perl -e 'use Socket", "Perl reverse shell"),
    (b"print \"\x7f\x45\x4c\x46\"", "ELF generation in script"),
    (b"meterpreter", "Meterpreter payload"),
    (b"cmd.exe /c powershell", "Windows command execution"),
    (b"CRYPTOMASTER", "Ransomware signature"),
    (b"YOUR_FILES_ARE_ENCRYPTED", "Ransomware note"),
    (b"YOUR FILES HAVE BEEN ENCRYPTED", "Ransomware note"),
    (b"ransomware", "Ransomware reference"),
    (b"encrypt_file(", "Encryption routine"),
    (b"decrypt_file(", "Decryption routine"),
    (b"0x9090909090909090", "NOP sled (shellcode)"),
    (b"\x31\xc0\x50\x68\x2f\x2f\x73\x68", "Shellcode: execve /bin/sh"),
    (b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68", "Shellcode: execve (alt)"),
    (b"\x6a\x0b\x58\x99\x52\x66\x68\x2d", "Shellcode: execve /bin/sh 64"),
)

# Paths excluded from all scans to reduce noise
DEFAULT_EXCLUDE = frozenset({
    "/node_modules/", "\\node_modules\\",
    "/.git/", "\\node_modules",
    "__pycache__/", ".cache/",
})
# System paths exempt from heavy scanning to reduce noise
# Only exclude critical system paths that never contain user-installed software
SYSTEM_PATHS = frozenset({
    "/usr/lib/modules/", "/usr/lib/firmware/", "/usr/share/locale/",
    "/usr/share/doc/", "/usr/share/man/", "/usr/include/", "/usr/src/",
    "/var/lib/apt/", "/var/lib/dpkg/", "/var/cache/", "/var/log/",
    "/lib/firmware/", "/lib/modules/",
    "/sys/", "/proc/", "/dev/",
    "/run/systemd/", "/run/dbus/", "/run/initramfs/",
    "/run/log/", "/run/udev/", "/run/NetworkManager/",
    "/run/lock/", "/run/mount/", "/run/user/",
})
SUSPICIOUS_STRINGS = (
    b"cmd.exe /c", b"powershell -",
    b"bypass", b"amsi", b"Invoke-",
    b"DownloadString", b"DownloadFile",
    b"Start-Process -Hidden",
    b"WScript.Shell", b"FileSystemObject",
    b".locked", b".encrypted", b"ransomware",
    b"reverse_shell", b"backdoor", b"rootkit",
    b"keylog", b"sniff", b"portscan")
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
