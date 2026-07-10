# 🛡 DefendR

**Advanced Antivirus & Security Suite** for Linux with PyQt5 GUI.

![DefendR Logo](https://raw.githubusercontent.com/derambrplays/DefendR/main/.github/logo.png)

## Features

- **File Scanner** — Signature + heuristic detection, whitelist for 87+ pentest tools
- **Real-Time Protection** — Watchdog monitors ~/Downloads, ~/Desktop, /tmp
- **Firewall** — iptables-based enable/disable/port blocking
- **Network Monitor** — ARP spoofing, DNS hijack, suspicious ports, C2 detection
- **Process Monitor** — PID/CPU/MEM/connections table with threat classification
- **Web Blocker** — Block domains via /etc/hosts
- **Anti-Phishing** — URL scoring (known domains, keywords, subdomains)
- **Sandbox** — Run files in firejail/bubblewrap with --net=none
- **Anti-Ransomware** — Monitor user dirs for encrypted file extensions
- **Rootkit Detector** — Hidden processes, suspicious kernel modules, LD_PRELOAD
- **Quarantine Manager** — Isolate/restore/delete threats with metadata
- **USB Scanner** — Auto-scan on mount
- **VPN Manager** — OpenVPN config management
- **Password Manager** — Encrypted vault with master password
- **Scheduler** — Recurring scans with interval
- **Signature Updater** — Pull latest signatures from GitHub
- **Game Mode** — Suppress notifications during fullscreen apps
- **WiFi Inspector** — Router port scan, credential check, continuous device monitor
- **Data Shredder** — 6 wipe standards (DoD, Gutmann 35-pass, Schneier, Nuke)
- **Software Updater** — Check apt/pip/flatpak/snap updates
- **Webcam Protection** — Monitor /dev/video*, block/unblock
- **DNS-over-HTTPS/DoT** — 4 providers with DNSSEC support
- **System Cleanup** — 14 categories with preview
- **Network Inspector** — ARP scan, router info, active connections
- **7 Languages** — PT, EN, ES, FR, DE, IT, RU

## Installation

```bash
git clone https://github.com/derambrplays/DefendR.git
cd DefendR
python3 install.py
```

The installer wizard will:
1. Select your language
2. Check dependencies (PyQt5, psutil)
3. Offer to install optional tools (firejail, nmap, openvpn)
4. Create desktop and menu shortcuts
5. Option to start DefendR

## Quick Start

```bash
python3 defendr.py
```

With root privileges (for firewall, DNS, webcam block):

```bash
python3 defendr.py --sudo
```

Or use the **DefendR (Root)** shortcut created by the installer.

## Requirements

- **Required:** Python 3, PyQt5, psutil
- **Optional:** firejail, nmap, openvpn, lsof

### Install dependencies

```bash
sudo apt install python3-pyqt5 python3-psutil
# Optional:
sudo apt install firejail nmap openvpn lsof
```

## Screenshots

*(coming soon)*

## License

MIT
