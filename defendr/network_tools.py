# Network tools: inspector, WiFi scanner, DNS over HTTPS
import os, subprocess, json, socket, threading, time, random, re, base64
from PyQt5 import QtCore
from defendr.constants import *

class NetworkInspector(QtCore.QObject):
    result_signal = QtCore.pyqtSignal(str, object)
    def __init__(self):
        super().__init__()
        self.scanning = False
    def arp_scan(self, interface=None):
        self.scanning = True
        try:
            import scapy.all as scapy
            if not interface:
                r = subprocess.run(["ip","route"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                for line in r.stdout.split("\n"):
                    if "default" in line:
                        parts = line.split()
                        interface = parts[-1] if len(parts) > 4 else None
                        break
            if not interface: interface = "eth0"
            import re as _re
            try:
                r2 = subprocess.run(["ip","-o","-f","inet","addr","show",interface], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                m = _re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', r2.stdout)
                if m:
                    ip_parts = m.group(1).split(".")
                    subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/{m.group(2)}"
                else:
                    subnet = "192.168.1.1/24"
            except:
                subnet = "192.168.1.1/24"
            arp_request = scapy.ARP(pdst=subnet)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered = scapy.srp(packet, timeout=3, iface=interface, verbose=False)[0]
            devices = []
            for sent, received in answered:
                devices.append({"ip": received.psrc, "mac": received.hwsrc})
            self.result_signal.emit("arp_scan", devices)
            self.scanning = False
            return devices
        except ImportError:
            self.result_signal.emit("error", "scapy not installed")
            self.scanning = False
            return []
        except Exception as e:
            self.result_signal.emit("error", str(e))
            self.scanning = False
            return []
    def router_info(self):
        info = {}
        try:
            r = subprocess.run(["ip","route"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            for line in r.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    info["gateway"] = parts[2]
                    if len(parts) > 4: info["interface"] = parts[4]
                    break
        except Exception: pass
        try:
            r = subprocess.run(["ip","addr","show"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            for line in r.stdout.split("\n"):
                m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m and not m.group(1).startswith("127."):
                    info["local_ip"] = m.group(1)
                    info["netmask"] = m.group(2)
                    break
        except Exception: pass
        try:
            r = subprocess.run(["nmcli","-t","-f","NAME,DEVICE,TYPE","connection","show","--active"],
                               capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            if r.returncode == 0:
                info["connections"] = [l for l in r.stdout.strip().split("\n") if l]
        except Exception: pass
        self.result_signal.emit("router_info", info)
        return info

class WiFiInspector(QtCore.QObject):
    result_signal = QtCore.pyqtSignal(str, object)
    device_signal = QtCore.pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.scanning = False
        self.monitoring = False
        self.known_devices = {}
    def scan_router(self):
        self.scanning = True
        results = {"gateway": "?", "open_ports": [], "warnings": [], "info": [], "firmware": "?"}
        try:
            r = subprocess.run(["ip","route"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            gateway = None
            for line in r.stdout.split("\n"):
                if "default" in line:
                    parts = line.split(); gateway = parts[2]; break
            if not gateway:
                results["error"]="No gateway found"
                self.result_signal.emit("wifi_scan", results)
                return results
            results["gateway"] = gateway
            nmap_r = subprocess.run(["nmap","-sT","-p","21,22,23,53,80,443,445,500,1723,1900,5351,8080,8443,49152-49156","--open","-n","-oG","-",gateway], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=90)
            results["nmap_output"] = nmap_r.stdout
            open_ports = re.findall(r"(\d+)/open", nmap_r.stdout)
            results["open_ports"] = open_ports
            port_risks = {"21":"FTP (unencrypted file transfer)","23":"Telnet (insecure remote access)","53":"DNS (possible DNS poisoning)","445":"SMB (vulnerable to EternalBlue)","500":"ISAKMP (VPN weak configs)","1723":"PPTP (outdated VPN protocol)","1900":"UPnP (device discovery, potential exploits)","5351":"NAT-PMP (router firewall bypass)"}
            for p in open_ports:
                if p in port_risks: results["warnings"].append(port_risks[p])
            if "80" in open_ports and "443" not in open_ports:
                results["warnings"].append("HTTP without HTTPS (login creds sent in clear text)")
            try:
                import urllib.request
                default_creds = [("admin","admin"),("admin","password"),("admin","1234"),("root","root"),("root","admin"),("user","user"),("guest","guest")]
                for user, pwd in default_creds:
                    try:
                        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                        req = urllib.request.Request(f"http://{gateway}/", headers={"Authorization":f"Basic {auth}"})
                        resp = urllib.request.urlopen(req, timeout=3)
                        if resp.status == 200:
                            results["warnings"].append(f"Router uses default login: {user}/{pwd}")
                            break
                    except Exception: pass
                pub = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode(errors='replace')
                results["public_ip"] = pub
            except Exception: pass
        except Exception as e:
            results["error"]=str(e)
        self.scanning = False
        self.result_signal.emit("wifi_scan", results)
        return results
    def start_monitoring(self):
        self.monitoring = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    def stop_monitoring(self):
        self.monitoring = False
    def _monitor_loop(self):
        while self.monitoring:
            try:
                devices = {}
                if os.path.exists("/proc/net/arp"):
                    with open("/proc/net/arp") as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                                devices[parts[0]] = parts[3]
                for ip, mac in devices.items():
                    if ip not in self.known_devices:
                        self.known_devices[ip] = mac
                        self.device_signal.emit(f"New device on network: {ip} ({mac})")
                    elif self.known_devices[ip] != mac:
                        self.device_signal.emit(f"Device {ip} changed MAC: {self.known_devices[ip]} -> {mac}")
                        self.known_devices[ip] = mac
                time.sleep(30)
            except Exception: time.sleep(30)

class DNSOverHTTPS:
    def __init__(self):
        self.providers = {
            "Cloudflare (1.1.1.1 + DoT)": {"ipv4": "1.1.1.1", "ipv6": "2606:4700:4700::1111", "doh": "https://cloudflare-dns.com/dns-query", "dot": "1dot1dot1dot1.cloudflare-dns.com"},
            "Quad9 (9.9.9.9 + DoT)": {"ipv4": "9.9.9.9", "ipv6": "2620:fe::fe", "doh": "https://dns.quad9.net/dns-query", "dot": "dns.quad9.net"},
            "Google (8.8.8.8 + DoT)": {"ipv4": "8.8.8.8", "ipv6": "2001:4860:4860::8888", "doh": "https://dns.google/dns-query", "dot": "dns.google"},
            "Mullvad (100.64.0.1, no-log)": {"ipv4": "194.242.2.2", "ipv6": "2a07:e340::2", "doh": "https://dns.mullvad.net/dns-query", "dot": "dns.mullvad.net"},
        }
        self.current = None
    def test_dns(self, ip):
        try:
            r = subprocess.run(["ping","-c1","-W2",ip], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            return r.returncode == 0
        except Exception: return False
    def set_dns(self, provider_key):
        if provider_key not in self.providers: return False, "Unknown provider"
        p = self.providers[provider_key]
        if not self.test_dns(p["ipv4"]): return False, f"DNS server {p['ipv4']} unreachable"
        try:
            resolvectl_ok = subprocess.run(["which","resolvectl"], capture_output=True, timeout=2).returncode == 0
            if resolvectl_ok:
                for iface in ["eth0","wlan0","wlp*"]:
                    subprocess.run(["resolvectl","dns",iface,p["ipv4"]], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                    subprocess.run(["resolvectl","dnsovertls",iface,"yes"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                    if "ipv6" in p: subprocess.run(["resolvectl","dns",iface,p["ipv6"]], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                subprocess.run(["resolvectl","default-route","eth0","true"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            else:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(f"# DefendR DNS-over-TLS: {provider_key}\n")
                    f.write(f"nameserver {p['ipv4']}\n")
                    if "ipv6" in p: f.write(f"nameserver {p['ipv6']}\n")
                    f.write("options use-vc timeout:2 attempts:1\n")
                    f.write("options edns0 trust-ad\n")
            self.current = provider_key
            return True, f"DNS set to {provider_key} with DoT"
        except PermissionError: return False, "Need root (sudo)"
        except Exception as e: return False, str(e)
    def reset_dns(self):
        try:
            resolvectl_ok = subprocess.run(["which","resolvectl"], capture_output=True, timeout=2).returncode == 0
            if resolvectl_ok: subprocess.run(["resolvectl","revert"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            else:
                with open("/etc/resolv.conf", "w") as f:
                    f.write("# Generated by NetworkManager\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n")
            self.current = None
            return True, "DNS reset to defaults"
        except PermissionError: return False, "Need root (sudo)"
        except Exception as e: return False, str(e)
    def enable_dnssec(self):
        try:
            resolvectl_ok = subprocess.run(["which","resolvectl"], capture_output=True, timeout=2).returncode == 0
            if resolvectl_ok:
                subprocess.run(["resolvectl","dnssec","yes"], capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=5)
                return True, "DNSSEC validation enabled"
            return False, "resolvectl not available"
        except Exception as e: return False, str(e)
    def get_current_dns(self):
        try:
            servers = []
            r = subprocess.run(["resolvectl","dns"], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", timeout=5)
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    if ":" in line and not line.startswith("Global"): servers.append(line.strip())
            if not servers:
                with open("/etc/resolv.conf") as f:
                    servers = [l.split()[1] for l in f if l.startswith("nameserver")]
            return servers if servers else ["No DNS configured"]
        except Exception: return ["Error reading DNS"]
