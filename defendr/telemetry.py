# Telemetry: communicates with DefendR Server
import os, json, threading, time, hashlib, platform, socket
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from defendr.constants import CONFIG_DIR
from defendr.filelock import safe_json_read, safe_json_write

SERVER_URL = "http://localhost:5000"
HEARTBEAT_INTERVAL = 60

class TelemetryClient:
    def __init__(self):
        self.uid = None
        self.username = None
        self.email = None
        self.user_info = {}
        self.config_file = os.path.join(CONFIG_DIR, "telemetry.json")
        self._load_config()
        self._running = False
        self._thread = None
        if self.uid:
            self._start_heartbeat()

    def _load_config(self):
        data = safe_json_read(self.config_file)
        if data:
            self.uid = data.get("uid")
            self.username = data.get("username")
            self.email = data.get("email")

    def _save_config(self):
        safe_json_write(self.config_file, {
            "uid": self.uid,
            "username": self.username,
            "email": self.email,
        })

    def is_registered(self):
        return self.uid is not None

    def get_username(self):
        return self.username or "Not logged in"

    def get_email(self):
        return self.email or ""

    def register(self, username, email, password):
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        pc_info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        }
        try:
            data = json.dumps({
                "username": username, "email": email.lower(),
                "password_hash": pwd_hash, "pc_info": pc_info,
            }).encode()
            req = Request(f"{SERVER_URL}/api/register", data=data,
                                  headers={"Content-Type": "application/json"})
            resp = urlopen(req, timeout=10)
            result = json.loads(resp.read())
            if result.get("status") == "ok":
                self.uid = result["uid"]
                self.username = result.get("username", username)
                self.email = result.get("email", email)
                self._save_config()
                self._start_heartbeat()
                return True, "Registered successfully"
            return False, result.get("error", "Registration failed")
        except HTTPError as e:
            try:
                body = e.read()
                err = json.loads(body)
                return False, err.get("error", f"HTTP {e.code}")
            except Exception:
                return False, f"Server error: {e.code}"
        except URLError as e:
            return False, f"Server unreachable: {e.reason}"
        except Exception as e:
            return False, f"Connection error: {e}"

    def login(self, email, password):
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            data = json.dumps({"email": email.lower(), "password_hash": pwd_hash}).encode()
            req = Request(f"{SERVER_URL}/api/login", data=data,
                                  headers={"Content-Type": "application/json"})
            resp = urlopen(req, timeout=10)
            result = json.loads(resp.read())
            if result.get("status") == "ok":
                self.uid = result["uid"]
                self.username = result.get("username", "")
                self.email = result.get("email", email)
                self.user_info = result
                self._save_config()
                self._start_heartbeat()
                return True, "Logged in successfully"
            return False, result.get("error", "Login failed")
        except HTTPError as e:
            try:
                body = e.read()
                err = json.loads(body)
                return False, err.get("error", f"HTTP {e.code}")
            except Exception:
                return False, f"Server error: {e.code}"
        except URLError as e:
            return False, f"Server unreachable: {e.reason}"
        except Exception as e:
            return False, f"Connection error: {e}"

    def logout(self):
        self.uid = None
        self.username = None
        self.email = None
        self.user_info = {}
        self._running = False
        self._save_config()

    def get_user_info(self):
        if not self.uid:
            return {}
        try:
            req = Request(f"{SERVER_URL}/api/user/{self.uid}")
            resp = urlopen(req, timeout=10)
            info = json.loads(resp.read())
            self.user_info = info
            return info
        except Exception:
            return self.user_info

    def _start_heartbeat(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()

    def _heartbeat_loop(self):
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            self._send_heartbeat()

    def _send_heartbeat(self):
        if not self.uid:
            return
        try:
            data = json.dumps({"uid": self.uid}).encode()
            req = Request(f"{SERVER_URL}/api/heartbeat", data=data,
                                  headers={"Content-Type": "application/json"})
            urlopen(req, timeout=5)
        except Exception:
            pass

    def send_report(self, report_type, message, report_data=None):
        if not self.uid:
            return
        try:
            data = json.dumps({
                "uid": self.uid, "type": report_type,
                "message": message, "data": report_data or {},
            }).encode()
            req = Request(f"{SERVER_URL}/api/report", data=data,
                                  headers={"Content-Type": "application/json"})
            urlopen(req, timeout=10)
        except Exception:
            pass

    def send_scan_result(self, scan_type, results):
        if not self.uid:
            return
        try:
            data = json.dumps({
                "uid": self.uid, "scan_type": scan_type, "results": results,
            }).encode()
            req = Request(f"{SERVER_URL}/api/scan_result", data=data,
                                  headers={"Content-Type": "application/json"})
            urlopen(req, timeout=10)
        except Exception:
            pass

    def send_error(self, error_type, message, traceback=""):
        if not self.uid:
            return
        try:
            data = json.dumps({
                "uid": self.uid, "type": error_type,
                "message": message, "traceback": traceback,
            }).encode()
            req = Request(f"{SERVER_URL}/api/error", data=data,
                                  headers={"Content-Type": "application/json"})
            urlopen(req, timeout=10)
        except Exception:
            pass

    def stop(self):
        self._running = False
