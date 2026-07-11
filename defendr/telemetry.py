# Telemetry: communicates with DefendR Server (hardened)
import json
import os
import platform
import socket
import threading
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from defendr.constants import CONFIG_DIR
from defendr.filelock import safe_json_read, safe_json_write
from defendr.hardener import Sanitizer, PasswordHasher, InjectionDetector, RateLimiter

SERVER_URL = os.environ.get("DEFENDR_SERVER", "http://localhost:5000")
HEARTBEAT_INTERVAL = 60
MAX_RETRIES = 3


def _sanitize_payload(data):
    if isinstance(data, dict):
        return {k: _sanitize_payload(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_payload(v) for v in data]
    if isinstance(data, str):
        return Sanitizer.text(data)
    return data


class TelemetryClient:
    def __init__(self):
        self.uid = None
        self.username = None
        self.email = None
        self.user_info = {}
        self.pwd_hash = None
        self.config_file = os.path.join(CONFIG_DIR, "telemetry.json")
        self._login_limiter = RateLimiter(max_attempts=5, window=300)
        self._load_config()
        self._running = False
        self._thread = None
        if self.uid:
            self._start_heartbeat()

    def _load_config(self):
        data = safe_json_read(self.config_file)
        if data:
            self.uid = Sanitizer.text(data.get("uid", ""), 128) or None
            self.username = Sanitizer.text(data.get("username", ""), 64) or None
            self.email = Sanitizer.text(data.get("email", ""), 254) or None
            self.pwd_hash = Sanitizer.text(data.get("pwd_hash", ""), 128) or None

    def _save_config(self):
        safe_json_write(self.config_file, {
            "uid": self.uid,
            "username": self.username,
            "email": self.email,
            "pwd_hash": self.pwd_hash,
        })

    def is_registered(self):
        return self.uid is not None

    def get_username(self):
        return self.username or "Not logged in"

    def get_email(self):
        return self.email or ""

    def register(self, username, email, password):
        username = Sanitizer.username(username)
        email = Sanitizer.email(email)
        if not username or not email or not password:
            return False, "Invalid username, email, or password"
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if InjectionDetector.has_sql_injection(username) or InjectionDetector.has_sql_injection(email):
            return False, "Invalid characters detected"

        pwd_hash = PasswordHasher.hash_password(password)
        pc_info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        }
        payload = _sanitize_payload({
            "username": username, "email": email,
            "password_hash": pwd_hash, "pc_info": pc_info,
        })
        try:
            data = json.dumps(payload).encode()
            req = Request(f"{SERVER_URL}/api/register", data=data,
                          headers={"Content-Type": "application/json"})
            resp = urlopen(req, timeout=10)
            result = json.loads(resp.read())
            if result.get("status") == "ok":
                self.uid = Sanitizer.text(result.get("uid", ""), 128)
                self.username = username
                self.email = email
                self.pwd_hash = pwd_hash
                self._save_config()
                self._start_heartbeat()
                return True, "Registered successfully"
            return False, Sanitizer.text(result.get("error", "Registration failed"), 200)
        except HTTPError as e:
            try:
                body = e.read()
                err = json.loads(body)
                return False, Sanitizer.text(err.get("error", f"HTTP {e.code}"), 200)
            except Exception:
                return False, f"Server error: {e.code}"
        except URLError as e:
            return False, f"Server unreachable: {e.reason}"
        except Exception as e:
            return False, f"Connection error: {e}"

    def login(self, email, password):
        email = Sanitizer.email(email)
        if not email or not password:
            return False, "Invalid email or password"
        if not self._login_limiter.check(email):
            return False, "Too many login attempts. Try again later."

        pwd_hash = PasswordHasher.hash_password(password)
        payload = _sanitize_payload({
            "email": email, "password_hash": pwd_hash,
        })
        try:
            data = json.dumps(payload).encode()
            req = Request(f"{SERVER_URL}/api/login", data=data,
                          headers={"Content-Type": "application/json"})
            resp = urlopen(req, timeout=10)
            result = json.loads(resp.read())
            if result.get("status") == "ok":
                self.uid = Sanitizer.text(result["uid"], 128)
                self.username = Sanitizer.text(result.get("username", ""), 64)
                self.email = email
                self.pwd_hash = pwd_hash
                self.user_info = result
                self._login_limiter.reset(email)
                self._save_config()
                self._start_heartbeat()
                return True, "Logged in successfully"
            return False, Sanitizer.text(result.get("error", "Login failed"), 200)
        except HTTPError as e:
            try:
                body = e.read()
                err = json.loads(body)
                return False, Sanitizer.text(err.get("error", f"HTTP {e.code}"), 200)
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
        self.pwd_hash = None
        self._running = False
        self._save_config()

    def get_user_info(self):
        if not self.uid:
            return {}
        for attempt in range(MAX_RETRIES):
            try:
                req = Request(f"{SERVER_URL}/api/user/{self.uid}")
                resp = urlopen(req, timeout=10)
                info = json.loads(resp.read())
                self.user_info = _sanitize_payload(info)
                return self.user_info
            except Exception:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(1)
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
            payload = _sanitize_payload({"uid": self.uid})
            data = json.dumps(payload).encode()
            req = Request(f"{SERVER_URL}/api/heartbeat", data=data,
                          headers={"Content-Type": "application/json"})
            urlopen(req, timeout=5)
        except Exception:
            pass

    def send_report(self, report_type, message, report_data=None):
        if not self.uid:
            return
        payload = _sanitize_payload({
            "uid": self.uid, "type": report_type,
            "message": message, "data": report_data or {},
        })
        try:
            data = json.dumps(payload).encode()
            req = Request(f"{SERVER_URL}/api/report", data=data,
                          headers={"Content-Type": "application/json"})
            urlopen(req, timeout=10)
        except Exception:
            pass

    def send_scan_result(self, scan_type, results):
        if not self.uid:
            return
        payload = _sanitize_payload({
            "uid": self.uid, "scan_type": scan_type, "results": results,
        })
        try:
            data = json.dumps(payload).encode()
            req = Request(f"{SERVER_URL}/api/scan_result", data=data,
                          headers={"Content-Type": "application/json"})
            urlopen(req, timeout=10)
        except Exception:
            pass

    def send_error(self, error_type, message, traceback=""):
        if not self.uid:
            return
        payload = _sanitize_payload({
            "uid": self.uid, "type": error_type,
            "message": message, "traceback": traceback,
        })
        try:
            data = json.dumps(payload).encode()
            req = Request(f"{SERVER_URL}/api/error", data=data,
                          headers={"Content-Type": "application/json"})
            urlopen(req, timeout=10)
        except Exception:
            pass

    def stop(self):
        self._running = False
