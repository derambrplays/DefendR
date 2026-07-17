# Cloud reputation server and client for DefendR
import json
import os
import sqlite3
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.parse import urlencode

REPUTATION_DB = "/mnt/defendr/server/reputation.db"
FALLBACK_DB = os.path.expanduser("~/.defendr/reputation.db")
REPUTATION_PORT = 48126
REPUTATION_HOST = "0.0.0.0"  # Listen on all interfaces so LAN clients can connect
DEFAULT_SERVER_IP = "192.168.1.10"  # Central server IP
DEFAULT_SERVER_URL = f"http://{DEFAULT_SERVER_IP}:{REPUTATION_PORT}"
MAX_BODY_SIZE = 1024 * 1024


def _get_db_path():
    os.makedirs(os.path.dirname(REPUTATION_DB), exist_ok=True)
    return REPUTATION_DB


def _init_db():
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("CREATE TABLE IF NOT EXISTS reputation (hash TEXT PRIMARY KEY, malicious INTEGER DEFAULT 0, safe INTEGER DEFAULT 0, reports INTEGER DEFAULT 0, last_seen REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS submissions (hash TEXT, filename TEXT, timestamp REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS clients (machine_id TEXT PRIMARY KEY, hostname TEXT, last_seen REAL)")
    conn.commit()
    conn.close()


class ReputationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._json(200, {"status": "DefendR Reputation Server", "version": "1.0"})
        if self.path.startswith("/lookup/"):
            file_hash = self.path[8:]
            if len(file_hash) == 64:
                try:
                    conn = sqlite3.connect(_get_db_path(), timeout=10)
                    cur = conn.execute("SELECT malicious, safe, reports FROM reputation WHERE hash=?", (file_hash,))
                    row = cur.fetchone()
                    conn.close()
                    if row:
                        data = {"hash": file_hash, "malicious": row[0], "safe": row[1], "reports": row[2]}
                        self._json(200, data)
                    else:
                        self._json(404, {"error": "not found"})
                except Exception as e:
                    self._json(500, {"error": str(e)})
            else:
                self._json(400, {"error": "invalid hash"})
        elif self.path == "/register":
            try:
                conn = sqlite3.connect(_get_db_path(), timeout=10)
                cur = conn.execute("SELECT COUNT(DISTINCT machine_id) FROM clients WHERE last_seen > ?", (time.time() - 86400 * 7,))
                active = cur.fetchone()[0]
                conn.close()
                self._json(200, {"status": "ok", "active_clients": active})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif self.path == "/stats":
            try:
                conn = sqlite3.connect(_get_db_path(), timeout=10)
                cur = conn.execute("SELECT COUNT(*), COALESCE(SUM(malicious),0), COALESCE(SUM(safe),0) FROM reputation")
                total, mal_total, safe_total = cur.fetchone()
                cur2 = conn.execute("SELECT COUNT(DISTINCT machine_id) FROM clients WHERE last_seen > ?", (time.time() - 86400 * 7,))
                active_clients = cur2.fetchone()[0]
                conn.close()
                self._json(200, {"total_hashes": total, "total_malicious": mal_total, "total_safe": safe_total, "active_clients": active_clients})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif self.path == "/ping":
            self._json(200, {"status": "ok", "version": "1.0"})
        else:
            self._json(404, {"error": "unknown endpoint"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY_SIZE:
            self._json(413, {"error": "payload too large"})
            return
        body = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})
            return
        if self.path == "/report":
            file_hash = data.get("hash", "")
            verdict = data.get("verdict", "")
            if len(file_hash) == 64 and verdict in ("malicious", "safe"):
                try:
                    conn = sqlite3.connect(_get_db_path(), timeout=10)
                    cur = conn.execute("SELECT malicious, safe, reports FROM reputation WHERE hash=?", (file_hash,))
                    row = cur.fetchone()
                    if row:
                        mal = row[0] + (1 if verdict == "malicious" else 0)
                        saf = row[1] + (1 if verdict == "safe" else 0)
                        conn.execute("UPDATE reputation SET malicious=?, safe=?, reports=reports+1, last_seen=? WHERE hash=?", (mal, saf, time.time(), file_hash))
                    else:
                        mal = 1 if verdict == "malicious" else 0
                        saf = 1 if verdict == "safe" else 0
                        conn.execute("INSERT INTO reputation (hash, malicious, safe, reports, last_seen) VALUES (?,?,?,1,?)", (file_hash, mal, saf, time.time()))
                    conn.commit()
                    conn.close()
                    self._json(200, {"status": "reported"})
                except Exception as e:
                    self._json(500, {"error": str(e)})
            else:
                self._json(400, {"error": "invalid hash or verdict"})
        elif self.path == "/register":
            machine_id = data.get("machine_id", "")
            hostname = data.get("hostname", "")
            if not machine_id:
                self._json(400, {"error": "missing machine_id"})
                return
            try:
                conn = sqlite3.connect(_get_db_path(), timeout=10)
                conn.execute("INSERT OR REPLACE INTO clients (machine_id, hostname, last_seen) VALUES (?,?,?)",
                             (machine_id, hostname, time.time()))
                conn.commit()
                conn.close()
                self._json(200, {"status": "registered"})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "unknown endpoint"})

    def _json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass


class ReputationServer:
    def __init__(self, port=REPUTATION_PORT):
        self.port = port
        self._server = None
        self._thread = None
        self.running = False
        self.actual_port = None
        _init_db()

    def start(self):
        if self.running:
            return
        HTTPServer.allow_reuse_address = True
        for attempt in range(10):
            try:
                self._server = HTTPServer((REPUTATION_HOST, self.port + attempt), ReputationHandler)
                self.actual_port = self.port + attempt
                break
            except OSError:
                continue
        if not self._server:
            raise RuntimeError("Nenhuma porta disponivel (48126-48135)")

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.running = True

    def stop(self):
        if self._server:
            self._server.shutdown()
            self.running = False

    def is_running(self):
        return self.running


class ReputationClient:
    _MACHINE_ID = None

    @classmethod
    def machine_id(cls):
        if cls._MACHINE_ID is None:
            mid = uuid.uuid4().hex[:12]
            cls._MACHINE_ID = mid
        return cls._MACHINE_ID

    def __init__(self, server_url=None):
        self.server_url = server_url or DEFAULT_SERVER_URL
        self._port = REPUTATION_PORT
        self.cache = {}
        self.cache_ttl = 3600
        self._lock = threading.Lock()

    def check(self, file_hash):
        with self._lock:
            if file_hash in self.cache:
                entry = self.cache[file_hash]
                if time.time() - entry["time"] < self.cache_ttl:
                    return entry["data"]
        try:
            req = Request(f"{self.server_url}/lookup/{file_hash}")
            with urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            result = {"verdict": self._verdict(data), "malicious": data.get("malicious", 0), "safe": data.get("safe", 0)}
            with self._lock:
                self.cache[file_hash] = {"time": time.time(), "data": result}
            return result
        except Exception:
            return None

    def report(self, file_hash, verdict, filename=""):
        try:
            data = json.dumps({"hash": file_hash, "verdict": verdict, "filename": filename}).encode()
            req = Request(f"{self.server_url}/report", data=data, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=5):
                pass
            with self._lock:
                self.cache.pop(file_hash, None)
        except Exception:
            pass

    def _verdict(self, data):
        mal = data.get("malicious", 0)
        saf = data.get("safe", 0)
        total = mal + saf
        if total < 2:
            return "unknown"
        ratio = mal / total
        if ratio >= 0.7:
            return "malicious"
        elif ratio <= 0.2:
            return "safe"
        return "suspicious"

    def register(self):
        try:
            data = json.dumps({"machine_id": self.machine_id(), "hostname": os.uname().nodename}).encode()
            req = Request(f"{self.server_url}/register", data=data, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    def ping(self):
        try:
            req = Request(f"{self.server_url}/ping")
            with urlopen(req, timeout=3) as resp:
                return json.loads(resp.read())
        except Exception:
            return None
