# Simple file locking using fcntl.flock (Linux only)
import fcntl, os, contextlib

_lock_files = {}

@contextlib.contextmanager
def file_lock(path, timeout=5):
    path = os.path.abspath(path)
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        try: os.remove(lock_path)
        except: pass

def safe_json_read(path, default=None):
    if not os.path.exists(path): return default
    with file_lock(path):
        try:
            with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
                return json.load(f)
        except: return default

def safe_json_write(path, data):
    with file_lock(path):
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
