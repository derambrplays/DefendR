# Hardener: injection prevention, input sanitization, crypto helpers
import hashlib
import hmac
import json
import os
import re
import secrets
import string
from defendr.constants import CONFIG_DIR

SALT_FILE = os.path.join(CONFIG_DIR, ".salt")
ENCRYPTION_KEY_FILE = os.path.join(CONFIG_DIR, ".key")

_cleaners = {}


class Sanitizer:
    @staticmethod
    def text(value, max_len=4096):
        if not isinstance(value, str):
            value = str(value) if value is not None else ""
        value = value.strip()[:max_len]
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        return value

    @staticmethod
    def sql_aware(value, max_len=4096):
        value = Sanitizer.text(value, max_len)
        dangerous = ["'", '"', ";", "--", "/*", "*/", "xp_", "UNION", "SELECT",
                     "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
                     "EXEC", "OR 1=1", "OR '1'='1", "OR \"1\"=\"1"]
        lower = value.lower()
        result = []
        for word in value.split():
            if word.lower() in (d.lower() for d in dangerous):
                continue
            result.append(word)
        return " ".join(result)

    @staticmethod
    def email(value, max_len=254):
        value = Sanitizer.text(value, max_len).lower()
        email_re = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
        if not email_re.match(value):
            return ""
        return value

    @staticmethod
    def username(value, max_len=64):
        value = Sanitizer.text(value, max_len)
        value = re.sub(r'[^\w\-\.]', '', value)
        return value

    @staticmethod
    def filepath(value, max_len=4096):
        value = Sanitizer.text(value, max_len)
        value = re.sub(r'\.\./', '', value)
        value = re.sub(r'\.\.\\', '', value)
        value = re.sub(r'[\x00-\x1f\x7f]', '', value)
        return os.path.normpath(value)

    @staticmethod
    def domain(value, max_len=253):
        value = Sanitizer.text(value, max_len).lower()
        value = re.sub(r'[^a-zA-Z0-9\-\.]', '', value)
        return value

    @staticmethod
    def ip(value):
        value = Sanitizer.text(value, 45)
        ip_re = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_re.match(value):
            parts = value.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return value
        return ""

    @staticmethod
    def port(value):
        try:
            p = int(value)
            if 1 <= p <= 65535:
                return p
        except (ValueError, TypeError):
            pass
        return 0

    @staticmethod
    def json_safe(value):
        return json.dumps(value, ensure_ascii=False, default=str)

    @staticmethod
    def html(value, max_len=4096):
        value = Sanitizer.text(value, max_len)
        table = str.maketrans({
            '<': '&lt;', '>': '&gt;', '&': '&amp;',
            '"': '&quot;', "'": '&#x27;',
        })
        return value.translate(table)


class PasswordHasher:
    @staticmethod
    def _get_salt():
        if os.path.isfile(SALT_FILE):
            with open(SALT_FILE, "rb") as f:
                return f.read()
        salt = os.urandom(32)
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.chmod(CONFIG_DIR, 0o700)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        os.chmod(SALT_FILE, 0o600)
        return salt

    @staticmethod
    def hash_password(password, iterations=200000):
        salt = PasswordHasher._get_salt()
        if isinstance(password, str):
            password = password.encode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
        return dk.hex()

    @staticmethod
    def verify_password(password, stored_hash, iterations=200000):
        return hmac.compare_digest(
            PasswordHasher.hash_password(password, iterations),
            stored_hash
        )


class CryptoStore:
    @staticmethod
    def _get_key():
        if os.path.isfile(ENCRYPTION_KEY_FILE):
            with open(ENCRYPTION_KEY_FILE, "rb") as f:
                return f.read()
        key = os.urandom(32)
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.chmod(CONFIG_DIR, 0o700)
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(ENCRYPTION_KEY_FILE, 0o600)
        return key

    @staticmethod
    def encrypt(plaintext):
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from base64 import urlsafe_b64encode
        raw_key = CryptoStore._get_key()
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, b"defendr-crypto-v1", 100000)
        key = urlsafe_b64encode(kdf.derive(raw_key))
        f = Fernet(key)
        return f.encrypt(plaintext.encode() if isinstance(plaintext, str) else plaintext)

    @staticmethod
    def decrypt(token):
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from base64 import urlsafe_b64encode
        raw_key = CryptoStore._get_key()
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, b"defendr-crypto-v1", 100000)
        key = urlsafe_b64encode(kdf.derive(raw_key))
        f = Fernet(key)
        return f.decrypt(token)


class InjectionDetector:
    SQL_PATTERNS = [
        r"(?i)(\bunion\b.*\bselect\b)",
        r"(?i)(\bselect\b.*\bfrom\b)",
        r"(?i)(\binsert\b.*\binto\b)",
        r"(?i)(\bdelete\b.*\bfrom\b)",
        r"(?i)(\bdrop\b.*\btable\b)",
        r"(?i)(\balter\b.*\btable\b)",
        r"(?i)(\bcreate\b.*\btable\b)",
        r"(?i)(\bexec\b.*\bxp_)",
        r"(?i)(\bor\s+\d+\s*=\s*\d+)",
        r"(?i)[\'\"]\s*or\s+[\'\"].*[\'\"]\s*=\s*[\'\"]",
        r"(?i)(\bpg_sleep\b|\bwaitfor\b.*\bdelay\b|\bbenchmark\b)",
        r"--|#|/\*.*\*/",
    ]

    COMMAND_PATTERNS = [
        r"[;&|`\n]",
        r"(?i)(\$\()",
        r"(?i)(\{\$)",
        r"(?i)(\|[^\s])",
        r"(?i)(subprocess|os\.system|os\.popen|eval\(|exec\()",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.",
        r"[\\/]etc[\\/]passwd",
        r"[\\/]windows[\\/]system32",
    ]

    @staticmethod
    def has_sql_injection(value):
        if not isinstance(value, str):
            return False
        for pat in InjectionDetector.SQL_PATTERNS:
            if re.search(pat, value):
                return True
        return False

    @staticmethod
    def has_command_injection(value):
        if not isinstance(value, str):
            return False
        for pat in InjectionDetector.COMMAND_PATTERNS:
            if re.search(pat, value):
                return True
        return False

    @staticmethod
    def has_path_traversal(value):
        if not isinstance(value, str):
            return False
        for pat in InjectionDetector.PATH_TRAVERSAL_PATTERNS:
            if re.search(pat, value):
                return True
        return False

    @staticmethod
    def scan_for_injection(value):
        return {
            "sql": InjectionDetector.has_sql_injection(value),
            "command": InjectionDetector.has_command_injection(value),
            "path_traversal": InjectionDetector.has_path_traversal(value),
            "safe": not any([
                InjectionDetector.has_sql_injection(value),
                InjectionDetector.has_command_injection(value),
                InjectionDetector.has_path_traversal(value),
            ]),
        }


class RateLimiter:
    def __init__(self, max_attempts=5, window=60):
        self.max_attempts = max_attempts
        self.window = window
        self._attempts = {}

    def check(self, key):
        now = __import__("time").time()
        if key in self._attempts:
            self._attempts[key] = [t for t in self._attempts[key] if now - t < self.window]
            if len(self._attempts[key]) >= self.max_attempts:
                return False
            self._attempts[key].append(now)
        else:
            self._attempts[key] = [now]
        return True

    def reset(self, key):
        self._attempts.pop(key, None)
