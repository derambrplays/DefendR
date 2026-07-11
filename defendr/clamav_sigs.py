# ClamAV signature downloader and parser
import gzip
import json
import os
import tarfile
import io
import re
import struct
import time
import urllib.request
from defendr.constants import CONFIG_DIR

CLAMAV_MIRROR = "https://database.clamav.net"
CVD_DIR = os.path.join(CONFIG_DIR, "clamav_db")
PARSED_CACHE = os.path.join(CONFIG_DIR, "clamav_patterns.json")
USER_AGENT = "ClamAV/1.0.0"


def _download_cvd(name, retries=3):
    os.makedirs(CVD_DIR, exist_ok=True)
    path = os.path.join(CVD_DIR, name)
    if os.path.isfile(path):
        return path
    url = f"{CLAMAV_MIRROR}/{name}"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=300) as resp:
                total = int(resp.headers.get("content-length", 0))
                data = bytearray()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
                with open(path, "wb") as f:
                    f.write(data)
            return path
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(5 * (attempt + 1))
            else:
                raise


def _parse_cvd(path):
    with open(path, "rb") as f:
        raw = f.read()
    header_end = raw.index(b"\n")
    header_line = raw[:header_end].decode("ascii", errors="replace")
    parts = header_line.split(":")
    md5 = parts[4] if len(parts) > 4 else ""

    compressed = raw[512:]
    try:
        decompressed = gzip.decompress(compressed)
    except Exception:
        try:
            import lzma
            decompressed = lzma.decompress(compressed)
        except Exception:
            return []

    patterns = []
    buf = io.BytesIO(decompressed)
    try:
        with tarfile.open(fileobj=buf, mode="r:") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".ndb"):
                    f = tar.extractfile(member)
                    if not f:
                        continue
                    for line in f.read().decode("ascii", errors="replace").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            sig_name, target_type, offset, hex_sig = line.split(":", 3)
                            raw_bytes = bytes.fromhex(hex_sig)
                            if raw_bytes:
                                patterns.append((raw_bytes, sig_name[:80]))
                        except (ValueError, KeyError):
                            pass
    except Exception:
        pass

    return patterns


def load_clamav_patterns():
    if os.path.isfile(PARSED_CACHE):
        try:
            with open(PARSED_CACHE, "r") as f:
                data = json.load(f)
            return [(bytes.fromhex(h), n) for h, n in data]
        except Exception:
            pass
    return None


def save_clamav_patterns(patterns):
    data = [[p[0].hex(), p[1]] for p in patterns]
    with open(PARSED_CACHE, "w") as f:
        json.dump(data, f)


def update_signatures(progress_cb=None):
    all_pats = []
    if progress_cb:
        progress_cb(0, "Baixando daily.cvd...")
    try:
        daily_path = _download_cvd("daily.cvd", retries=3)
        if progress_cb:
            progress_cb(30, "Parseando daily.cvd...")
        daily_pats = _parse_cvd(daily_path)
        all_pats.extend(daily_pats)
    except Exception as e:
        if progress_cb:
            progress_cb(30, f"daily.cvd: {e}")

    if progress_cb:
        progress_cb(50, "Aguardando para baixar main.cvd...")
    time.sleep(10)
    try:
        main_path = _download_cvd("main.cvd", retries=5)
        if progress_cb:
            progress_cb(75, "Parseando main.cvd...")
        main_pats = _parse_cvd(main_path)
        all_pats.extend(main_pats)
    except Exception as e:
        if progress_cb:
            progress_cb(75, f"main.cvd: {e}")

    if progress_cb:
        progress_cb(95, f"Salvando {len(all_pats)} padrões...")

    seen = set()
    unique = []
    for b, n in all_pats:
        if b not in seen:
            seen.add(b)
            unique.append((b, n))

    save_clamav_patterns(unique)

    if progress_cb:
        progress_cb(100, f"{len(unique)} assinaturas carregadas")
    return unique
