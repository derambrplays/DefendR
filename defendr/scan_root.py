#!/usr/bin/env python3
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DISPLAY"] = ":0"

from defendr.engine import DefendREngine

def emit(obj):
    print(json.dumps(obj), flush=True)

paths = json.loads(sys.argv[1])
mode = sys.argv[2]

engine = DefendREngine()
combined = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": []}

def on_progress(pct, msg):
    emit({"t": "p", "p": pct, "m": msg})

try:
    for path in paths:
        emit({"t": "s", "m": f"Scanning {path}..."})
        if mode == "completo":
            result = engine.scan_completo(path, progress_cb=on_progress)
        else:
            result = engine.scan_rapido(path, progress_cb=on_progress)
        for k in ("malicious", "suspicious", "pentest"):
            combined[k].extend(result.get(k, []))
        combined["safe"] += result.get("safe", 0)
        combined["errors"].extend(result.get("errors", []))
        if not engine.scanning:
            break
    emit({"t": "r", "d": combined})
except Exception as e:
    emit({"t": "e", "m": str(e)})
    sys.exit(1)
