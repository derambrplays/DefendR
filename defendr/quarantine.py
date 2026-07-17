# Quarantine management with file locking, symlink safety, cross-fs support
import os, json, shutil, uuid, hashlib
from pathlib import Path
from datetime import datetime
from defendr.constants import QUARANTINE_DIR
from defendr.filelock import file_lock, safe_json_read, safe_json_write

class QuarantineManager:
    def __init__(self):
        self.quar_dir = QUARANTINE_DIR
        self.meta_file = os.path.join(QUARANTINE_DIR, "metadata.json")
        self.metadata = self._load_meta()
    def _load_meta(self):
        return safe_json_read(self.meta_file) or {}
    def _save_meta(self):
        safe_json_write(self.meta_file, self.metadata)
    def quarantine(self, filepath):
        fpath = Path(os.path.realpath(filepath))
        if not fpath.exists(): return False, "File not found"
        if fpath.is_symlink(): return False, "Cannot quarantine a symlink (resolve real path first)"
        qid = uuid.uuid4().hex[:12]
        dest = os.path.join(self.quar_dir, qid + fpath.suffix)
        try:
            shutil.move(str(fpath), dest)
        except shutil.Error:
            shutil.copy2(str(fpath), dest)
            os.remove(str(fpath))
        with open(dest, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        meta = {
            "original": str(fpath.resolve()),
            "quarantined": dest,
            "date": datetime.now().isoformat(),
            "hash": file_hash,
            "size": os.path.getsize(dest),
        }
        self.metadata[qid] = meta
        self._save_meta()
        return True, qid
    def restore(self, qid):
        if qid not in self.metadata: return False, "ID not found"
        info = self.metadata[qid]
        orig = Path(info["original"])
        orig.parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(info["quarantined"]):
            try:
                shutil.move(info["quarantined"], str(orig))
            except shutil.Error:
                shutil.copy2(info["quarantined"], str(orig))
                os.remove(info["quarantined"])
        del self.metadata[qid]
        self._save_meta()
        return True, str(orig)
    def delete_permanently(self, qid):
        if qid not in self.metadata: return False, "ID not found"
        info = self.metadata[qid]
        if os.path.exists(info["quarantined"]):
            try:
                os.remove(info["quarantined"])
            except OSError as e:
                return False, f"Falha ao excluir: {e}"
        del self.metadata[qid]
        self._save_meta()
        return True, "Deleted"
    def list_quarantined(self):
        self.metadata = self._load_meta()
        return list(self.metadata.items())
