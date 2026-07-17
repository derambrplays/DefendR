# Kernel Guard: eBPF-based realtime monitor
# Requires: bpfcc-tools, linux-headers-$(uname -r)
# Instalacao: apt install bpfcc-tools linux-headers-$(uname -r)
#
# Fallback: quando bcc nao esta disponivel, usa watchdog + inotify via /proc

import os
import threading
import time
import subprocess
import socket as sockmod
from collections import defaultdict

from defendr.constants import SUSPICIOUS_EXTS

SAFE_PATHS = frozenset({
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
    "/lib64/",
    "/etc/",
    "/home/kalleb/go/",
    "/usr/share/kali-themes/",
})

_EXEC_PROG = r"""
#include <uapi/linux/ptrace.h>
struct ev_t { u32 pid; u32 uid; u32 seq; char comm[16]; char fn[64]; };
BPF_HASH(events, u32, struct ev_t);
BPF_ARRAY(cnt, u32, 1);
static u32 nxt(void) { u32 k=0; u32*v=cnt.lookup(&k); u32 n=v?*v+1:1; cnt.update(&k,&n); return n; }
int kprobe____x64_sys_execve(struct pt_regs *ctx) {
    struct ev_t e={}; e.pid=bpf_get_current_pid_tgid()>>32; e.uid=bpf_get_current_uid_gid(); e.seq=nxt();
    bpf_get_current_comm(&e.comm,sizeof(e.comm));
    struct pt_regs *r=(struct pt_regs *)PT_REGS_PARM1(ctx);
    const char __user *fn=0; bpf_probe_read_kernel(&fn,sizeof(fn),&r->di);
    if(fn) bpf_probe_read_user_str(&e.fn,sizeof(e.fn),fn);
    events.update(&e.seq,&e); return 0;
}
"""

_OPENAT_PROG = r"""
#include <uapi/linux/ptrace.h>
#define P 64
struct ev_t { u32 pid; u32 uid; u32 seq; char comm[16]; char fname[P]; };
BPF_HASH(events, u32, struct ev_t);
BPF_ARRAY(cnt, u32, 1);
static u32 nxt(void) { u32 k=0; u32*v=cnt.lookup(&k); u32 n=v?*v+1:1; cnt.update(&k,&n); return n; }
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    const char __user *fn=(const char __user *)PT_REGS_PARM2(ctx);
    struct ev_t e={}; e.pid=bpf_get_current_pid_tgid()>>32; e.uid=bpf_get_current_uid_gid(); e.seq=nxt();
    bpf_get_current_comm(&e.comm,sizeof(e.comm));
    bpf_probe_read_user_str(&e.fname,sizeof(e.fname),fn);
    events.update(&e.seq,&e); return 0;
}
"""

_CONNECT_PROG = r"""
#include <uapi/linux/ptrace.h>
struct ev_t { u32 pid; u32 uid; u32 seq; u32 daddr; u16 dport; char comm[16]; };
BPF_HASH(events, u32, struct ev_t);
BPF_ARRAY(cnt, u32, 1);
static u32 nxt(void) { u32 k=0; u32*v=cnt.lookup(&k); u32 n=v?*v+1:1; cnt.update(&k,&n); return n; }
struct sa4 { u16 family; u16 port; u32 addr; u8 pad[8]; };
int kprobe____sys_connect(struct pt_regs *ctx) {
    void __user *addr=(void __user *)PT_REGS_PARM2(ctx); int al=(int)PT_REGS_PARM3(ctx);
    if(al<16) return 0;
    struct sa4 s={}; bpf_probe_read_user(&s,sizeof(s),addr); if(s.family!=2) return 0;
    struct ev_t e={}; e.pid=bpf_get_current_pid_tgid()>>32; e.uid=bpf_get_current_uid_gid(); e.seq=nxt();
    e.daddr=s.addr; e.dport=s.port; bpf_get_current_comm(&e.comm,sizeof(e.comm));
    events.update(&e.seq,&e); return 0;
}
"""


# Fallback: monitor baseado em /proc quando bcc nao disponivel
class ProcFallbackMonitor:
    def __init__(self, alert_cb):
        self.alert_cb = alert_cb
        self.active = False
        self._known_procs = {}
        self._alerted = set()

    def start(self):
        self.active = True
        self._known_procs = self._snapshot()
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def stop(self):
        self.active = False

    def _snapshot(self):
        procs = {}
        try:
            for p in os.listdir("/proc"):
                if not p.isdigit():
                    continue
                try:
                    with open(f"/proc/{p}/status") as f:
                        lines = f.readlines()
                    name = "?"
                    for l in lines:
                        if l.startswith("Name:"):
                            name = l.split(":")[1].strip()
                            break
                    procs[int(p)] = name
                except Exception:
                    continue
        except Exception:
            pass
        return procs

    def _run(self):
        while self.active:
            try:
                current = self._snapshot()
                new_pids = set(current) - set(self._known_procs)
                for pid in new_pids:
                    name = current[pid]
                    if name in ("python3", "python", "bash", "zsh", "sh", "systemd", "kworker"):
                        continue
                    path = f"/proc/{pid}/exe"
                    try:
                        exe = os.readlink(path)
                    except Exception:
                        exe = "?"
                    ext = os.path.splitext(exe)[1].lower()
                    key = f"kexec_{pid}"
                    if key not in self._alerted and ext in SUSPICIOUS_EXTS and not any(exe.startswith(p) for p in SAFE_PATHS):
                        self._alerted.add(key)
                        if self.alert_cb:
                            self.alert_cb("HIGH",
                                f"[Kernel] Novo processo: PID {pid} ({name}) - {exe}")
                self._known_procs = current
                time.sleep(1)
            except Exception:
                time.sleep(2)


class KernelGuard:
    def __init__(self, alert_callback=None, block_callback=None):
        self.alert_callback = alert_callback
        self.block_callback = block_callback
        self.active = False
        self._bpf_modules = []
        self._event_maps = {}
        self._last_seqs = {}
        self._thread = None
        self._fallback = None
        self._event_count = 0
        self._exec_rates = defaultdict(list)
        self._miner_ports = {3333, 3334, 3335, 3336, 4444, 5555, 7777, 8888,
                             14444, 33445, 42000, 42001, 42002}
        self._detected = set()
        self._bcc_available = False
        self._check_bcc()

    def _check_bcc(self):
        try:
            import bcc
            self._bcc_available = True
        except ImportError:
            self._bcc_available = False
        try:
            r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=3)
            kv = r.stdout.strip()
            parts = [int(x) for x in kv.split(".")[:2]]
            self._lsm_available = parts[0] >= 5 and parts[1] >= 4
        except Exception:
            self._lsm_available = False

    def start(self):
        if self.active:
            return True
        if self._bcc_available:
            try:
                return self._start_bcc()
            except Exception as e:
                print(f"[KernelGuard] BCC failed: {e}, using fallback")
        print("[KernelGuard] Usando fallback /proc (instale bpfcc-tools para eBPF)")
        self._fallback = ProcFallbackMonitor(self.alert_callback)
        self._fallback.start()
        self.active = True
        return False

    def _start_bcc(self):
        from bcc import BPF
        self._bpf_modules = []
        self._event_maps = {}

        for name, prog in [("exec", _EXEC_PROG), ("openat", _OPENAT_PROG), ("connect", _CONNECT_PROG)]:
            try:
                mod = BPF(text=prog)
                self._bpf_modules.append(mod)
                self._event_maps[name] = mod["events"]
            except Exception as e:
                print(f"[KernelGuard] Falha ao carregar kprobe_{name}: {e}")

        if not self._event_maps:
            return False

        self._last_seqs = {name: 0 for name in self._event_maps}
        self.active = True
        self._thread = threading.Thread(target=self._poll_bcc, daemon=True)
        self._thread.start()
        names = "+".join(self._event_maps.keys())
        print(f"[KernelGuard] eBPF carregado: {names}")
        return True

    def _poll_bcc(self):
        while self.active:
            for name, emap in list(self._event_maps.items()):
                try:
                    items = list(emap.items())
                    if not items:
                        continue
                    last = self._last_seqs.get(name, 0)
                    for k, v in items:
                        seq = v.seq
                        if seq <= last:
                            continue
                        if seq > last:
                            self._last_seqs[name] = seq
                        self._event_count += 1
                        if name == "exec":
                            self._on_exec(v)
                        elif name == "openat":
                            self._on_file_open(v)
                        elif name == "connect":
                            self._on_connect(v)
                    emap.clear()
                except Exception:
                    pass
            time.sleep(0.1)

    def _on_exec(self, ev):
        pid = ev.pid
        comm = bytes(ev.comm).decode("utf-8", errors="replace").rstrip("\x00")
        fn = bytes(ev.fn).decode("utf-8", errors="replace").rstrip("\x00")
        now = time.time()
        self._exec_rates[pid].append(now)
        self._exec_rates[pid] = [t for t in self._exec_rates[pid] if now - t < 5]
        if len(self._exec_rates[pid]) > 20:
            key = f"execburst_{pid}"
            if key not in self._detected:
                self._detected.add(key)
                self._alert("HIGH", f"[eBPF] Process burst PID {pid} ({comm}): {len(self._exec_rates[pid])} execs/5s")
        if any(fn.startswith(p) for p in SAFE_PATHS):
            return
        ext = os.path.splitext(fn)[1].lower()
        if ext in SUSPICIOUS_EXTS:
            key = f"exec_{pid}_{fn}"
            if key not in self._detected:
                self._detected.add(key)
                self._alert("MEDIUM", f"[eBPF] Exec: PID {pid} ({comm}) -> {fn}")

    def _on_file_open(self, ev):
        pass

    def _on_connect(self, ev):
        pid = ev.pid
        comm = bytes(ev.comm).decode("utf-8", errors="replace").rstrip("\x00")
        dport = socket_ntohs(ev.dport)
        daddr = socket_ntoa(ev.daddr)
        if dport in self._miner_ports:
            key = f"miner_{pid}_{dport}"
            if key not in self._detected:
                self._detected.add(key)
                self._alert("HIGH", f"[eBPF] Miner: PID {pid} ({comm}) -> {daddr}:{dport}")

    def _alert(self, severity, msg):
        if self.alert_callback:
            self.alert_callback(severity, f"{msg}")
        print(f"[KernelGuard] {severity}: {msg}")

    def stop(self):
        self.active = False
        if self._bpf_modules:
            for m in self._bpf_modules:
                try:
                    m.cleanup()
                except Exception:
                    pass
        if self._fallback:
            self._fallback.stop()
        self._bpf_modules = []
        self._event_maps = {}

    def get_stats(self):
        return {
            "bcc_available": self._bcc_available,
            "lsm_available": self._lsm_available,
            "active": self.active,
            "event_count": self._event_count,
            "detections": len(self._detected),
            "using_ebpf": bool(self._event_maps),
            "using_fallback": self._fallback is not None and self._fallback.active,
        }

    def install_deps(self):
        print("Instalando dependencias do KernelGuard:")
        cmds = [
            "apt-get update -qq",
            "apt-get install -y -qq bpfcc-tools linux-headers-$(uname -r)",
        ]
        for c in cmds:
            try:
                subprocess.run(c, shell=True, check=True, timeout=120)
                print(f"  OK: {c}")
            except subprocess.CalledProcessError as e:
                print(f"  FAIL: {c} -> {e}")
        print("Reinicie o DefendR para ativar o KernelGuard.")


def socket_ntohs(port):
    return sockmod.ntohs(port)

def socket_ntoa(addr):
    b = addr.to_bytes(4, "little")
    return sockmod.inet_ntoa(b)
