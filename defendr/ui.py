# Main UI: SplashScreen, MainWindow, all pages and handlers
import os, sys, json, subprocess, threading, time, socket, textwrap
from datetime import datetime
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import *
from defendr.engine import DefendREngine
from defendr.monitors import NetworkMonitor, RealTimeProtector, AntiRansomware, WebcamProtector, USBScanner, GameMode
from defendr.selfprotect import SelfProtection
from defendr.advanced_protection import AdvancedProtection
from defendr.security import FirewallManager, WebBlocker, AntiPhishing, SandboxManager, RootkitDetector
from defendr.tools import DataShredder, SoftwareUpdater, CleanupManager, PasswordManager, VPNManager
from defendr.network_tools import NetworkInspector, WiFiInspector, DNSOverHTTPS
from defendr.quarantine import QuarantineManager
from defendr.scheduler import Scheduler, SignatureUpdater
from defendr.lang import _
from defendr.telemetry import TelemetryClient

ALERT_SOUND = "/home/kalleb/Downloads/new-ford-chime.mp3"

def _play_alert_sound():
    try:
        uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or str(os.getuid()))
        if uid != os.geteuid():
            import pwd
            user = pwd.getpwuid(uid).pw_name
            pulse_server = f"unix:/run/user/{uid}/pulse/native"
            subprocess.Popen(
                ["/usr/sbin/runuser", "-u", user, "--",
                 "env", f"PULSE_SERVER={pulse_server}",
                 "play", "-q", ALERT_SOUND, "trim", "0", "2"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["play", "-q", ALERT_SOUND, "trim", "0", "2"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

class DropZone(QtWidgets.QLabel):
    dropped = QtCore.pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(QtCore.Qt.AlignCenter)
        self.setText("🎯 Arraste um arquivo aqui\npara escanear")
        self.setStyleSheet(f"""
            QLabel {{
                background: rgba(44,44,46,0.4);
                border: 2px dashed {BORDER};
                border-radius: 16px;
                color: {TEXT_DIM};
                font-size: 14px;
                padding: 40px;
            }}
            QLabel:hover {{
                border-color: {ACCENT};
                color: {TEXT};
                background: rgba(124,77,255,0.08);
            }}
        """)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(f"""
                QLabel {{
                    background: rgba(124,77,255,0.12);
                    border: 2px solid {ACCENT};
                    border-radius: 16px;
                    color: {ACCENT_LIGHT};
                    font-size: 14px;
                    padding: 40px;
                }}
            """)
    def dragLeaveEvent(self, event):
        self.setStyleSheet(f"""
            QLabel {{
                background: rgba(44,44,46,0.4);
                border: 2px dashed {BORDER};
                border-radius: 16px;
                color: {TEXT_DIM};
                font-size: 14px;
                padding: 40px;
            }}
        """)
    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.dropped.emit(path)
        self.setStyleSheet(f"""
            QLabel {{
                background: rgba(44,44,46,0.4);
                border: 2px dashed {BORDER};
                border-radius: 16px;
                color: {TEXT_DIM};
                font-size: 14px;
                padding: 40px;
            }}
        """)

# ===================== QTHREAD WORKERS =====================
class TaskWorker(QtCore.QThread):
    """Generic worker for running heavy tasks in background thread."""
    finished = QtCore.pyqtSignal(object)
    error = QtCore.pyqtSignal(str)

    def __init__(self, target, args=(), kwargs=None):
        super().__init__()
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def run(self):
        try:
            result = self._target(*self._args, **self._kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class ScanWorker(QtCore.QThread):
    """Dedicated worker for file scanning."""
    finished = QtCore.pyqtSignal(object)
    progress = QtCore.pyqtSignal(int, str)
    error = QtCore.pyqtSignal(str)
    result_found = QtCore.pyqtSignal(object)

    def __init__(self, engine, path, mode="rapido"):
        super().__init__()
        self.engine = engine
        self.path = path
        self.mode = mode

    def run(self):
        try:
            paths = self.path if isinstance(self.path, list) else [self.path]
            import os as os_mod
            if os_mod.geteuid() != 0:
                self._run_as_root(paths)
                return
            combined = self._run_direct(paths)
            self.finished.emit(combined)
        except Exception as e:
            self.error.emit(str(e))

    def _run_direct(self, paths):
        combined = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": []}
        def on_progress(count, msg):
            self.progress.emit(count, msg)
        def on_result(r):
            self.result_found.emit(r)
        for path in paths:
            result = self.engine.scan_with_level(path, level=self.mode, progress_cb=on_progress, result_cb=on_result)
            combined["malicious"].extend(result.get("malicious", []))
            combined["suspicious"].extend(result.get("suspicious", []))
            combined["pentest"].extend(result.get("pentest", []))
            combined["safe"] += result.get("safe", 0)
            combined["errors"].extend(result.get("errors", []))
        return combined

    def _run_as_root(self, paths):
        import subprocess, json, os as os_mod
        script = "/usr/local/bin/defendr-sudo.sh"
        args = [json.dumps(paths), self.mode]
        self.progress.emit(-1, _("Solicitando permissão de root..."))
        self._hd_proc = subprocess.Popen(
            ["pkexec", script, "scan"] + args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        combined = {"malicious": [], "suspicious": [], "pentest": [], "safe": 0, "errors": []}
        for line in self._hd_proc.stdout:
            line = line.strip()
            if not line:
                continue
            if not self.engine.scanning:
                self._hd_proc.kill()
                break
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = obj.get("t")
            if t == "p":
                self.progress.emit(obj.get("p", 0), obj.get("m", ""))
            elif t == "s":
                self.progress.emit(-1, obj.get("m", ""))
            elif t == "r":
                combined = obj.get("d", combined)
            elif t == "e":
                self.error.emit(obj.get("m", "Erro desconhecido"))
                return
        self._hd_proc.wait()
        err = self._hd_proc.stderr.read().strip()
        if self._hd_proc.returncode != 0 and self._hd_proc.returncode is not None:
            if self.engine.scanning:
                self.error.emit(_("Scan como root falhou (código %d): %s") % (self._hd_proc.returncode, err[:200] if err else _("senha cancelada")))
            return
        self._hd_proc = None
        self.finished.emit(combined)

class SplashScreen(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.Tool)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setFixedSize(520, 380)

        screen = QtWidgets.QApplication.primaryScreen().geometry()
        x = (screen.width() - 520) // 2
        y = (screen.height() - 380) // 2
        self.setGeometry(x, y, 520, 380)

        splash_img = os.path.join(os.path.dirname(__file__), "splash.png")
        if os.path.exists(splash_img):
            self._bg = QtGui.QPixmap(splash_img)
        else:
            self._bg = None
        self._progress = 0.0
        self._target = 0.0
        self._message = ""

        self._anim_timer = QtCore.QTimer()
        self._anim_timer.timeout.connect(self._tick)
        self._anim_timer.start(16)

        self.setStyleSheet("background: transparent;")
        self.show()

    def draw(self, message, target=0):
        self._message = message
        self._target = float(target)

    def finish(self, widget):
        self._target = 100
        self._message = ""
        self.repaint()
        widget.show()
        QtCore.QTimer.singleShot(300, self.close)

    def _tick(self):
        diff = self._target - self._progress
        if abs(diff) > 0.5:
            self._progress += diff * 0.12
        else:
            self._progress = self._target
        self.repaint()

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setRenderHint(QtGui.QPainter.SmoothPixmapTransform)

        w, h = self.width(), self.height()
        r = 24

        p.setBrush(QtGui.QColor(0, 0, 0, 100))
        p.setPen(QtCore.Qt.NoPen)
        p.drawRoundedRect(self.rect().adjusted(2, 6, -2, -2), r, r)

        p.setBrush(QtGui.QColor(DARK_BG))
        p.setPen(QtCore.Qt.NoPen)
        p.drawRoundedRect(self.rect().adjusted(2, 2, -2, -2), r, r)

        clip_rect = self.rect().adjusted(2, 2, -2, -2)
        p.setClipRect(clip_rect)
        p.setClipping(True)

        if self._bg:
            scaled = self._bg.scaled(w - 4, h - 4, QtCore.Qt.KeepAspectRatioByExpanding, QtCore.Qt.SmoothTransformation)
            sx = (w - 4 - scaled.width()) // 2
            sy = (h - 4 - scaled.height()) // 2
            p.setOpacity(0.15)
            p.drawPixmap(sx + 2, sy + 2, scaled)

        p.setOpacity(1.0)
        p.setClipping(False)

        grad = QtGui.QLinearGradient(0, 0, w, 0)
        grad.setColorAt(0.0, QtGui.QColor(ACCENT))
        grad.setColorAt(0.5, QtGui.QColor(ACCENT_LIGHT))
        grad.setColorAt(1.0, QtGui.QColor(ACCENT))
        p.setBrush(grad)
        p.drawRoundedRect(QtCore.QRect(22, 22, w - 44, 3), 2, 2)

        icon_size = 72
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        if os.path.exists(icon_path):
            icon_pix = QtGui.QPixmap(icon_path)
            scaled_icon = icon_pix.scaled(icon_size, icon_size, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
            ix = (w - scaled_icon.width()) // 2
            p.drawPixmap(ix, 40, scaled_icon)
        else:
            p.setPen(QtCore.Qt.NoPen)
            p.setBrush(QtGui.QColor(ACCENT))
            shield_r = QtCore.QRect((w - icon_size)//2, 40, icon_size, icon_size)
            p.drawRoundedRect(shield_r, 14, 14)
            p.setPen(QtGui.QColor(TEXT))
            sf = QtGui.QFont("Segoe UI", 30, QtGui.QFont.Bold)
            p.setFont(sf)
            p.drawText(shield_r, QtCore.Qt.AlignCenter, "D")

        p.setPen(QtGui.QColor(TEXT))
        tf = QtGui.QFont("Segoe UI", 26, QtGui.QFont.Bold)
        p.setFont(tf)
        p.drawText(QtCore.QRect(0, 122, w, 50), QtCore.Qt.AlignCenter, "DefendR")

        p.setPen(QtGui.QColor(ACCENT_LIGHT))
        sf2 = QtGui.QFont("Segoe UI", 12)
        p.setFont(sf2)
        p.drawText(QtCore.QRect(0, 166, w, 25), QtCore.Qt.AlignCenter, "Advanced Protection")

        p.setPen(QtGui.QColor(150, 150, 150))
        vf = QtGui.QFont("Segoe UI", 9)
        p.setFont(vf)
        p.drawText(QtCore.QRect(0, 188, w, 20), QtCore.Qt.AlignCenter, "v2.0.0")

        bar_x, bar_y = 50, 250
        bar_w, bar_h = w - 100, 6

        p.setBrush(QtGui.QColor(DARK_MID))
        p.setPen(QtCore.Qt.NoPen)
        p.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 3, 3)

        pct = max(0, min(100, self._progress))
        if pct > 0:
            fill_w = int(bar_w * pct / 100)
            if fill_w > 0:
                g2 = QtGui.QLinearGradient(bar_x, 0, bar_x + bar_w, 0)
                g2.setColorAt(0.0, QtGui.QColor(ACCENT))
                g2.setColorAt(1.0, QtGui.QColor(ACCENT_LIGHT))
                p.setBrush(g2)
                p.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 3, 3)

        p.setPen(QtGui.QColor(ACCENT_LIGHT))
        pf = QtGui.QFont("Segoe UI", 10, QtGui.QFont.Bold)
        p.setFont(pf)
        p.drawText(QtCore.QRect(bar_x, bar_y - 22, bar_w, 20), QtCore.Qt.AlignCenter, f"{int(pct)}%")

        if self._message:
            p.setPen(QtGui.QColor(200, 200, 200))
            mf = QtGui.QFont("Segoe UI", 10)
            p.setFont(mf)
            p.drawText(QtCore.QRect(20, bar_y + 18, w - 40, 20), QtCore.Qt.AlignCenter, self._message)

        p.end()

class IntrusionPopup(QtWidgets.QWidget):
    def __init__(self, title, message, severity="HIGH", source_ip="", attack_type="", parent=None):
        super().__init__(parent)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.Tool)
        self.setAttribute(QtCore.Qt.WA_ShowWithoutActivating)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")

        # Position: top-right corner, below clock area
        screen = QtWidgets.QApplication.primaryScreen().geometry()
        w, h = 420, 160
        margin = 12
        x = screen.width() - w - margin
        y = margin + 28
        self.setGeometry(x, y, w, h)

        colors = {"HIGH": ("#ff453a", "#ff3b30"), "MEDIUM": ("#ffd60a", "#ff9500"), "LOW": ("#30d158", "#34c759")}
        main_color, accent = colors.get(severity, colors["HIGH"])

        frame = QtWidgets.QFrame(self)
        frame.setGeometry(0, 0, w, h)
        frame.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #2c2c2e, stop:1 #1c1c1e);
                border: 2px solid {main_color};
                border-radius: 14px;
            }}
        """)
        shadow = QtWidgets.QGraphicsDropShadowEffect(frame)
        shadow.setBlurRadius(30)
        shadow.setOffset(0, 4)
        shadow.setColor(QtGui.QColor(0, 0, 0, 120))
        frame.setGraphicsEffect(shadow)

        icon = QtWidgets.QLabel("🛑" if severity == "HIGH" else "⚠️", frame)
        icon.setStyleSheet("font-size: 28px; background: transparent;")
        icon.move(14, 14)
        icon.resize(36, 36)

        title_lbl = QtWidgets.QLabel(title, frame)
        title_lbl.setStyleSheet(f"font-size: 15px; font-weight: 700; color: {main_color}; background: transparent;")
        title_lbl.move(56, 14)
        title_lbl.resize(w - 70, 22)

        sev_lbl = QtWidgets.QLabel(f"[{severity}] {attack_type}", frame)
        sev_lbl.setStyleSheet(f"font-size: 11px; color: {accent}; background: transparent; font-weight: 600;")
        sev_lbl.move(56, 38)
        sev_lbl.resize(w - 70, 18)

        msg_lbl = QtWidgets.QLabel(message, frame)
        msg_lbl.setWordWrap(True)
        msg_lbl.setStyleSheet("font-size: 12px; color: #f5f5f7; background: transparent;")
        msg_lbl.move(14, 66)
        msg_lbl.resize(w - 28, 54)

        if source_ip:
            ip_lbl = QtWidgets.QLabel(f"Origem: {source_ip}", frame)
            ip_lbl.setStyleSheet("font-size: 10px; color: #8e8e93; background: transparent;")
            ip_lbl.move(14, 128)
            ip_lbl.resize(200, 16)

        dismiss_btn = QtWidgets.QPushButton("✕", frame)
        dismiss_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: #8e8e93; border: none;
                font-size: 16px; font-weight: 600;
            }}
            QPushButton:hover {{ color: white; }}
        """)
        dismiss_btn.move(w - 36, 6)
        dismiss_btn.resize(28, 28)
        dismiss_btn.clicked.connect(self.close)

        # Notification sound (Avast-style alert)
        try:
            import subprocess
            snd = "/home/kalleb/Downloads/new-ford-chime.mp3"
            player = "mpg123"
            if not os.path.exists(snd):
                snd = os.path.join(os.path.dirname(__file__), "alert.wav")
                player = "paplay"
            subprocess.run([player, snd], capture_output=True, timeout=2)
        except Exception:
            QtWidgets.QApplication.beep()

        # Slide-in animation
        anim = QtCore.QPropertyAnimation(self, b"pos")
        anim.setDuration(300)
        anim.setStartValue(QtCore.QPoint(screen.width(), y))
        anim.setEndValue(QtCore.QPoint(x, y))
        anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        anim.start()
        self._anim = anim

        self.show()
        QtCore.QTimer.singleShot(8000, self.close)

class SidebarButton(QtWidgets.QPushButton):
    def __init__(self, text, icon_emoji=""):
        super().__init__(f"  {icon_emoji}  {text}")
        self.setCheckable(True)
        self.setFixedHeight(44)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_DIM}; border: none;
                text-align: left; padding: 10px 18px; font-size: 13px;
                border-radius: 10px; margin: 2px 8px; font-weight: 500;
            }}
            QPushButton:hover {{
                background: {DARK_MID}; color: {TEXT};
            }}
            QPushButton:checked {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {ACCENT}, stop:1 {ACCENT_DARK});
                color: white; font-weight: 600;
            }}
        """)

class StatCard(QtWidgets.QFrame):
    def __init__(self, label, icon, color):
        super().__init__()
        self.setStyleSheet(f"""
            StatCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(36,36,38,0.9), stop:1 rgba(44,44,46,0.7));
                border: 1px solid {BORDER}; border-radius: 14px; padding: 10px;
            }}
        """)
        self.setMinimumSize(150, 90)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(3)
        self.icon_lbl = QtWidgets.QLabel(icon)
        self.icon_lbl.setStyleSheet(f"font-size: 24px; background: transparent;")
        self.icon_lbl.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.icon_lbl)
        self.value_lbl = QtWidgets.QLabel("0")
        self.value_lbl.setStyleSheet(f"font-size: 26px; font-weight: 700; color: {color}; background: transparent;")
        self.value_lbl.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.value_lbl)
        self.title_lbl = QtWidgets.QLabel(label)
        self.title_lbl.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent; font-weight: 500;")
        self.title_lbl.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.title_lbl)
    def set_value(self, val):
        self.value_lbl.setText(str(val))

class MainWindow(QtWidgets.QMainWindow):
    desktop_scan_done = QtCore.pyqtSignal(object)
    desktop_scan_error = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.engine = DefendREngine()
        self.netmon = NetworkMonitor()
        try:
            from defendr.reputation import DEFAULT_SERVER_IP
            self.netmon.trusted_ips.add(DEFAULT_SERVER_IP)
        except Exception:
            pass
        self.desktop_scan_done.connect(self._on_desktop_scan_done)
        self.desktop_scan_error.connect(self._on_desktop_scan_error)
        self.netmon.alert_signal.connect(self._on_net_alert)
        self.netmon.data_signal.connect(self._on_net_data)
        self.netmon.intrusion_signal.connect(self._on_net_intrusion)
        self.quarantine = QuarantineManager()
        self.rt_protector = RealTimeProtector(self.engine)
        self.rt_protector.alert_signal.connect(self._on_rt_alert)
        self.firewall = FirewallManager()
        self.firewall.intrusion_signal.connect(lambda s, m: self._show_intrusion_popup(s, m, "Intrusao de Rede", ""))
        self.web_blocker = WebBlocker()
        self.anti_phish = AntiPhishing()
        self.sandbox = SandboxManager()
        self.ransomware = AntiRansomware()
        self.ransomware.alert_signal.connect(self._on_ransomware_alert)
        self.rootkit = RootkitDetector()
        self.rootkit.alert_signal.connect(self._on_rootkit_alert)
        self.scheduler = Scheduler()
        self.scheduler.scan_triggered.connect(self._on_scheduled_scan)
        self.sig_updater = SignatureUpdater(self.engine)
        self.sig_updater.update_signal.connect(self._on_update_status)
        self.game_mode = GameMode()
        self.game_mode.mode_changed.connect(self._on_game_mode)
        self.usb_scanner = USBScanner(self.engine)
        self.usb_scanner.scan_signal.connect(self._on_usb_scan)
        self.usb_scanner.alert_signal.connect(self._on_usb_alert)
        self.vpn = VPNManager()
        self.pwd_mgr = PasswordManager()
        self.net_inspector = NetworkInspector()
        self.net_inspector.result_signal.connect(self._on_inspect_result)
        self.wifi_inspector = WiFiInspector()
        self.wifi_inspector.result_signal.connect(self._on_wifi_result)
        self.wifi_inspector.device_signal.connect(self._on_wifi_device)
        self.shredder = DataShredder()
        self.shredder.progress_signal.connect(self._on_shred_progress)
        self.shredder.done_signal.connect(self._on_shred_done)
        self.soft_updater = SoftwareUpdater()
        self.soft_updater.update_signal.connect(self._on_soft_update)
        self.soft_updater.progress_signal.connect(self._on_soft_progress)
        self.webcam_protector = WebcamProtector()
        self.webcam_protector.alert_signal.connect(self._on_webcam_alert)
        self.webcam_protector.block_signal.connect(self._on_webcam_block)
        self.dns_over_https = DNSOverHTTPS()
        self.cleanup_mgr = CleanupManager()
        self.cleanup_mgr.progress_signal.connect(self._on_cleanup_progress)
        self.cleanup_mgr.done_signal.connect(self._on_cleanup_done)
        self.cleanup_mgr.preview_signal.connect(self._on_cleanup_preview)
        self.telemetry = TelemetryClient()
        self.enterprise_mode = False
        self.autostart_enabled = False
        self._autostart_path = os.path.expanduser("~/.config/autostart/defendr.desktop")
        self.selfprotect = SelfProtection(os.getpid())
        self.selfprotect.alert_signal.connect(self._on_selfprotect_alert)
        self.adv_protection = AdvancedProtection()
        self.adv_protection.alert_signal.connect(self._on_adv_alert)

        self.setWindowTitle(_("DefendR - Advanced Protection"))
        self.setMinimumSize(1200, 750)
        self.resize(1300, 800)
        icon_svg = os.path.join(os.path.dirname(__file__), "icon.svg")
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        if os.path.exists(icon_svg):
            self.setWindowIcon(QtGui.QIcon(icon_svg))
        elif os.path.exists(icon_path):
            self.setWindowIcon(QtGui.QIcon(icon_path))

        self._setup_ui()
        self._setup_tray()
        self.protection_level = self.engine.config_data.get("protection_level", "medium")
        self._update_protect_buttons()
        self._update_protect_label()
        self._start_monitors()
        self._auto_start_cloud_server()

    def _update_protect_buttons(self):
        level = getattr(self, 'protection_level', 'medium')
        for frame, key in self.prot_level_btns:
            active = key == level
            frame.setStyleSheet(f"""
                background: rgba(255,255,255,{0.08 if active else 0});
                border: 2px solid {ACCENT if active else 'transparent'};
                border-radius: 10px;
                padding: 8px;
            """ if active else "background: transparent;")

    def _set_protection_level(self, level):
        if getattr(self, 'enterprise_mode', False):
            return
        self.protection_level = level
        self.engine.config_data["protection_level"] = level
        try:
            from defendr.filelock import safe_json_write
            safe_json_write(self.engine.config_file, self.engine.config_data)
        except Exception: pass
        self._update_protect_buttons()
        basic = level == "basic"
        medium = level in ("medium", "hard")
        hard = level == "hard"
        self.rt_protector.stop() if hasattr(self.rt_protector, 'active') and self.rt_protector.active else None
        self.rt_protector.start()
        if basic:
            self.ransomware.stop()
            self.webcam_protector.stop()
            self.adv_protection.stop()
            self.selfprotect.stop()
        elif medium:
            self.ransomware.start()
            self.webcam_protector.start()
            self.adv_protection.stop()
            self.selfprotect.stop()
        elif hard:
            self.ransomware.start()
            self.webcam_protector.start()
            self.adv_protection.start()
            self.selfprotect.start()
        self._update_protect_label()

    def _update_protect_label(self):
        level = getattr(self, 'protection_level', 'medium')
        level_map = {"basic": "Basic", "medium": "Medium", "hard": "Hard"}
        color_map = {"basic": GREEN, "medium": YELLOW, "hard": RED}
        self.protect_indicator.setText(f"●  {level_map.get(level, 'Medium').upper()}")
        self.protect_indicator.setStyleSheet(f"font-size: 12px; color: {color_map.get(level, YELLOW)}; background: transparent; font-weight: 600;")

    def _update_defendr(self):
        def task():
            import subprocess
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            try:
                # Fetch & pull
                subprocess.run(["git", "fetch", "origin"], cwd=base,
                               capture_output=True, timeout=30)
                r = subprocess.run(["git", "pull", "origin", "main"], cwd=base,
                                   capture_output=True, text=True, timeout=30)
                out = r.stdout.strip() + r.stderr.strip()
                if "Already up to date" in out:
                    return ("info", "DefendR ja esta na versao mais recente!")
                if r.returncode == 0 and "Updating" in out:
                    return ("ok", "Atualizado!\n" + out[:200])
                return ("erro", "Falha ao atualizar:\n" + out[:200])
            except Exception as e:
                return ("erro", f"Erro: {str(e)[:100]}")

        self.upd_status.setText("Atualizando...")
        w = TaskWorker(task)
        w.finished.connect(lambda res: (
            self.upd_status.setText(res[1][:60]),
            self._show_msg(res[1])
        ))
        w.start()

    def _uninstall_defendr(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        uninstaller = os.path.join(base, "uninstall.py")
        if os.path.exists(uninstaller):
            self._cleanup_all()
            self.hide()
            self.tray.hide()
            QtCore.QProcess.startDetached(sys.executable, [uninstaller])
            QtCore.QTimer.singleShot(500, QtWidgets.qApp.quit)

    def _restart_app(self):
        self.tray.showMessage("DefendR", "Reiniciando...", QtWidgets.QSystemTrayIcon.Information, 2000)
        self._cleanup_all()
        args = list(sys.argv)
        if "--restart" not in args:
            args.append("--restart")
        QtCore.QTimer.singleShot(2000, lambda: (
            QtCore.QProcess.startDetached(sys.executable, args),
            QtWidgets.qApp.quit()
        ))

    def _cleanup_all(self):
        self.monitor_timer.stop()
        self.proc_timer.stop()
        if hasattr(self, 'fw_detect_timer'):
            self.fw_detect_timer.stop()
        self.netmon.stop()
        self.selfprotect.stop()
        self.adv_protection.stop()
        self.rt_protector.stop()
        self.usb_scanner.stop()
        self.game_mode.stop()
        self.firewall.disable()
        self.engine.stop()
        self.ransomware.stop()
        if hasattr(self, '_rep_server'):
            self._rep_server.stop()

    def closeEvent(self, event):
        if self.game_mode.suppress_notifications():
            event.accept()
            return
        event.ignore()
        self.hide()
        self.tray.showMessage("DefendR", _("Protecao continua ativa em segundo plano"),
                              QtWidgets.QSystemTrayIcon.Information, 2000)

    def _setup_tray(self):
        icon_svg = os.path.join(os.path.dirname(__file__), "icon.svg")
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        if os.path.exists(icon_svg):
            icon = QtGui.QIcon(icon_svg)
        elif os.path.exists(icon_path):
            icon = QtGui.QIcon(icon_path)
        else:
            icon = QtGui.QIcon()
        self.tray = QtWidgets.QSystemTrayIcon(icon, self)
        self.tray.setToolTip(_("Protected by DefendR"))
        menu = QtWidgets.QMenu()
        show_action = menu.addAction(_("Open DefendR"))
        show_action.triggered.connect(self.show)
        menu.addSeparator()
        self.tray_status = menu.addAction(_("Protected by DefendR"))
        self.tray_status.setEnabled(False)
        menu.addSeparator()
        self.tray_game = menu.addAction("🎮  " + _("Game Mode") + ": OFF")
        self.tray_game.triggered.connect(self._toggle_game_mode_tray)
        menu.addSeparator()
        quit_action = menu.addAction(_("Quit"))
        quit_action.triggered.connect(self._quit_app)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda r: self.show() if r == QtWidgets.QSystemTrayIcon.DoubleClick else None)
        self.tray.show()

    def _toggle_game_mode_tray(self):
        if self.game_mode.active:
            self.game_mode.active = False
            self.tray_game.setText("🎮  Game Mode: OFF")
        else:
            self.game_mode.active = True
            self.tray_game.setText("🎮  Game Mode: ON")

    def _tray_clicked(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.DoubleClick:
            self.show(); self.raise_(); self.activateWindow()

    def _quit_app(self):
        self.netmon.stop(); self.rt_protector.stop(); self.ransomware.stop()
        self.usb_scanner.stop(); self.game_mode.stop()
        if hasattr(self, 'webcam_protector'): self.webcam_protector.stop()
        self.selfprotect.stop()
        self.adv_protection.stop()
        self.engine.scanning = False
        self.monitor_timer.stop()
        self.proc_timer.stop()
        if hasattr(self, 'fw_detect_timer'): self.fw_detect_timer.stop()
        self.firewall.disable()
        self.hide(); self.tray.hide()
        QtCore.QTimer.singleShot(100, QtWidgets.QApplication.quit)

    def _switch_page(self, key):
        pages = {"dashboard":0,"scanner":1,"realtime":2,"firewall":3,"network":4,
                 "processes":5,"quarantine":6,"tools":7,"reporterror":8,"hdscan":9,"settings":10}
        idx = pages.get(key, 0)
        self.content_stack.setCurrentIndex(idx)
        if key == "network": self._update_dns()
        for btn, k in self.nav_btns:
            btn.setChecked(k == key)

    # ===================== UI SETUP =====================
    def _setup_ui(self):
        self.setStyleSheet(f"""
            QMainWindow {{ background: {DARK_BG}; font-family: {FONT}; }}
            QToolTip {{ background: {DARK_CARD}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 8px; font-size: 12px; padding: 6px; }}
            QScrollBar:vertical {{ background: {DARK_BG}; width: 6px; border: none; border-radius: 3px; }}
            QScrollBar::handle:vertical {{ background: {DARK_MID}; border-radius: 3px; min-height: 30px; }}
            QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QScrollBar:horizontal {{ background: {DARK_BG}; height: 6px; border: none; border-radius: 3px; }}
            QScrollBar::handle:horizontal {{ background: {DARK_MID}; border-radius: 3px; min-width: 30px; }}
            QLabel.section-header {{ font-size: 15px; font-weight: 600; color: {TEXT}; background: transparent; }}
            QLabel.stat-label {{ font-size: 13px; color: {TEXT_DIM}; background: transparent; }}
        """)
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QHBoxLayout(central)
        main_layout.setContentsMargins(0,0,0,0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QtWidgets.QFrame()
        sidebar.setFixedWidth(190)
        sidebar.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {DARK_MID}, stop:1 #1a1a1c); border-right: 1px solid {BORDER};")
        sidebar_layout = QtWidgets.QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0,0,0,0)
        sidebar_layout.setSpacing(0)

        # Logo
        logo_frame = QtWidgets.QFrame()
        logo_frame.setStyleSheet("background: transparent;")
        logo_frame.setMinimumHeight(80)
        logo_layout = QtWidgets.QVBoxLayout(logo_frame)
        logo_layout.setAlignment(QtCore.Qt.AlignCenter)
        logo_icon = QtWidgets.QLabel("⚔")
        logo_icon.setStyleSheet(f"font-size: 32px; color: {ACCENT_LIGHT}; background: transparent;")
        logo_icon.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(logo_icon)
        logo_text = QtWidgets.QLabel("DefendR")
        logo_text.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {ACCENT_LIGHT}; background: transparent; letter-spacing: 1px;")
        logo_text.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(logo_text)
        ver_text = QtWidgets.QLabel("v2.0")
        ver_text.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent;")
        ver_text.setAlignment(QtCore.Qt.AlignCenter)
        logo_layout.addWidget(ver_text)
        self.enterprise_badge = QtWidgets.QLabel("🔥  EMPRESARIAL")
        self.enterprise_badge.setStyleSheet(f"font-size: 11px; color: {RED}; background: rgba(255,69,58,0.08); border: 1px solid {RED}; border-radius: 10px; padding: 4px 8px; font-weight: 700;")
        self.enterprise_badge.setAlignment(QtCore.Qt.AlignCenter)
        self.enterprise_badge.hide()
        logo_layout.addWidget(self.enterprise_badge)
        sidebar_layout.addWidget(logo_frame)

        # Nav buttons
        self.nav_btns = []
        nav_items = [
            ("dashboard","📊",_("Dashboard")),
            ("scanner","🔍",_("Scanner")),
            ("realtime","🛡",_("Real-Time")),
            ("firewall","🔒",_("Firewall")),
            ("network","🌐",_("Network")),
            ("processes","⚙",_("Processes")),
            ("quarantine","📦",_("Quarantine")),
            ("tools","🧰",_("Tools")),
            ("reporterror","👤",_("Account")),
            ("hdscan","💿",_("HD Scan")),
            ("settings","🔧",_("Settings")),
        ]
        nav_tooltips = {
            "dashboard": "Visão geral do sistema, status de proteção e ações rápidas",
            "scanner": "Escaneie arquivos e pastas em busca de malware",
            "realtime": "Proteção em tempo real: monitoramento do sistema, anti-ransomware, webcam",
            "firewall": "Gerencie regras de firewall iptables",
            "network": "Monitoramento de rede, inspetor, VPN e DNS",
            "processes": "Monitore processos em execução",
            "quarantine": "Visualize e gerencie arquivos em quarentena",
            "tools": "Sandbox, detecção de rootkit, gerenciador de senhas e mais",
            "reporterror": "Login, registro e envio de relatórios de erro",
            "hdscan": "Escaneie o HD inteiro com recomendações",
            "settings": "Configure o comportamento do DefendR",
        }
        for key, icon, label in nav_items:
            btn = SidebarButton(label, icon)
            btn.setToolTip(nav_tooltips.get(key, ""))
            btn.clicked.connect(lambda checked, k=key: self._switch_page(k))
            sidebar_layout.addWidget(btn)
            self.nav_btns.append((btn, key))
        sidebar_layout.addStretch()

        # Protection status
        self.protect_frame = QtWidgets.QFrame()
        self.protect_frame.setStyleSheet(f"background: rgba(48,209,88,0.06); border-top: 1px solid {BORDER}; padding: 10px;")
        pf_layout = QtWidgets.QVBoxLayout(self.protect_frame)
        self.protect_indicator = QtWidgets.QLabel("●  Protected")
        self.protect_indicator.setStyleSheet(f"font-size: 12px; color: {GREEN}; background: transparent; font-weight: 600;")
        self.protect_indicator.setAlignment(QtCore.Qt.AlignCenter)
        pf_layout.addWidget(self.protect_indicator)
        self.protect_count = QtWidgets.QLabel("0 threats blocked")
        self.protect_count.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        self.protect_count.setAlignment(QtCore.Qt.AlignCenter)
        pf_layout.addWidget(self.protect_count)
        sidebar_layout.addWidget(self.protect_frame)
        main_layout.addWidget(sidebar)

        # Content
        self.content_stack = QtWidgets.QStackedWidget()
        self.content_stack.setStyleSheet(f"background: {DARK_BG};")
        main_layout.addWidget(self.content_stack, 1)

        self._build_dashboard()
        self._build_scanner()
        self._build_realtime()
        self._build_firewall()
        self._build_network()
        self._build_processes()
        self._build_quarantine()
        self._build_tools()
        self._build_report_error()
        self._build_hd_scan()
        self._build_settings()

        self.nav_btns[0][0].setChecked(True)

    def _page_widget(self):
        w = QtWidgets.QWidget()
        w.setStyleSheet(f"background: {DARK_BG};")
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(24,20,24,20)
        layout.setSpacing(12)
        return w, layout

    def _page_header(self, layout, title, subtitle=""):
        h = QtWidgets.QLabel(title)
        h.setStyleSheet(f"font-size: 28px; font-weight: 700; color: {TEXT}; background: transparent; padding-bottom: 2px;")
        layout.addWidget(h)
        if subtitle:
            s = QtWidgets.QLabel(subtitle)
            s.setStyleSheet(f"font-size: 13px; color: {TEXT_DIM}; background: transparent; padding-bottom: 4px;")
            layout.addWidget(s)

    def _btn(self, text, handler, color=ACCENT):
        btn = QtWidgets.QPushButton(text)
        btn.setCursor(QtCore.Qt.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {color}, stop:1 {ACCENT_DARK});
                color: white; border: none; border-radius: 22px;
                padding: 8px 20px; font-size: 13px; font-weight: 600;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {ACCENT_LIGHT}, stop:1 {color});
            }}
            QPushButton:pressed {{
                background: {ACCENT_DARK};
            }}
        """)
        btn.clicked.connect(handler)
        return btn

    # ===== DASHBOARD =====
    def _build_dashboard(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("nav_dashboard"), "System overview and real-time protection status")
        # Stats
        stats_frame = QtWidgets.QWidget()
        stats_frame.setStyleSheet("background: transparent;")
        stats_layout = QtWidgets.QHBoxLayout(stats_frame)
        stats_layout.setSpacing(10)
        self.stat_cards = {}
        stat_defs = [
            ("cpu","🖥","CPU",ACCENT_LIGHT),("mem","💾","Memory",CYAN),
            ("procs","⚙","Processes",YELLOW),("alerts","🚨","Alerts",RED),
            ("scanned","📁","Scanned",GREEN),("threats","🛡","Threats",ACCENT),
            ("users","👥","Protected",ACCENT_LIGHT),
        ]
        for key, icon, label, color in stat_defs:
            card = StatCard(label, icon, color)
            stats_layout.addWidget(card)
            self.stat_cards[key] = card
        layout.addWidget(stats_frame)

        # Quick actions row
        action_frame = QtWidgets.QWidget()
        action_frame.setStyleSheet("background: transparent;")
        action_layout = QtWidgets.QHBoxLayout(action_frame)
        action_layout.setSpacing(8)
        for text, handler in [("🔍 Quick Scan", lambda: self._switch_page("scanner")),
                               ("🛡 Firewall", lambda: self._switch_page("firewall")),
                               ("📦 Quarantine", lambda: self._switch_page("quarantine")),
                               ("🔧 Update Signatures", self._manual_update)]:
            action_layout.addWidget(self._btn(text, handler))
        action_layout.addStretch()
        layout.addWidget(action_frame)

        # Protection level
        self.prot_frame = QtWidgets.QFrame()
        prot_frame = self.prot_frame
        prot_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        prot_layout = QtWidgets.QVBoxLayout(prot_frame)
        prot_header = QtWidgets.QLabel("🛡  Protection Level")
        prot_header.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {TEXT}; background: transparent;")
        prot_layout.addWidget(prot_header)
        prot_btn_frame = QtWidgets.QWidget()
        prot_btn_frame.setStyleSheet("background: transparent;")
        prot_btn_layout = QtWidgets.QHBoxLayout(prot_btn_frame)
        prot_btn_layout.setSpacing(8)

        self.prot_level_btns = []
        prot_levels = [
            ("basic", "Basic", "RT scan + USB", GREEN),
            ("medium", "Medium", "+ Network + Ransomware + Webcam", YELLOW),
            ("hard", "Hard", "+ Rootkit + SelfProtect + Advanced", RED),
        ]
        prot_tooltips = {
            "basic": "Básico: apenas escaneamento em tempo real + verificação de USB",
            "medium": "Médio: adiciona monitoramento de rede, anti-ransomware e proteção de webcam",
            "hard": "Máximo: adiciona detecção de rootkit, autoproteção e proteção avançada",
        }
        for key, label, desc, color in prot_levels:
            btn_frame = QtWidgets.QFrame()
            btn_frame.setStyleSheet("background: transparent;")
            btn_frame.setCursor(QtCore.Qt.PointingHandCursor)
            btn_frame.setToolTip(prot_tooltips.get(key, ""))
            bl = QtWidgets.QVBoxLayout(btn_frame)
            bl.setAlignment(QtCore.Qt.AlignCenter)
            bl.setSpacing(2)
            title = QtWidgets.QLabel(label)
            title.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {color}; background: transparent;")
            title.setAlignment(QtCore.Qt.AlignCenter)
            bl.addWidget(title)
            sub = QtWidgets.QLabel(desc)
            sub.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent;")
            sub.setAlignment(QtCore.Qt.AlignCenter)
            bl.addWidget(sub)
            btn_frame.mousePressEvent = lambda e, k=key: self._set_protection_level(k)
            prot_btn_layout.addWidget(btn_frame)
            self.prot_level_btns.append((btn_frame, key))
        prot_btn_layout.addStretch()
        prot_layout.addWidget(prot_btn_frame)
        layout.addWidget(prot_frame)

        # Joguin IA
        ia_frame = QtWidgets.QFrame()
        ia_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        ia_layout = QtWidgets.QVBoxLayout(ia_frame)
        ia_header = QtWidgets.QLabel("🧠  Joguin IA")
        ia_header.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {ACCENT_LIGHT}; background: transparent;")
        ia_layout.addWidget(ia_header)
        ia_row = QtWidgets.QHBoxLayout()
        self.ia_level_lbl = QtWidgets.QLabel("Level 1")
        self.ia_level_lbl.setStyleSheet(f"font-size: 22px; font-weight: 700; color: {ACCENT}; background: transparent;")
        ia_row.addWidget(self.ia_level_lbl)
        self.ia_xp_bar = QtWidgets.QProgressBar()
        self.ia_xp_bar.setFixedHeight(8)
        self.ia_xp_bar.setStyleSheet(f"QProgressBar {{ background: {DARK_MID}; border: none; border-radius: 4px; }} QProgressBar::chunk {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ACCENT}, stop:1 {ACCENT_LIGHT}); border-radius: 4px; }}")
        self.ia_xp_bar.setTextVisible(False)
        ia_row.addWidget(self.ia_xp_bar, 1)
        self.ia_xp_lbl = QtWidgets.QLabel("0/0 XP")
        self.ia_xp_lbl.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        ia_row.addWidget(self.ia_xp_lbl)
        ia_layout.addLayout(ia_row)
        ia_info_row = QtWidgets.QHBoxLayout()
        self.ia_acc_lbl = QtWidgets.QLabel("🎯 0% accuracy")
        self.ia_acc_lbl.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        ia_info_row.addWidget(self.ia_acc_lbl)
        self.ia_hash_lbl = QtWidgets.QLabel("📚 0 hashes")
        self.ia_hash_lbl.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        ia_info_row.addWidget(self.ia_hash_lbl)
        self.ia_pat_lbl = QtWidgets.QLabel("🧩 0 patterns")
        self.ia_pat_lbl.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        ia_info_row.addWidget(self.ia_pat_lbl)
        ia_info_row.addStretch()
        ia_layout.addLayout(ia_info_row)
        self.ia_status_lbl = QtWidgets.QLabel("🤖 Aprendendo com cada scan...")
        self.ia_status_lbl.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        ia_layout.addWidget(self.ia_status_lbl)
        layout.addWidget(ia_frame)

        # Alerts
        alert_frame = QtWidgets.QFrame()
        alert_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        alert_layout = QtWidgets.QVBoxLayout(alert_frame)
        alert_header = QtWidgets.QLabel("📋  Security Events")
        alert_header.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {TEXT}; background: transparent;")
        alert_layout.addWidget(alert_header)
        self.alert_list = QtWidgets.QListWidget()
        self.alert_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QListWidget::item {{ padding: 8px 12px; border-bottom: 1px solid {DARK_MID}; }} QListWidget::item:selected {{ background: {ACCENT}; }}")
        self.alert_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.alert_list.customContextMenuRequested.connect(self._alert_context_menu)
        alert_layout.addWidget(self.alert_list)
        alert_actions = QtWidgets.QHBoxLayout()
        alert_actions.addWidget(self._btn("🗑 Clear", self._clear_alerts))
        alert_actions.addStretch()
        alert_layout.addLayout(alert_actions)
        layout.addWidget(alert_frame, 1)
        self.content_stack.addWidget(w)

    # ===== SCANNER =====
    def _build_scanner(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔍  File Scanner"), "Scan files/directories, USB auto-scan, scheduled scans")
        btn_frame = QtWidgets.QWidget()
        btn_frame.setStyleSheet("background: transparent;")
        btn_layout = QtWidgets.QHBoxLayout(btn_frame)
        scan_btns = [
            ("📁 Scan File", self._scan_file, "Escolha um arquivo para escanear"),
            ("📂 Scan Folder", self._scan_dir, "Escolha uma pasta para escanear todos os arquivos"),
            ("⏹ Stop", self._stop_scan, "Para o escaneamento em andamento"),
            ("🗑 Clear", self._clear_scan, "Limpa os resultados do escaneamento"),
            ("📀 Scan USB", self._scan_usb_manual, "Escaneie dispositivos USB conectados"),
            ("🧪 Sandbox", self._run_selected_in_sandbox, "Execute o arquivo selecionado em um ambiente isolado"),
        ]
        for text, handler, tip in scan_btns:
            b = self._btn(text, handler)
            b.setToolTip(tip)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addWidget(btn_frame)

        level_frame = QtWidgets.QWidget()
        level_frame.setStyleSheet("background: transparent;")
        level_layout = QtWidgets.QHBoxLayout(level_frame)
        level_layout.addWidget(QtWidgets.QLabel(_("Scan Level:")))
        self.scan_level_combo = QtWidgets.QComboBox()
        self.scan_level_combo.addItems([_("Light (quick)"), _("Medium (balanced)"), _("Heavy (deep)")])
        self.scan_level_combo.setCurrentIndex(1)
        self.scan_level_combo.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 10px;font-size:12px;")
        self.scan_level_combo.currentIndexChanged.connect(self._on_scan_level_change)
        level_layout.addWidget(self.scan_level_combo)
        level_layout.addStretch()
        layout.addWidget(level_frame)

        self.drop_zone = DropZone()
        self.drop_zone.dropped.connect(lambda p: self._scan_file_path(p))
        layout.addWidget(self.drop_zone)

        self.scan_progress = QtWidgets.QProgressBar()
        self.scan_progress.setStyleSheet(f"QProgressBar {{ background: rgba(44,44,46,0.6); border: none; border-radius: 8px; height: 8px; text-align: center; font-size: 10px; color: {TEXT}; }} QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {ACCENT_LIGHT}); border-radius: 8px; }}")
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)
        self.scan_status = QtWidgets.QLabel(_("Ready"))
        self.scan_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        layout.addWidget(self.scan_status)

        self.scan_tree = QtWidgets.QTreeWidget()
        self.scan_tree.setHeaderLabels([_("Risk"), _("File"), _("Reason")])
        self.scan_tree.setColumnWidth(0,90); self.scan_tree.setColumnWidth(2,250)
        self.scan_tree.setStyleSheet(f"QTreeWidget {{ background: rgba(36,36,38,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QTreeWidget::item {{ padding: 6px 8px; border-bottom: 1px solid {DARK_MID}; }} QHeaderView::section {{ background: rgba(44,44,46,0.8); color: {ACCENT_LIGHT}; border: none; padding: 6px 8px; font-size: 12px; font-weight: 600; }}")
        self.scan_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.scan_tree.customContextMenuRequested.connect(lambda pos: self._scan_tree_context_menu(pos))
        layout.addWidget(self.scan_tree, 1)
        scan_actions = QtWidgets.QHBoxLayout()
        b = self._btn("📂 Abrir local", self._scan_open_location); b.setToolTip("Abre a pasta onde o arquivo está localizado"); scan_actions.addWidget(b)
        b = self._btn("✅ Validar", self._scan_validate_selected, "#30d158"); b.setToolTip("Marca o arquivo como seguro (whitelist)"); scan_actions.addWidget(b)
        b = self._btn("📦 Quarentena", self._scan_quarantine_selected); b.setToolTip("Move o arquivo para a quarentena"); scan_actions.addWidget(b)
        b = self._btn("🗑 Excluir", self._scan_delete_selected, "#c0392b"); b.setToolTip("Exclui permanentemente o arquivo"); scan_actions.addWidget(b)
        scan_actions.addStretch()
        layout.addLayout(scan_actions)
        self.content_stack.addWidget(w)

    # ===== REAL-TIME =====
    def _build_realtime(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🛡  Real-Time Protection"), "File system monitoring + Anti-Ransomware + Web Blocker + Anti-Phishing")

        # RT toggle
        rt_frame = QtWidgets.QFrame()
        rt_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        rt_l = QtWidgets.QVBoxLayout(rt_frame)
        rt_l.addWidget(QtWidgets.QLabel("File System Monitor"))
        self.rt_toggle = self._btn(_("▶ Start Real-Time Protection"), self._toggle_rt)
        self.rt_toggle.setToolTip("Monitora o sistema de arquivos em tempo real para detectar ameaças")
        rt_l.addWidget(self.rt_toggle)
        self.rt_status = QtWidgets.QLabel(_("Status: Stopped"))
        self.rt_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        rt_l.addWidget(self.rt_status)
        layout.addWidget(rt_frame)

        # Ransomware
        rw_frame = QtWidgets.QFrame()
        rw_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        rw_l = QtWidgets.QVBoxLayout(rw_frame)
        rw_l.addWidget(QtWidgets.QLabel("Anti-Ransomware"))
        self.rw_toggle = self._btn(_("▶ Start Ransomware Detection"), self._toggle_rw)
        self.rw_toggle.setToolTip("Detecta comportamentos suspeitos de ransomware (criptografia em massa)")
        rw_l.addWidget(self.rw_toggle)
        self.rw_status = QtWidgets.QLabel(_("Status: Stopped"))
        self.rw_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        rw_l.addWidget(self.rw_status)
        layout.addWidget(rw_frame)

        # Webcam Protection
        wc_frame = QtWidgets.QFrame()
        wc_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        wc_l = QtWidgets.QVBoxLayout(wc_frame)
        wc_l.addWidget(QtWidgets.QLabel("Webcam Protection"))
        wc_l.addWidget(QtWidgets.QLabel("Monitors /dev/video* for unauthorized access"))
        wc_btn_row = QtWidgets.QHBoxLayout()
        self.wc_toggle = self._btn(_("▶ Start Webcam Monitor"), self._toggle_webcam)
        self.wc_toggle.setToolTip("Monitora dispositivos de webcam para acesso não autorizado")
        wc_btn_row.addWidget(self.wc_toggle)
        self.wc_block_btn = self._btn(_("🔴 Block Webcam"), self._webcam_block_device)
        self.wc_block_btn.setToolTip("Bloqueia todos os dispositivos de webcam no sistema")
        wc_btn_row.addWidget(self.wc_block_btn)
        self.wc_unblock_btn = self._btn(_("🟢 Unblock Webcam"), self._webcam_unblock_device)
        self.wc_unblock_btn.setToolTip("Desbloqueia dispositivos de webcam bloqueados anteriormente")
        wc_btn_row.addWidget(self.wc_unblock_btn)
        wc_l.addLayout(wc_btn_row)
        self.wc_status = QtWidgets.QLabel(_("Status: Stopped"))
        self.wc_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        wc_l.addWidget(self.wc_status)
        self.wc_list = QtWidgets.QListWidget()
        self.wc_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; max-height: 80px; }}")
        wc_l.addWidget(self.wc_list)
        layout.addWidget(wc_frame)

        # Web Blocker
        wb_frame = QtWidgets.QFrame()
        wb_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        wb_l = QtWidgets.QVBoxLayout(wb_frame)
        wb_l.addWidget(QtWidgets.QLabel("Web Blocker (hosts file)"))
        wb_input_row = QtWidgets.QHBoxLayout()
        self.wb_input = QtWidgets.QLineEdit()
        self.wb_input.setPlaceholderText("domain.com")
        self.wb_input.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; padding: 8px 12px;")
        wb_input_row.addWidget(self.wb_input)
        b = self._btn(_("Block"), self._web_block); b.setToolTip("Adiciona o domínio ao /etc/hosts para bloqueá-lo"); wb_input_row.addWidget(b)
        b = self._btn(_("Unblock"), self._web_unblock); b.setToolTip("Remove o domínio da lista de bloqueio"); wb_input_row.addWidget(b)
        wb_l.addLayout(wb_input_row)
        self.wb_list = QtWidgets.QListWidget()
        self.wb_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; max-height: 120px; }}")
        wb_l.addWidget(self.wb_list)
        self._refresh_web_block()
        layout.addWidget(wb_frame)

        # Anti-Phishing
        ap_frame = QtWidgets.QFrame()
        ap_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        ap_l = QtWidgets.QVBoxLayout(ap_frame)
        ap_l.addWidget(QtWidgets.QLabel("Anti-Phishing URL Checker"))
        url_row = QtWidgets.QHBoxLayout()
        self.ap_input = QtWidgets.QLineEdit()
        self.ap_input.setPlaceholderText("https://suspeitosite.com")
        self.ap_input.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; padding: 8px 12px;")
        url_row.addWidget(self.ap_input)
        url_row.addWidget(self._btn(_("Check URL"), self._check_phishing))
        ap_l.addLayout(url_row)
        self.ap_result = QtWidgets.QLabel("")
        self.ap_result.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        self.ap_result.setWordWrap(True)
        ap_l.addWidget(self.ap_result)
        layout.addWidget(ap_frame)

        # RT alerts
        rt_alert_frame = QtWidgets.QFrame()
        rt_alert_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        rt_al = QtWidgets.QVBoxLayout(rt_alert_frame)
        rt_al.addWidget(QtWidgets.QLabel("📋  Protection Alerts"))
        self.rt_alerts = QtWidgets.QListWidget()
        self.rt_alerts.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QListWidget::item {{ padding: 6px 10px; border-bottom: 1px solid {DARK_MID}; }}")
        rt_al.addWidget(self.rt_alerts)
        layout.addWidget(rt_alert_frame, 1)
        self.content_stack.addWidget(w)

    # ===== FIREWALL =====
    def _build_firewall(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔒  Firewall"), "iptables-based firewall management")
        if not self.firewall.is_available():
            layout.addWidget(QtWidgets.QLabel("⚠ iptables not available. Run with sudo."))
            self.content_stack.addWidget(w); return

        self.fw_frame = QtWidgets.QFrame()
        fw_frame = self.fw_frame
        fw_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        fw_l = QtWidgets.QVBoxLayout(fw_frame)
        fw_l.addWidget(QtWidgets.QLabel("Firewall Control"))
        fw_btn_row = QtWidgets.QHBoxLayout()
        fw_btn_row.addWidget(self._btn(_("🛡 Enable Firewall"), self._fw_enable))
        fw_btn_row.addWidget(self._btn(_("Disable Firewall"), self._fw_disable))
        fw_btn_row.addWidget(self._btn(_("🔄 Flush Rules"), self._fw_flush))
        fw_l.addLayout(fw_btn_row)
        self.fw_status = QtWidgets.QLabel("Firewall: Disabled")
        self.fw_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        fw_l.addWidget(self.fw_status)
        layout.addWidget(fw_frame)

        # Port blocking
        self.port_frame = QtWidgets.QFrame()
        port_frame = self.port_frame
        port_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        port_l = QtWidgets.QVBoxLayout(port_frame)
        port_l.addWidget(QtWidgets.QLabel("Port Management"))
        port_row = QtWidgets.QHBoxLayout()
        self.port_input = QtWidgets.QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g. 4444)")
        self.port_input.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; padding: 8px 12px; max-width: 100px;")
        port_row.addWidget(self.port_input)
        port_row.addWidget(self._btn(_("Block Port"), self._fw_block_port))
        port_row.addWidget(self._btn(_("Allow Port"), self._fw_allow_port))
        port_l.addLayout(port_row)
        layout.addWidget(port_frame)

        # Rules display
        rules_frame = QtWidgets.QFrame()
        rules_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        rules_l = QtWidgets.QVBoxLayout(rules_frame)
        rules_l.addWidget(QtWidgets.QLabel("Current Rules"))
        self.fw_rules = QtWidgets.QListWidget()
        self.fw_rules.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; font-family: monospace; }} QListWidget::item {{ padding: 3px 6px; }}")
        rules_l.addWidget(self.fw_rules)
        rules_l.addWidget(self._btn(_("🔄 Refresh Rules"), self._fw_refresh))
        layout.addWidget(rules_frame, 1)
        self.content_stack.addWidget(w)

    # ===== NETWORK =====
    def _build_network(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🌐  Network"), "Monitor + Inspector + VPN")
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }} QTabBar::tab {{ background: transparent; color: {TEXT_DIM}; padding: 8px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 4px 2px; }} QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: 600; }} QTabBar::tab:hover {{ color: {TEXT}; }} QTabBar {{ background: rgba(44,44,46,0.4); border-radius: 10px; padding: 2px; }}")

        # Tab 1: Network Monitor
        mon_w = QtWidgets.QWidget()
        mon_l = QtWidgets.QVBoxLayout(mon_w)
        self.net_toggle_frame = QtWidgets.QWidget()
        toggle_frame = self.net_toggle_frame
        toggle_frame.setStyleSheet("background: transparent;")
        toggle_layout = QtWidgets.QHBoxLayout(toggle_frame)
        self.net_status = QtWidgets.QLabel("●  Monitoring: OFF")
        self.net_status.setStyleSheet(f"font-size: 13px; color: {TEXT_DIM}; background: transparent;")
        toggle_layout.addWidget(self.net_status)
        self.net_toggle = self._btn(_("▶ Start"), self._toggle_net)
        toggle_layout.addWidget(self.net_toggle)
        toggle_layout.addStretch()
        mon_l.addWidget(toggle_frame)

        info_frame = QtWidgets.QWidget()
        info_frame.setStyleSheet("background: transparent;")
        info_layout = QtWidgets.QHBoxLayout(info_frame)
        info_layout.setSpacing(10)
        # ARP
        arp_card = QtWidgets.QFrame()
        arp_card.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        arp_l = QtWidgets.QVBoxLayout(arp_card)
        arp_l.addWidget(QtWidgets.QLabel("ARP Table"))
        self.arp_table = QtWidgets.QTableWidget(0,3)
        self.arp_table.setHorizontalHeaderLabels(["IP","MAC","Interface"])
        self.arp_table.setStyleSheet(f"QTableWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QHeaderView::section {{ background: {DARK_MID}; color: {ACCENT_LIGHT}; border: none; padding: 3px; }}")
        self.arp_table.horizontalHeader().setStretchLastSection(True)
        arp_l.addWidget(self.arp_table)
        info_layout.addWidget(arp_card)
        # DNS
        dns_card = QtWidgets.QFrame()
        dns_card.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        dns_l = QtWidgets.QVBoxLayout(dns_card)
        dns_l.addWidget(QtWidgets.QLabel("DNS Servers"))
        self.dns_label = QtWidgets.QLabel("Loading...")
        self.dns_label.setStyleSheet(f"font-size: 11px; color: {TEXT}; background: transparent; padding: 6px;")
        self.dns_label.setWordWrap(True)
        dns_l.addWidget(self.dns_label)
        info_layout.addWidget(dns_card)
        # Conns
        conn_card = QtWidgets.QFrame()
        conn_card.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        conn_l = QtWidgets.QVBoxLayout(conn_card)
        conn_l.addWidget(QtWidgets.QLabel("Active Connections"))
        self.conn_label = QtWidgets.QLabel("--")
        self.conn_label.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {ACCENT}; background: transparent;")
        self.conn_label.setAlignment(QtCore.Qt.AlignCenter)
        conn_l.addWidget(self.conn_label)
        info_layout.addWidget(conn_card)
        mon_l.addWidget(info_frame)

        net_alert_frame = QtWidgets.QFrame()
        net_alert_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        net_al = QtWidgets.QVBoxLayout(net_alert_frame)
        net_al.addWidget(QtWidgets.QLabel("🚨  Network Alerts"))
        self.net_alerts = QtWidgets.QListWidget()
        self.net_alerts.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QListWidget::item {{ padding: 6px 10px; border-bottom: 1px solid {DARK_MID}; }}")
        net_al.addWidget(self.net_alerts)
        mon_l.addWidget(net_alert_frame, 1)
        tabs.addTab(mon_w, "Monitor")

        # Tab 2: Network Inspector
        ins_w = QtWidgets.QWidget()
        ins_l = QtWidgets.QVBoxLayout(ins_w)
        ins_l.addWidget(self._btn(_("🔍 ARP Scan Network"), self._arp_scan))
        ins_l.addWidget(self._btn(_("📡 Router Info"), self._router_info))
        self.inspector_results = QtWidgets.QPlainTextEdit()
        self.inspector_results.setReadOnly(True)
        self.inspector_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; padding: 10px;")
        ins_l.addWidget(self.inspector_results, 1)
        tabs.addTab(ins_w, "Inspector")

        # Tab 3: WiFi Inspector
        wifi_w = QtWidgets.QWidget()
        wifi_l = QtWidgets.QVBoxLayout(wifi_w)
        wifi_btn_row = QtWidgets.QHBoxLayout()
        wifi_btn_row.addWidget(self._btn(_("📡 Scan Router"), self._wifi_scan))
        self.wifi_monitor_btn = self._btn(_("▶ Start Continuous Monitor"), self._wifi_start_monitor)
        wifi_btn_row.addWidget(self.wifi_monitor_btn)
        wifi_l.addLayout(wifi_btn_row)
        wifi_l.addWidget(QtWidgets.QLabel("Scans router for open ports and security issues"))
        self.wifi_results = QtWidgets.QPlainTextEdit()
        self.wifi_results.setReadOnly(True)
        self.wifi_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; padding: 10px;")
        wifi_l.addWidget(self.wifi_results, 1)
        self.wifi_device_list = QtWidgets.QListWidget()
        self.wifi_device_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; max-height: 100px; }}")
        wifi_l.addWidget(self.wifi_device_list)
        tabs.addTab(wifi_w, "WiFi Inspector")

        # Tab 4: VPN
        vpn_w = QtWidgets.QWidget()
        vpn_l = QtWidgets.QVBoxLayout(vpn_w)
        if self.vpn.is_available():
            vpn_l.addWidget(QtWidgets.QLabel("OpenVPN Manager"))
            vpn_btn_row = QtWidgets.QHBoxLayout()
            vpn_btn_row.addWidget(self._btn(_("📂 Add Config"), self._vpn_add))
            vpn_btn_row.addWidget(self._btn(_("▶ Connect"), self._vpn_connect))
            vpn_btn_row.addWidget(self._btn(_("⏹ Disconnect"), self._vpn_disconnect))
            vpn_l.addLayout(vpn_btn_row)
            self.vpn_status = QtWidgets.QLabel("VPN: Disconnected")
            self.vpn_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
            vpn_l.addWidget(self.vpn_status)
            self.vpn_list = QtWidgets.QListWidget()
            self.vpn_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }}")
            vpn_l.addWidget(self.vpn_list, 1)
            self._refresh_vpn_list()
        else:
            vpn_l.addWidget(QtWidgets.QLabel("⚠ OpenVPN not installed. Run: sudo apt install openvpn"))
        tabs.addTab(vpn_w, "VPN")

        # Tab 5: DNS over HTTPS
        dns_w = QtWidgets.QWidget()
        dns_l = QtWidgets.QVBoxLayout(dns_w)
        dns_l.addWidget(QtWidgets.QLabel("DNS-over-HTTPS Configuration"))
        for provider_name in self.dns_over_https.providers:
            btn = self._btn(f"Set {provider_name}", lambda p=provider_name: self._dns_set(p))
            dns_l.addWidget(btn)
        dns_l.addWidget(self._btn(_("Reset to Default"), self._dns_reset))
        self.dns_status = QtWidgets.QLabel(f"Current: {', '.join(self.dns_over_https.get_current_dns())}")
        self.dns_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent; padding: 6px;")
        self.dns_status.setWordWrap(True)
        dns_l.addWidget(self.dns_status)
        dns_l.addWidget(self._btn(_("🔒 Enable DNSSEC"), self._dns_enable_dnssec))
        dns_l.addStretch()
        tabs.addTab(dns_w, "DNS")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(w)

    # ===== PROCESSES =====
    def _build_processes(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("⚙  Process Monitor"), "Monitor running processes for suspicious activity")
        btn_frame = QtWidgets.QWidget()
        btn_frame.setStyleSheet("background: transparent;")
        btn_layout = QtWidgets.QHBoxLayout(btn_frame)
        btn_layout.addWidget(self._btn(_("🔄 Refresh"), self._refresh_procs))
        btn_layout.addStretch()
        layout.addWidget(btn_frame)
        self.proc_table = QtWidgets.QTableWidget(0,6)
        self.proc_table.setHorizontalHeaderLabels(["PID","Name","CPU%","MEM%","Conns","Status"])
        self.proc_table.setStyleSheet(f"QTableWidget {{ background: rgba(36,36,38,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QHeaderView::section {{ background: rgba(44,44,46,0.8); color: {ACCENT_LIGHT}; border: none; padding: 6px 8px; font-size: 12px; font-weight: 600; }} QTableWidget::item {{ padding: 3px; }}")
        self.proc_table.setAlternatingRowColors(True)
        self.proc_table.setStyleSheet(self.proc_table.styleSheet()+f"\nQTableWidget{{alternate-background-color:{DARK_MID};}}")
        self.proc_table.horizontalHeader().setStretchLastSection(True)
        self.proc_table.setColumnWidth(0,60); self.proc_table.setColumnWidth(1,180)
        self.proc_table.setColumnWidth(2,60); self.proc_table.setColumnWidth(3,60); self.proc_table.setColumnWidth(4,60)
        layout.addWidget(self.proc_table, 1)
        self.content_stack.addWidget(w)

    # ===== QUARANTINE =====
    def _build_quarantine(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("📦  Quarantine"), "View and manage quarantined files")
        q_btn_frame = QtWidgets.QWidget()
        q_btn_frame.setStyleSheet("background: transparent;")
        q_btn_l = QtWidgets.QHBoxLayout(q_btn_frame)
        q_btn_l.addWidget(self._btn(_("🔄 Refresh"), self._refresh_quarantine))
        q_btn_l.addWidget(self._btn(_("🗑 Delete All"), self._quarantine_delete_all))
        q_btn_l.addStretch()
        layout.addWidget(q_btn_frame)

        self.q_table = QtWidgets.QTableWidget(0,5)
        self.q_table.setHorizontalHeaderLabels(["ID","Original Path","Date","Size","Actions"])
        self.q_table.setStyleSheet(f"QTableWidget {{ background: rgba(36,36,38,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QHeaderView::section {{ background: rgba(44,44,46,0.8); color: {ACCENT_LIGHT}; border: none; padding: 6px 8px; }} QPushButton {{ background: {ACCENT}; color: white; border: none; border-radius: 8px; padding: 5px 12px; font-size: 11px; }}")
        self.q_table.horizontalHeader().setStretchLastSection(True)
        self.q_table.setColumnWidth(0,100); self.q_table.setColumnWidth(1,250); self.q_table.setColumnWidth(2,140); self.q_table.setColumnWidth(3,60); self.q_table.setColumnWidth(4,280)
        layout.addWidget(self.q_table, 1)
        self._refresh_quarantine()
        self.content_stack.addWidget(w)

    # ===== TOOLS =====
    def _build_tools(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🧰  Tools"), "Sandbox, Rootkit Detection, Password Manager, Scheduler")
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }} QTabBar::tab {{ background: transparent; color: {TEXT_DIM}; padding: 8px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 4px 2px; }} QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: 600; }} QTabBar::tab:hover {{ color: {TEXT}; }} QTabBar {{ background: rgba(44,44,46,0.4); border-radius: 10px; padding: 2px; }}")

        # Sandbox
        sand_w = QtWidgets.QWidget()
        sand_l = QtWidgets.QVBoxLayout(sand_w)
        if self.sandbox.available:
            sand_l.addWidget(QtWidgets.QLabel(f"Sandbox: {self.sandbox.sandbox_type} available"))
            sand_row = QtWidgets.QHBoxLayout()
            sand_row.addWidget(self._btn(_("📁 Select File & Run"), self._sandbox_run))
            sand_l.addLayout(sand_row)
        else:
            sand_l.addWidget(QtWidgets.QLabel("⚠ No sandbox tool found. Install firejail: sudo apt install firejail"))
        tabs.addTab(sand_w, "Sandbox")

        # Rootkit
        rk_w = QtWidgets.QWidget()
        rk_l = QtWidgets.QVBoxLayout(rk_w)
        rk_l.addWidget(self._btn(_("🔍 Run Rootkit Scan"), self._rootkit_scan))
        self.rk_results = QtWidgets.QPlainTextEdit()
        self.rk_results.setReadOnly(True)
        self.rk_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; padding: 10px;")
        rk_l.addWidget(self.rk_results, 1)
        tabs.addTab(rk_w, "Rootkit Detector")

        # Password Manager
        pwd_w = QtWidgets.QWidget()
        pwd_l = QtWidgets.QVBoxLayout(pwd_w)
        pwd_top = QtWidgets.QHBoxLayout()
        self.pwd_unlock_btn = self._btn(_("🔓 Unlock Vault"), self._pwd_unlock)
        pwd_top.addWidget(self.pwd_unlock_btn)
        pwd_top.addWidget(self._btn(_("🔒 Lock"), self._pwd_lock))
        pwd_top.addStretch()
        pwd_l.addLayout(pwd_top)

        pwd_form = QtWidgets.QFrame()
        pwd_form.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        pwd_form_l = QtWidgets.QVBoxLayout(pwd_form)
        pwd_form_l.addWidget(QtWidgets.QLabel("New Entry"))
        fg = QtWidgets.QGridLayout()
        fg.addWidget(QtWidgets.QLabel("Site:"),0,0); self.pwd_site = QtWidgets.QLineEdit(); fg.addWidget(self.pwd_site,0,1)
        fg.addWidget(QtWidgets.QLabel("User:"),1,0); self.pwd_user = QtWidgets.QLineEdit(); fg.addWidget(self.pwd_user,1,1)
        fg.addWidget(QtWidgets.QLabel("Pass:"),2,0); self.pwd_pass = QtWidgets.QLineEdit(); fg.addWidget(self.pwd_pass,2,1)
        self.pwd_site.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 12px;")
        self.pwd_user.setStyleSheet(self.pwd_site.styleSheet()); self.pwd_pass.setStyleSheet(self.pwd_site.styleSheet())
        pwd_form_l.addLayout(fg)
        pwd_form_l.addWidget(self._btn(_("💾 Save Entry"), self._pwd_add))
        pwd_l.addWidget(pwd_form)
        self.pwd_list = QtWidgets.QListWidget()
        self.pwd_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }}")
        pwd_l.addWidget(self.pwd_list, 1)
        self._refresh_pwd()
        tabs.addTab(pwd_w, "Password Manager")

        # Scheduler
        sched_w = QtWidgets.QWidget()
        sched_l = QtWidgets.QVBoxLayout(sched_w)
        sched_l.addWidget(QtWidgets.QLabel("Scheduled Scans"))
        sched_form = QtWidgets.QHBoxLayout()
        self.sched_name = QtWidgets.QLineEdit(); self.sched_name.setPlaceholderText("Name")
        self.sched_path = QtWidgets.QLineEdit(); self.sched_path.setPlaceholderText("Path to scan")
        self.sched_hours = QtWidgets.QSpinBox(); self.sched_hours.setRange(1,168); self.sched_hours.setValue(24); self.sched_hours.setPrefix("Every "); self.sched_hours.setSuffix("h")
        for wgt in [self.sched_name, self.sched_path, self.sched_hours]:
            wgt.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 12px;")
        sched_form.addWidget(self.sched_name)
        sched_form.addWidget(self.sched_path)
        sched_form.addWidget(self.sched_hours)
        sched_form.addWidget(self._btn(_("➕ Add"), self._sched_add))
        sched_l.addLayout(sched_form)
        self.sched_list = QtWidgets.QListWidget()
        self.sched_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }}")
        sched_l.addWidget(self.sched_list, 1)
        sched_l.addWidget(self._btn(_("🔄 Refresh"), self._sched_refresh))
        self._sched_refresh()
        tabs.addTab(sched_w, "Scheduler")

        # Data Shredder
        shred_w = QtWidgets.QWidget()
        shred_l = QtWidgets.QVBoxLayout(shred_w)
        shred_l.addWidget(QtWidgets.QLabel("Secure File Shredder"))
        shred_l.addWidget(QtWidgets.QLabel("Overwrites files with random data before deletion"))
        shred_row = QtWidgets.QHBoxLayout()
        shred_row.addWidget(self._btn(_("📁 Shred File"), self._shred_file))
        shred_row.addWidget(self._btn(_("📂 Shred Folder"), self._shred_folder))
        shred_l.addLayout(shred_row)
        std_row = QtWidgets.QHBoxLayout()
        std_row.addWidget(QtWidgets.QLabel("Standard:"))
        self.shred_standard = QtWidgets.QComboBox()
        for key in self.shredder.standards:
            self.shred_standard.addItem(key, key)
        self.shred_standard.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 10px;font-size:12px;")
        self.shred_standard.currentIndexChanged.connect(self._shred_standard_changed)
        std_row.addWidget(self.shred_standard)
        std_row.addWidget(self._btn(_("🧹 Wipe Free Space"), self._shred_free_space))
        shred_l.addLayout(std_row)
        self.shred_progress = QtWidgets.QProgressBar()
        self.shred_progress.setStyleSheet(f"QProgressBar {{ background: {DARK_MID}; border: 1px solid {BORDER}; border-radius: 4px; height: 14px; }} QProgressBar::chunk {{ background: {RED}; border-radius: 3px; }}")
        self.shred_progress.hide()
        shred_l.addWidget(self.shred_progress)
        self.shred_status = QtWidgets.QLabel("")
        self.shred_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        shred_l.addWidget(self.shred_status)
        shred_l.addStretch()
        tabs.addTab(shred_w, "Shredder")

        # Cleanup
        clean_w = QtWidgets.QWidget()
        clean_l = QtWidgets.QVBoxLayout(clean_w)
        clean_l.addWidget(QtWidgets.QLabel("System Cleanup"))
        clean_l.addWidget(QtWidgets.QLabel("Clean APT cache, logs, temp files, caches, trash"))
        clean_l.addWidget(self._btn(_("🧹 Run Cleanup"), self._run_cleanup))
        clean_l.addWidget(self._btn(_("👁 Preview Cleanup"), self._cleanup_preview))
        self.clean_progress = QtWidgets.QProgressBar()
        self.clean_progress.setStyleSheet(f"QProgressBar {{ background: {DARK_MID}; border: 1px solid {BORDER}; border-radius: 4px; height: 14px; }} QProgressBar::chunk {{ background: {GREEN}; border-radius: 3px; }}")
        self.clean_progress.hide()
        clean_l.addWidget(self.clean_progress)
        self.clean_status = QtWidgets.QLabel("")
        self.clean_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        clean_l.addWidget(self.clean_status)
        self.clean_results = QtWidgets.QListWidget()
        self.clean_results.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }}")
        clean_l.addWidget(self.clean_results, 1)
        tabs.addTab(clean_w, "Cleanup")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(w)

    # ===== ACCOUNT / LOGIN / REGISTER =====
    def _build_report_error(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("👤  Account"), _("Login, register, and manage your DefendR account"))
        self.acct_stack = QtWidgets.QStackedWidget()

        # Page 0: Login/Register form
        login_page = QtWidgets.QWidget()
        login_l = QtWidgets.QVBoxLayout(login_page)
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }} QTabBar::tab {{ background: transparent; color: {TEXT_DIM}; padding: 8px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 4px 2px; }} QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: 600; }} QTabBar::tab:hover {{ color: {TEXT}; }} QTabBar {{ background: rgba(44,44,46,0.4); border-radius: 10px; padding: 2px; }}")

        # Login tab
        login_tab = QtWidgets.QWidget()
        login_tab_l = QtWidgets.QVBoxLayout(login_tab)
        lf = QtWidgets.QFrame()
        lf.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        lf_l = QtWidgets.QVBoxLayout(lf)
        lf_l.addWidget(QtWidgets.QLabel(_("Login")))
        lg = QtWidgets.QGridLayout()
        lg.addWidget(QtWidgets.QLabel(_("Email:")), 0, 0)
        self.log_email = QtWidgets.QLineEdit()
        self.log_email.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 12px;")
        lg.addWidget(self.log_email, 0, 1)
        lg.addWidget(QtWidgets.QLabel(_("Password:")), 1, 0)
        self.log_pass = QtWidgets.QLineEdit()
        self.log_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.log_pass.setStyleSheet(self.log_email.styleSheet())
        lg.addWidget(self.log_pass, 1, 1)
        lf_l.addLayout(lg)
        lr = QtWidgets.QHBoxLayout()
        lr.addWidget(self._btn(_("Login"), self._do_login))
        self.log_status = QtWidgets.QLabel("")
        self.log_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        lr.addWidget(self.log_status)
        lr.addStretch()
        lf_l.addLayout(lr)
        login_tab_l.addWidget(lf)
        login_tab_l.addStretch()
        tabs.addTab(login_tab, _("Login"))

        # Register tab
        reg_tab = QtWidgets.QWidget()
        reg_tab_l = QtWidgets.QVBoxLayout(reg_tab)
        rf = QtWidgets.QFrame()
        rf.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        rf_l = QtWidgets.QVBoxLayout(rf)
        rf_l.addWidget(QtWidgets.QLabel(_("Create Account")))
        rg = QtWidgets.QGridLayout()
        rg.addWidget(QtWidgets.QLabel(_("Username:")), 0, 0)
        self.reg_user = QtWidgets.QLineEdit()
        self.reg_user.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 12px;")
        rg.addWidget(self.reg_user, 0, 1)
        rg.addWidget(QtWidgets.QLabel(_("Email:")), 1, 0)
        self.reg_email = QtWidgets.QLineEdit()
        self.reg_email.setStyleSheet(self.reg_user.styleSheet())
        rg.addWidget(self.reg_email, 1, 1)
        rg.addWidget(QtWidgets.QLabel(_("Password:")), 2, 0)
        self.reg_pass = QtWidgets.QLineEdit()
        self.reg_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.reg_pass.setStyleSheet(self.reg_user.styleSheet())
        rg.addWidget(self.reg_pass, 2, 1)
        rf_l.addLayout(rg)
        rr = QtWidgets.QHBoxLayout()
        rr.addWidget(self._btn(_("Register"), self._do_register))
        self.reg_status = QtWidgets.QLabel("")
        self.reg_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        rr.addWidget(self.reg_status)
        rr.addStretch()
        rf_l.addLayout(rr)
        reg_tab_l.addWidget(rf)
        reg_tab_l.addStretch()
        tabs.addTab(reg_tab, _("Register"))
        login_l.addWidget(tabs)
        self.acct_stack.addWidget(login_page)

        # Page 1: Account info (when logged in)
        acct_page = QtWidgets.QWidget()
        acct_l = QtWidgets.QVBoxLayout(acct_page)
        info_frame = QtWidgets.QFrame()
        info_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        info_l = QtWidgets.QVBoxLayout(info_frame)
        info_l.addWidget(QtWidgets.QLabel(_("Account Info")))
        self.acct_info = QtWidgets.QTextEdit()
        self.acct_info.setReadOnly(True)
        self.acct_info.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; padding: 10px;")
        self.acct_info.setMaximumHeight(200)
        info_l.addWidget(self.acct_info)
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self._btn(_("🔄 Refresh"), self._refresh_account))
        btn_row.addWidget(self._btn(_("🚪 Logout"), self._do_logout))
        btn_row.addStretch()
        info_l.addLayout(btn_row)
        acct_l.addWidget(info_frame)

        # Error report section inside account page
        rpt_frame = QtWidgets.QFrame()
        rpt_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        rpt_l = QtWidgets.QVBoxLayout(rpt_frame)
        rpt_l.addWidget(QtWidgets.QLabel(_("Send Error Report")))
        rpt_grid = QtWidgets.QGridLayout()
        rpt_grid.addWidget(QtWidgets.QLabel(_("Type:")), 0, 0)
        self.rpt_type = QtWidgets.QComboBox()
        self.rpt_type.addItems([_("Bug"), _("Feature Request"), _("False Positive"), _("Crash"), _("Other")])
        self.rpt_type.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 10px;font-size:12px;")
        rpt_grid.addWidget(self.rpt_type, 0, 1)
        rpt_grid.addWidget(QtWidgets.QLabel(_("Message:")), 1, 0)
        self.rpt_message = QtWidgets.QPlainTextEdit()
        self.rpt_message.setPlaceholderText(_("Describe the issue..."))
        self.rpt_message.setStyleSheet(f"background:{DARK_BG};color:{TEXT};border:1px solid {BORDER};border-radius:8px;padding:6px 12px;")
        self.rpt_message.setMaximumHeight(100)
        rpt_grid.addWidget(self.rpt_message, 1, 1)
        rpt_l.addLayout(rpt_grid)
        rpt_l.addWidget(self._btn(_("Send Report"), self._do_send_report))
        self.rpt_status = QtWidgets.QLabel("")
        self.rpt_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        rpt_l.addWidget(self.rpt_status)
        acct_l.addWidget(rpt_frame)
        acct_l.addStretch()
        self.acct_stack.addWidget(acct_page)

        layout.addWidget(self.acct_stack, 1)
        self.content_stack.addWidget(w)
        self._update_account_ui()

    def _update_account_ui(self):
        if self.telemetry.is_registered():
            self.acct_stack.setCurrentIndex(1)
            self._refresh_account()
        else:
            self.acct_stack.setCurrentIndex(0)

    def _do_login(self):
        email = self.log_email.text().strip()
        pwd = self.log_pass.text().strip()
        if not email or not pwd:
            self.log_status.setText(_("Fill all fields"))
            return
        ok, msg = self.telemetry.login(email, pwd)
        self.log_status.setText(msg)
        if ok:
            self._update_account_ui()

    def _do_register(self):
        user = self.reg_user.text().strip()
        email = self.reg_email.text().strip()
        pwd = self.reg_pass.text().strip()
        if not user or not email or not pwd:
            self.reg_status.setText(_("Fill all fields"))
            return
        ok, msg = self.telemetry.register(user, email, pwd)
        self.reg_status.setText(msg)
        if ok:
            self._update_account_ui()

    def _do_logout(self):
        self.telemetry.logout()
        self._update_account_ui()

    def _refresh_account(self):
        info = self.telemetry.get_user_info()
        txt = f"{_('Username:')} {self.telemetry.get_username()}\n"
        txt += f"{_('Email:')} {self.telemetry.get_email()}\n"
        txt += f"UID: {self.telemetry.uid or 'N/A'}\n"
        if info.get("registered"):
            txt += f"{_('Registered:')} {info['registered'][:19]}\n"
        if info.get("last_seen"):
            txt += f"{_('Last seen:')} {info['last_seen'][:19]}\n"
        pc = info.get("pc_info", {})
        if pc:
            txt += f"\n--- {_('PC Info')} ---\n"
            for k, v in pc.items():
                txt += f"{k}: {v}\n"
        self.acct_info.setPlainText(txt)

    def _do_send_report(self):
        if not self.telemetry.is_registered():
            self.rpt_status.setText(_("You must be logged in"))
            return
        msg = self.rpt_message.toPlainText().strip()
        if not msg:
            self.rpt_status.setText(_("Write a message"))
            return
        rtype = self.rpt_type.currentText().lower().replace(" ", "_")
        self.telemetry.send_report(rtype, msg)
        self.rpt_status.setText(_("Report sent!"))
        self.rpt_message.clear()

    # ===== HD SCAN =====
    def _build_hd_scan(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("💿  HD Scanner"), _("Scan your drives and get security recommendations"))

        mode_frame = QtWidgets.QFrame()
        mode_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 16px; padding: 10px;")
        mode_l = QtWidgets.QHBoxLayout(mode_frame)
        mode_l.setContentsMargins(20, 10, 20, 10)
        self.hd_mode = "rapido"
        self.hd_rapido_btn = QtWidgets.QPushButton(_("Rápido"))
        self.hd_completo_btn = QtWidgets.QPushButton(_("Completo"))
        for btn in (self.hd_rapido_btn, self.hd_completo_btn):
            btn.setCursor(QtCore.Qt.PointingHandCursor)
            btn.setFixedHeight(42)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: rgba(44,44,46,0.6);
                    color: {TEXT_DIM};
                    border: 2px solid transparent;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: 600;
                    padding: 0 24px;
                }}
                QPushButton:hover {{
                    color: {TEXT};
                    border-color: {ACCENT};
                }}
            """)
        self.hd_rapido_btn.setStyleSheet(self.hd_rapido_btn.styleSheet() + f"""
            QPushButton {{
                background: {ACCENT};
                color: white;
                border-color: {ACCENT_LIGHT};
            }}
        """)
        self.hd_rapido_btn.clicked.connect(lambda: self._hd_set_mode("rapido"))
        self.hd_completo_btn.clicked.connect(lambda: self._hd_set_mode("completo"))
        mode_l.addWidget(self.hd_rapido_btn)
        mode_l.addWidget(self.hd_completo_btn)
        self.hd_rapido_btn.setToolTip("Rápido: escaneia apenas locais comuns de malware")
        self.hd_completo_btn.setToolTip("Completo: escaneia todo o sistema de arquivos (pode demorar)")
        layout.addWidget(mode_frame)

        ball_frame = QtWidgets.QFrame()
        ball_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 16px;")
        ball_l = QtWidgets.QVBoxLayout(ball_frame)
        ball_l.setAlignment(QtCore.Qt.AlignCenter)
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.setAlignment(QtCore.Qt.AlignCenter)
        self.hd_ball_btn = QtWidgets.QPushButton()
        self.hd_ball_btn.setFixedSize(120, 120)
        self.hd_ball_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.hd_ball_btn.setStyleSheet(f"""
            QPushButton {{
                background: qradialgradient(cx:0.4, cy:0.4, radius:0.5,
                    stop:0 {ACCENT_LIGHT}, stop:0.6 {ACCENT}, stop:1 {ACCENT_DARK});
                border: 3px solid {BORDER};
                border-radius: 60px;
                font-size: 40px;
                color: white;
            }}
            QPushButton:hover {{
                border-color: {ACCENT_LIGHT};
                background: qradialgradient(cx:0.4, cy:0.4, radius:0.5,
                    stop:0 #d0b3ff, stop:0.6 {ACCENT_LIGHT}, stop:1 {ACCENT});
            }}
            QPushButton:pressed {{
                background: qradialgradient(cx:0.4, cy:0.4, radius:0.5,
                    stop:0 {ACCENT}, stop:0.6 {ACCENT_DARK}, stop:1 #4a00b3);
            }}
        """)
        self.hd_ball_btn.setText("▶")
        self.hd_ball_btn.clicked.connect(self._hd_start_scan)
        self.hd_ball_btn.setToolTip("Clique para iniciar o escaneamento do HD")
        btn_row.addWidget(self.hd_ball_btn)
        self.hd_stop_btn = QtWidgets.QPushButton("■")
        self.hd_stop_btn.setFixedSize(90, 90)
        self.hd_stop_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.hd_stop_btn.setToolTip("Para o escaneamento em andamento")
        self.hd_stop_btn.setStyleSheet(f"""
            QPushButton {{
                background: qradialgradient(cx:0.4, cy:0.4, radius:0.5,
                    stop:0 #ff6b6b, stop:0.6 #e03131, stop:1 #c92a2a);
                border: 3px solid #ff8787;
                border-radius: 45px;
                font-size: 32px;
                color: white;
            }}
            QPushButton:hover {{
                border-color: white;
                background: qradialgradient(cx:0.4, cy:0.4, radius:0.5,
                    stop:0 #ff8787, stop:0.6 #e03131, stop:1 #c92a2a);
            }}
        """)
        self.hd_stop_btn.hide()
        self.hd_stop_btn.clicked.connect(self._hd_stop_scan)
        btn_row.addSpacing(10)
        btn_row.addWidget(self.hd_stop_btn)
        ball_l.addLayout(btn_row)
        self.hd_ball_label = QtWidgets.QLabel(_("Click to scan your HD"))
        self.hd_ball_label.setStyleSheet(f"font-size: 14px; color: {ACCENT_LIGHT}; background: transparent;")
        self.hd_ball_label.setAlignment(QtCore.Qt.AlignCenter)
        ball_l.addWidget(self.hd_ball_label)
        layout.addWidget(ball_frame, 0, QtCore.Qt.AlignCenter)
        self.hd_progress = QtWidgets.QProgressBar()
        self.hd_progress.setStyleSheet(f"QProgressBar {{ background: rgba(44,44,46,0.6); border: none; border-radius: 8px; height: 14px; text-align: center; font-size: 10px; color: {TEXT}; }} QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {ACCENT_LIGHT}); border-radius: 8px; }}")
        self.hd_progress.hide()
        self.hd_progress.setTextVisible(True)
        layout.addWidget(self.hd_progress)
        self.hd_status = QtWidgets.QLabel(_("Ready"))
        self.hd_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        layout.addWidget(self.hd_status)
        hd_tabs = QtWidgets.QTabWidget()
        hd_tabs.setStyleSheet(f"QTabWidget::pane {{ background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }} QTabBar::tab {{ background: transparent; color: {TEXT_DIM}; padding: 8px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 4px 2px; }} QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: 600; }} QTabBar::tab:hover {{ color: {TEXT}; }} QTabBar {{ background: rgba(44,44,46,0.4); border-radius: 10px; padding: 2px; }}")

        results_w = QtWidgets.QWidget()
        results_l = QtWidgets.QVBoxLayout(results_w)
        self.hd_results_tree = QtWidgets.QTreeWidget()
        self.hd_results_tree.setHeaderLabels([_("Risk"), _("Path"), _("Directory"), _("Reason")])
        self.hd_results_tree.setColumnWidth(0, 90)
        self.hd_results_tree.setColumnWidth(2, 200)
        self.hd_results_tree.setColumnWidth(3, 300)
        self.hd_results_tree.setStyleSheet(f"QTreeWidget {{ background: rgba(36,36,38,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QTreeWidget::item {{ padding: 6px 8px; border-bottom: 1px solid {DARK_MID}; }} QHeaderView::section {{ background: rgba(44,44,46,0.8); color: {ACCENT_LIGHT}; border: none; padding: 6px 8px; font-size: 12px; font-weight: 600; }}")
        self.hd_results_tree.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.hd_results_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.hd_results_tree.customContextMenuRequested.connect(self._hd_tree_context_menu)
        results_l.addWidget(self.hd_results_tree)
        hd_actions = QtWidgets.QHBoxLayout()
        b = self._btn("📂 Abrir local", self._hd_open_location); b.setToolTip("Abre a pasta do arquivo selecionado"); hd_actions.addWidget(b)
        b = self._btn("✅ Validar", self._hd_validate_selected, "#30d158"); b.setToolTip("Marca o arquivo como seguro (whitelist)"); hd_actions.addWidget(b)
        b = self._btn("📦 Quarentena", self._hd_quarantine_selected); b.setToolTip("Move o arquivo para a quarentena"); hd_actions.addWidget(b)
        b = self._btn("🗑 Excluir", self._hd_delete_selected, "#c0392b"); b.setToolTip("Exclui permanentemente o arquivo"); hd_actions.addWidget(b)
        hd_actions.addStretch()
        results_l.addLayout(hd_actions)
        hd_tabs.addTab(results_w, _("Results"))

        recs_w = QtWidgets.QWidget()
        recs_l = QtWidgets.QVBoxLayout(recs_w)
        self.hd_recs_list = QtWidgets.QListWidget()
        self.hd_recs_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QListWidget::item {{ padding: 8px 12px; border-bottom: 1px solid {DARK_MID}; }}")
        recs_l.addWidget(self.hd_recs_list)
        hd_tabs.addTab(recs_w, _("Recommendations"))

        drives_w = QtWidgets.QWidget()
        drives_l = QtWidgets.QVBoxLayout(drives_w)
        self.hd_drives_list = QtWidgets.QListWidget()
        self.hd_drives_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QListWidget::item {{ padding: 6px 10px; }}")
        drives_l.addWidget(self.hd_drives_list)
        hd_tabs.addTab(drives_w, _("Drives"))
        layout.addWidget(hd_tabs, 1)
        self.content_stack.addWidget(w)

    def _hd_set_mode(self, mode):
        self.hd_mode = mode
        if mode == "rapido":
            self.hd_rapido_btn.setStyleSheet(f"""
                QPushButton {{ background: {ACCENT}; color: white; border: 2px solid {ACCENT_LIGHT}; border-radius: 10px; font-size: 14px; font-weight: 600; padding: 0 24px; height: 42px; }}
                QPushButton:hover {{ border-color: white; }}
            """)
            self.hd_completo_btn.setStyleSheet(f"""
                QPushButton {{ background: rgba(44,44,46,0.6); color: {TEXT_DIM}; border: 2px solid transparent; border-radius: 10px; font-size: 14px; font-weight: 600; padding: 0 24px; height: 42px; }}
                QPushButton:hover {{ color: {TEXT}; border-color: {ACCENT}; }}
            """)
        else:
            self.hd_rapido_btn.setStyleSheet(f"""
                QPushButton {{ background: rgba(44,44,46,0.6); color: {TEXT_DIM}; border: 2px solid transparent; border-radius: 10px; font-size: 14px; font-weight: 600; padding: 0 24px; height: 42px; }}
                QPushButton:hover {{ color: {TEXT}; border-color: {ACCENT}; }}
            """)
            self.hd_completo_btn.setStyleSheet(f"""
                QPushButton {{ background: {ACCENT}; color: white; border: 2px solid {ACCENT_LIGHT}; border-radius: 10px; font-size: 14px; font-weight: 600; padding: 0 24px; height: 42px; }}
                QPushButton:hover {{ border-color: white; }}
            """)

    def _hd_stop_scan(self):
        self.engine.scanning = False
        if hasattr(self, '_hd_worker') and hasattr(self._hd_worker, '_hd_proc') and self._hd_worker._hd_proc:
            try:
                self._hd_worker._hd_proc.kill()
            except Exception:
                pass
        self.hd_stop_btn.setEnabled(False)
        self.hd_status.setText(_("Stopping scan..."))

    def _hd_start_scan(self):
        self.hd_results_tree.clear()
        self.hd_recs_list.clear()
        self.hd_progress.setValue(0)
        self.hd_progress.setFormat("")
        self.hd_progress.show()
        self.hd_ball_btn.setText("⏳")
        self.hd_ball_btn.setEnabled(False)
        self.hd_stop_btn.show()
        self.hd_stop_btn.setEnabled(True)
        label = _("Quick scan in progress...") if self.hd_mode == "rapido" else _("Full scan in progress...")
        self.hd_status.setText(label)
        paths = ["/"]
        try:
            import psutil, os
            seen = set()
            for p in psutil.disk_partitions():
                if p.fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "devpts",
                                "cgroup2", "cgroup", "pstore", "efivarfs",
                                "fusectl", "securityfs", "selinuxfs",
                                "debugfs", "tracefs", "hugetlbfs", "mqueue",
                                "configfs", "bpf", "bpf_fs"):
                    continue
                seen.add(p.mountpoint)
            paths = ["/"] if "/" in seen else list(seen)
        except Exception:
            pass
        self._hd_worker = ScanWorker(self.engine, paths, mode=self.hd_mode)
        self._hd_worker.finished.connect(self._hd_scan_done)
        self._hd_worker.progress.connect(self._hd_update_progress)
        self._hd_worker.result_found.connect(self._hd_add_result_item)
        self._hd_worker.start()

    def _hd_update_progress(self, pct, msg):
        if pct >= 0:
            self.hd_progress.setRange(0, 100)
            self.hd_progress.setValue(min(pct, 100))
            self.hd_progress.setFormat(f"{min(pct, 100)}%")
        else:
            self.hd_progress.setRange(0, 0)
            self.hd_progress.setFormat("")
        self.hd_status.setText(msg)

    def _hd_add_result_item(self, r):
        risk = r.get("risk", "unknown")
        if risk == "pentest":
            return
        d = os.path.dirname(r["path"])
        if risk == "malicious":
            item = QtWidgets.QTreeWidgetItem([_("MALICIOUS"), r["path"], d, r.get("reason", "")])
            for i in range(4): item.setForeground(i, QtGui.QColor(RED))
        elif risk == "suspicious":
            item = QtWidgets.QTreeWidgetItem([_("SUSPICIOUS"), r["path"], d, r.get("reason", "")])
            for i in range(4): item.setForeground(i, QtGui.QColor(YELLOW))
        elif risk == "pentest":
            item = QtWidgets.QTreeWidgetItem([_("ALLOWED"), r["path"], d, r.get("reason", "")])
            for i in range(4): item.setForeground(i, QtGui.QColor(CYAN))
        else:
            return
        item.setToolTip(1, r["path"])
        self.hd_results_tree.addTopLevelItem(item)

    def _hd_scan_done(self, results):
        self.hd_progress.hide()
        self.hd_stop_btn.hide()
        self.hd_ball_btn.setText("✓")
        self.hd_ball_btn.setEnabled(True)
        malicious = len(results["malicious"])
        suspicious = len(results["suspicious"])
        safe = results["safe"]
        total = malicious + suspicious + safe + len(results["pentest"])
        mode_label = _("Quick scan") if self.hd_mode == "rapido" else _("Full scan")
        self.hd_ball_label.setText(_("%s complete: %d files") % (mode_label, total))
        if not any([results["malicious"], results["suspicious"], results["pentest"]]):
            item = QtWidgets.QTreeWidgetItem([_("SAFE"), _("No threats found"), "", _("All files are clean")])
            for i in range(4): item.setForeground(i, QtGui.QColor(GREEN))
            self.hd_results_tree.addTopLevelItem(item)
        if safe > 0:
            self.hd_recs_list.addItem(_("✅ %d clean files - no action needed") % safe)
        if malicious:
            self._show_msg(f"HD Scan: {malicious} malware encontrado!", sound=True)
        if malicious > 0:
            self.hd_recs_list.addItem(_("🔴 %d malicious files found - quarantine them immediately") % malicious)
        if suspicious > 0:
            self.hd_recs_list.addItem(_("🟡 %d suspicious files - review manually") % suspicious)
        if malicious == 0 and suspicious == 0:
            self.hd_recs_list.addItem(_("🟢 Drive is clean - no security issues detected"))
        self.hd_recs_list.addItem(_("💾 Disk usage: check for large unused files in Settings > Cleanup"))
        self.hd_recs_list.addItem(_("🔄 Signatures: keep DefendR updated for best detection"))
        try:
            import psutil
            for part in psutil.disk_partitions():
                if part.fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "devpts",
                                   "cgroup2", "cgroup", "pstore", "efivarfs",
                                   "fusectl", "securityfs", "selinuxfs",
                                   "debugfs", "tracefs", "hugetlbfs", "mqueue",
                                   "configfs", "bpf", "bpf_fs"):
                    continue
                try:
                    du = psutil.disk_usage(part.mountpoint)
                    pct = du.used / du.total * 100
                    self.hd_recs_list.addItem(_("📊 %s: %dGB / %dGB (%d%% used)") % (
                        part.mountpoint, du.used//(1024**3), du.total//(1024**3), pct))
                    if pct > 90:
                        self.hd_recs_list.addItem(_("🔴 WARNING: %s almost full - free up space") % part.mountpoint)
                    elif pct > 75:
                        self.hd_recs_list.addItem(_("🟡 %s above 75%% - consider cleanup") % part.mountpoint)
                except Exception:
                    pass
        except Exception:
            pass
        if self.telemetry.is_registered():
            self.telemetry.send_scan_result("hd_scan", {
                "malicious": malicious, "suspicious": suspicious, "safe": safe, "mode": self.hd_mode,
            })
        self._refresh_drives()

    def _hd_tree_context_menu(self, pos):
        item = self.hd_results_tree.itemAt(pos)
        if not item or item.text(0) in ("SAFE",):
            return
        path = item.toolTip(1)
        menu = QtWidgets.QMenu()
        if path and os.path.isfile(path):
            menu.addAction("📂 Abrir local do arquivo").triggered.connect(
                lambda: os.system(f'xdg-open "{os.path.dirname(path)}"'))
            menu.addSeparator()
            menu.addAction("✅ Validar (ignorar sempre)").triggered.connect(
                lambda: self._hd_validate_path(path))
            menu.addAction("📦 Mover para Quarentena").triggered.connect(
                lambda: self._hd_quarantine_path(path))
            menu.addAction("🗑 Excluir permanentemente").triggered.connect(
                lambda: self._hd_delete_path(path))
        menu.addSeparator()
        menu.addAction("📦 Quarentena dos selecionados").triggered.connect(
            self._hd_quarantine_selected)
        menu.exec_(self.hd_results_tree.viewport().mapToGlobal(pos))

    def _hd_open_location(self):
        item = self.hd_results_tree.currentItem()
        if not item or item.text(0) in ("SAFE",):
            self._show_msg("Selecione um arquivo na lista")
            return
        path = item.toolTip(1)
        if not path or not os.path.isfile(path):
            self._show_msg("Arquivo nao encontrado")
            return
        os.system(f'xdg-open "{os.path.dirname(path)}"')

    def _hd_validate_selected(self):
        for item in self.hd_results_tree.selectedItems():
            if item.text(0) in ("SAFE",):
                continue
            path = item.toolTip(1)
            if path and os.path.isfile(path):
                self._hd_validate_path(path)

    def _hd_validate_path(self, path):
        self.engine.whitelist.add(path.lower())
        self.engine.save_config()
        self._show_msg(f"✅ Validado: {os.path.basename(path)}")

    def _hd_quarantine_selected(self):
        items = self.hd_results_tree.selectedItems()
        if not items:
            return
        paths = []
        for item in items:
            if item.text(0) in ("SAFE",):
                continue
            p = item.toolTip(1)
            if p and os.path.isfile(p):
                paths.append(p)
        if not paths:
            return
        if len(paths) > 1:
            reply = QtWidgets.QMessageBox.question(self, "Confirmar",
                f"Mover {len(paths)} arquivo(s) para quarentena?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if reply != QtWidgets.QMessageBox.Yes:
                return
        for p in paths:
            ok, msg = self.quarantine.quarantine(p)
            if ok:
                self._remove_hd_tree_item(p)
        if len(paths) == 1:
            self._show_msg(f"📦 Quarentenado: {os.path.basename(paths[0])}")

    def _hd_delete_selected(self):
        items = self.hd_results_tree.selectedItems()
        if not items:
            return
        paths = []
        for item in items:
            if item.text(0) in ("SAFE",):
                continue
            p = item.toolTip(1)
            if p and os.path.isfile(p):
                paths.append(p)
        if not paths:
            return
        label = f"Excluir permanentemente '{os.path.basename(paths[0])}'?" if len(paths) == 1 else f"Excluir permanentemente {len(paths)} arquivo(s)?"
        reply = QtWidgets.QMessageBox.question(self, "Confirmar", label,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply != QtWidgets.QMessageBox.Yes:
            return
        deleted = 0
        for p in paths:
            try:
                os.remove(p)
                self._remove_hd_tree_item(p)
                deleted += 1
            except Exception as e:
                self._show_msg(f"Erro ao excluir {os.path.basename(p)}: {e}")
        if len(paths) == 1 and deleted > 0:
            self._show_msg(f"🗑 Excluído: {os.path.basename(paths[0])}")

    def _hd_quarantine_path(self, path):
        ok, msg = self.quarantine.quarantine(path)
        if ok:
            self._show_msg(f"📦 Quarentenado: {os.path.basename(path)}")
            self._remove_hd_tree_item(path)
        else:
            self._show_msg(f"Erro: {msg}")

    def _hd_delete_path(self, path):
        reply = QtWidgets.QMessageBox.question(self, "Confirmar",
            f"Excluir permanentemente '{os.path.basename(path)}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            try:
                os.remove(path)
                self._show_msg(f"🗑 Excluído: {os.path.basename(path)}")
                self._remove_hd_tree_item(path)
            except Exception as e:
                self._show_msg(f"Erro ao excluir: {e}")

    def _remove_hd_tree_item(self, path):
        for i in range(self.hd_results_tree.topLevelItemCount()):
            item = self.hd_results_tree.topLevelItem(i)
            if item.toolTip(1) == path:
                self.hd_results_tree.takeTopLevelItem(i)
                break

    def _refresh_drives(self):
        self.hd_drives_list.clear()
        try:
            import psutil
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    self.hd_drives_list.addItem(
                        f"{part.device:20s} {part.mountpoint:25s} "
                        f"{usage.used//(1024**3):>4d}GB / {usage.total//(1024**3):>4d}GB "
                        f"({usage.percent:>3.0f}%) [{part.fstype}]"
                    )
                except Exception:
                    self.hd_drives_list.addItem(f"{part.device:20s} {part.mountpoint:25s} [?] [{part.fstype}]")
        except Exception:
            self.hd_drives_list.addItem("Install psutil for drive info")

    # ===== SETTINGS =====
    def _build_settings(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔧  Settings"), "Configure DefendR behavior")
        tabs = QtWidgets.QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }} QTabBar::tab {{ background: transparent; color: {TEXT_DIM}; padding: 8px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 4px 2px; }} QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: 600; }} QTabBar::tab:hover {{ color: {TEXT}; }} QTabBar {{ background: rgba(44,44,46,0.4); border-radius: 10px; padding: 2px; }}")

        # General
        gen_w = QtWidgets.QWidget()
        gen_scroll = QtWidgets.QScrollArea()
        gen_scroll.setWidgetResizable(True)
        gen_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; } QScrollBar:vertical { width: 8px; background: transparent; } QScrollBar::handle:vertical { background: rgba(255,255,255,0.1); border-radius: 4px; min-height: 30px; } QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }")
        gen_l = QtWidgets.QVBoxLayout()
        gen_l.setContentsMargins(0, 0, 0, 0)

        prot_frame = QtWidgets.QFrame()
        prot_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        prot_l = QtWidgets.QVBoxLayout(prot_frame)
        prot_l.addWidget(QtWidgets.QLabel("Protection"))
        self.protect_cb = QtWidgets.QCheckBox("Enable real-time protection")
        self.protect_cb.setToolTip("Ativa ou desativa o monitoramento do sistema de arquivos em tempo real")
        self.protect_cb.setChecked(True)
        self.protect_cb.setStyleSheet(f"QCheckBox {{ color: {TEXT}; font-size: 12px; }} QCheckBox::indicator {{ width: 16px; height: 16px; }}")
        self.protect_cb.toggled.connect(self._toggle_protection)
        prot_l.addWidget(self.protect_cb)
        info = QtWidgets.QLabel("Pentesting tools are automatically whitelisted.\nOnly truly malicious files are flagged.")
        info.setStyleSheet(f"font-size: 10px; color: {TEXT_DIM}; background: transparent; padding: 4px 0;")
        prot_l.addWidget(info)
        gen_l.addWidget(prot_frame)

        # Signatures
        sig_frame = QtWidgets.QFrame()
        sig_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        sig_l = QtWidgets.QVBoxLayout(sig_frame)
        sig_l.addWidget(QtWidgets.QLabel("Signatures & Updates"))
        sig_row = QtWidgets.QHBoxLayout()
        sig_row.addWidget(self._btn(_("🔄 Check for Updates"), self._manual_update))
        self.sig_count = QtWidgets.QLabel(f"Signatures: {self.sig_updater.get_signature_count()}")
        self.sig_count.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        sig_row.addWidget(self.sig_count)
        sig_row.addStretch()
        sig_l.addLayout(sig_row)
        self.update_status = QtWidgets.QLabel("")
        self.update_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        sig_l.addWidget(self.update_status)
        gen_l.addWidget(sig_frame)

        # Game Mode
        gm_frame = QtWidgets.QFrame()
        gm_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        gm_l = QtWidgets.QVBoxLayout(gm_frame)
        gm_l.addWidget(QtWidgets.QLabel("Game Mode"))
        self.gm_cb = QtWidgets.QCheckBox("Auto-detect fullscreen games and suppress notifications")
        self.gm_cb.setToolTip("Suprime notificacoes do DefendR automaticamente quando um jogo em tela cheia eh detectado")
        self.gm_cb.setStyleSheet(f"QCheckBox {{ color: {TEXT}; font-size: 12px; }}")
        self.gm_cb.toggled.connect(lambda v: self.game_mode.start() if v else self.game_mode.stop())
        gm_l.addWidget(self.gm_cb)
        gen_l.addWidget(gm_frame)

        # Auto-start
        as_frame = QtWidgets.QFrame()
        as_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        as_l = QtWidgets.QVBoxLayout(as_frame)
        as_l.addWidget(QtWidgets.QLabel("Inicializacao"))
        self.autostart_cb = QtWidgets.QCheckBox("Iniciar DefendR ao ligar o computador")
        self.autostart_cb.setToolTip("Faz o DefendR iniciar automaticamente quando voce faz login")
        self.autostart_cb.setStyleSheet(f"QCheckBox {{ color: {TEXT}; font-size: 12px; }} QCheckBox::indicator {{ width: 16px; height: 16px; }}")
        self.autostart_cb.toggled.connect(self._toggle_autostart)
        as_l.addWidget(self.autostart_cb)
        # Restore autostart state
        saved = self.engine.config_data.get("autostart", False)
        self.autostart_cb.setChecked(saved)
        # If enterprise mode is active, lock the checkbox
        if self.engine.config_data.get("enterprise_mode"):
            self.autostart_cb.setEnabled(False)
        gen_l.addWidget(as_frame)

        # Enterprise Mode
        em_frame = QtWidgets.QFrame()
        em_frame.setStyleSheet(f"background: rgba(255,69,58,0.04); border: 2px solid {RED}; border-radius: 14px;")
        em_l = QtWidgets.QVBoxLayout(em_frame)
        em_header = QtWidgets.QLabel("🔥  Modo Empresarial")
        em_header.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {RED}; background: transparent;")
        em_l.addWidget(em_header)
        em_desc = QtWidgets.QLabel("Ativa todas as protecoes, bloqueia dispositivos, endurece o sistema\ne mantem vigilancia constante. Dificulta ataques de forma agressiva.")
        em_desc.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
        em_l.addWidget(em_desc)
        em_btn_row = QtWidgets.QHBoxLayout()
        self.enterprise_cb = QtWidgets.QCheckBox("Ativar Modo Empresarial")
        self.enterprise_cb.setToolTip("Modo maximo de seguranca: bloqueia dispositivos, endurece o sistema e exige senha para desativar")
        self.enterprise_cb.setStyleSheet(f"QCheckBox {{ color: {RED}; font-size: 13px; font-weight: 600; }} QCheckBox::indicator {{ width: 18px; height: 18px; }}")
        self.enterprise_cb.toggled.connect(self._toggle_enterprise_mode)
        if self.engine.config_data.get("enterprise_mode"):
            self.enterprise_cb.blockSignals(True)
            self.enterprise_cb.setChecked(True)
            self.enterprise_cb.blockSignals(False)
        em_btn_row.addWidget(self.enterprise_cb)
        em_btn_row.addStretch()
        em_l.addLayout(em_btn_row)
        gen_l.addWidget(em_frame)

        # Software Updates
        su_frame = QtWidgets.QFrame()
        su_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        su_l = QtWidgets.QVBoxLayout(su_frame)
        su_l.addWidget(QtWidgets.QLabel("Software Updater"))
        su_l.addWidget(QtWidgets.QLabel("Check for outdated system packages and pip packages"))
        su_btn_row = QtWidgets.QHBoxLayout()
        b = self._btn(_("🔍 Check for Updates"), self._check_soft_updates); b.setToolTip("Verifica se ha pacotes do sistema e pip desatualizados"); su_btn_row.addWidget(b)
        self.su_install_btn = self._btn(_("📥 Install All Updates"), self._su_install_all)
        self.su_install_btn.setToolTip("Instala todas as atualizacoes de sistema e pip disponiveis")
        su_btn_row.addWidget(self.su_install_btn)
        su_l.addLayout(su_btn_row)
        self.su_status = QtWidgets.QLabel("")
        self.su_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        su_l.addWidget(self.su_status)
        self.su_results = QtWidgets.QPlainTextEdit()
        self.su_results.setReadOnly(True)
        self.su_results.setStyleSheet(f"background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; padding: 10px; max-height: 120px;")
        su_l.addWidget(self.su_results)
        gen_l.addWidget(su_frame)

        # DefendR Update
        upd_frame = QtWidgets.QFrame()
        upd_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        upd_l = QtWidgets.QVBoxLayout(upd_frame)
        upd_l.addWidget(QtWidgets.QLabel("🛡  DefendR Atualizacao"))
        upd_l.addWidget(QtWidgets.QLabel("Baixa a versao mais recente do GitHub e reinicia automaticamente"))
        upd_row = QtWidgets.QHBoxLayout()
        b = self._btn("⬇️  Atualizar DefendR", self._update_defendr, ACCENT_LIGHT); b.setToolTip("Baixa a versao mais recente do GitHub e reinicia automaticamente"); upd_row.addWidget(b)
        self.upd_status = QtWidgets.QLabel("")
        self.upd_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        upd_row.addWidget(self.upd_status)
        upd_row.addStretch()
        upd_l.addLayout(upd_row)
        gen_l.addWidget(upd_frame)

        # Restart button
        restart_frame = QtWidgets.QFrame()
        restart_frame.setStyleSheet(f"background: rgba(255,69,58,0.04); border: 1px solid {RED}; border-radius: 14px;")
        restart_l = QtWidgets.QVBoxLayout(restart_frame)
        restart_l.addWidget(QtWidgets.QLabel("Reiniciar DefendR"))
        restart_l.addWidget(QtWidgets.QLabel("Reinicia o aplicativo para aplicar atualizacoes e correcoes"))
        btn_restart = self._btn("🔄 Reiniciar Agora", self._restart_app, RED)
        btn_restart.setToolTip("Reinicia o DefendR para aplicar atualizacoes e correcoes")
        restart_l.addWidget(btn_restart)
        gen_l.addWidget(restart_frame)

        # Uninstall button
        uninst_frame = QtWidgets.QFrame()
        uninst_frame.setStyleSheet(f"background: rgba(255,69,58,0.04); border: 1px solid {RED}; border-radius: 14px;")
        uninst_l = QtWidgets.QVBoxLayout(uninst_frame)
        uninst_l.addWidget(QtWidgets.QLabel("Desinstalar DefendR"))
        uninst_l.addWidget(QtWidgets.QLabel("Remove todos os arquivos, configuracoes e atalhos do sistema"))
        btn_uninst = self._btn("🗑  Desinstalar", self._uninstall_defendr, RED)
        btn_uninst.setToolTip("Remove permanentemente o DefendR e todos os seus dados")
        uninst_l.addWidget(btn_uninst)
        gen_l.addWidget(uninst_frame)
        gen_l.addStretch()
        gen_w.setLayout(gen_l)
        gen_scroll.setWidget(gen_w)
        tabs.addTab(gen_scroll, "General")

        # Whitelist
        wl_w = QtWidgets.QWidget()
        wl_l = QtWidgets.QVBoxLayout(wl_w)
        wl_title = QtWidgets.QLabel("Pentest Tool Whitelist")
        wl_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {ACCENT_LIGHT}; background: transparent;")
        wl_l.addWidget(wl_title)
        self.wl_edit = QtWidgets.QPlainTextEdit()
        self.wl_edit.setPlainText("\n".join(sorted(self.engine.whitelist)))
        self.wl_edit.setStyleSheet(f"QPlainTextEdit {{ background: {DARK_BG}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 4px; font-size: 11px; padding: 6px; }}")
        wl_l.addWidget(self.wl_edit)
        wl_l.addWidget(self._btn("💾 Save Whitelist", self._save_wl))
        tabs.addTab(wl_w, "Whitelist")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(w)

    # ===================== CLOUD SERVER =====================
    def _auto_start_cloud_server(self):
        try:
            from defendr.reputation import ReputationServer, REPUTATION_PORT, DEFAULT_SERVER_IP, ReputationClient
            self._rep_server = ReputationServer()
            self._rep_server.start()
            if self._rep_server.actual_port:
                self.engine.rep_client = ReputationClient(server_url=f"http://{DEFAULT_SERVER_IP}:{self._rep_server.actual_port}")
            if hasattr(self, 'cloud_server_status'):
                self.cloud_server_status.setText(f"Servidor: Rodando na porta {self._rep_server.actual_port or REPUTATION_PORT}")
        except Exception as e:
            if hasattr(self, 'cloud_server_status'):
                self.cloud_server_status.setText(f"Servidor: Erro ao iniciar - {str(e)[:50]}")

    # ===================== MONITORS =====================
    def _start_monitors(self):
        self.monitor_timer = QtCore.QTimer()
        self.monitor_timer.timeout.connect(self._update_stats)
        self.monitor_timer.start(4000)
        self.proc_timer = QtCore.QTimer()
        self.proc_timer.timeout.connect(self._refresh_procs)
        self.proc_timer.start(5000)
        self.fw_detect_timer = QtCore.QTimer()
        self.fw_detect_timer.timeout.connect(self._fw_detect_loop)
        self.fw_detect_timer.start(3000)
        self._notify_queue = []
        self._notify_timer = QtCore.QTimer()
        self._notify_timer.timeout.connect(self._process_notify)
        self._notify_timer.setInterval(2500)
        self.netmon.start()
        self._update_dns()
        self._refresh_procs()
        self.rt_protector.start()
        self.rt_toggle.setText("⏹ Stop Real-Time Protection")
        self.rt_status.setText(_("Status: Active"))
        self.usb_scanner.start()
        if self.protection_level in ("medium", "hard"):
            self.ransomware.start()
            self.rw_toggle.setText("⏹ Stop Ransomware Detection")
            self.rw_status.setText(_("Status: Active"))
            self.webcam_protector.start()
        if self.protection_level == "hard":
            self.selfprotect.start()
            self.adv_protection.start()
        self._update_protect_label()

        # Restore autostart from config
        if self.engine.config_data.get("autostart"):
            self._setup_autostart()
            self.autostart_enabled = True
        if self.engine.config_data.get("enterprise_mode"):
            self._setup_autostart()
            self.autostart_enabled = True
            QtCore.QTimer.singleShot(1000, self._activate_enterprise)

    def _update_stats(self):
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.3)
            mem = psutil.virtual_memory().percent
            procs = len(psutil.pids())
            self.stat_cards["cpu"].set_value(f"{cpu:.0f}%")
            self.stat_cards["mem"].set_value(f"{mem:.0f}%")
            self.stat_cards["procs"].set_value(str(procs))
            try:
                net_conns = psutil.net_connections(kind="tcp")
                nconns = len([c for c in net_conns if c.status == "ESTABLISHED"])
                self.conn_label.setText(str(nconns))
            except (psutil.AccessDenied, PermissionError): pass
            except Exception: pass
            threats = self.stat_cards["threats"].value_lbl.text()
            self.tray.setToolTip(f"DefendR - Proteção Ativa\nCPU: {cpu:.0f}% | RAM: {mem:.0f}%\nAmeaças: {threats}")
            if hasattr(self.engine, "rep_client"):
                import json
                from urllib.request import Request, urlopen
                req = Request(f"http://127.0.0.1:48124/stats")
                with urlopen(req, timeout=3) as resp:
                    sdata = json.loads(resp.read())
                self.stat_cards["users"].set_value(str(sdata.get("active_clients", 0)))
            ia = self.engine.joguin.get_stats()
            self.ia_level_lbl.setText(f"Level {ia['level']}")
            self.ia_xp_bar.setMaximum(100)
            self.ia_xp_bar.setValue(int(ia['pct_to_next']))
            self.ia_xp_lbl.setText(f"{ia['xp']}/{ia['xp'] + ia['xp_for_next']} XP")
            self.ia_acc_lbl.setText(f"🎯 {ia['accuracy']}% accuracy")
            self.ia_hash_lbl.setText(f"📚 {ia['known_hashes']} hashes")
            self.ia_pat_lbl.setText(f"🧩 {ia['patterns']} patterns")
            if ia['total'] > 0:
                self.ia_status_lbl.setText(f"🤖 Aprendi com {ia['total']} arquivos — {ia['correct']} acertos")
        except Exception: pass

    def _update_dns(self):
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf") as f:
                    servers = [l.split()[1] for l in f if l.startswith("nameserver")]
                self.dns_label.setText("\n".join(servers) if servers else "None configured")
        except Exception: pass

    # ===================== SCANNER =====================
    def _scan_file_path(self, path):
        if os.path.isfile(path):
            self._do_scan(path)

    def _scan_file(self):
        import pwd
        uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or "1000")
        home = pwd.getpwuid(uid).pw_dir
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to scan", home)
        if path: self._do_scan(path)
    def _scan_dir(self):
        import pwd
        uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or "1000")
        home = pwd.getpwuid(uid).pw_dir
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to scan", home)
        if path: self._do_scan(path)
    def _scan_usb_manual(self):
        for base in ["/media", "/run/media", "/mnt"]:
            if not os.path.isdir(base):
                continue
            for root, dirs, _ in os.walk(base, topdown=True):
                if root == base:
                    continue
                if os.path.ismount(root):
                    self._do_scan(root)
                    return
        self.scan_status.setText("No USB mounts found")

    def _scan_desktop(self):
        import pwd
        try:
            uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or os.getuid())
            home = pwd.getpwuid(uid).pw_dir
            for nome in ["Desktop", "Área de trabalho", "桌面", "Escritorio"]:
                d = os.path.join(home, nome)
                if os.path.isdir(d):
                    self.scan_status.setText(f"Escaneando: {d}")
                    self._scan_desktop_path(d)
                    return
            self.scan_status.setText("Desktop not found")
        except Exception as e:
            self.scan_status.setText(f"Erro: {str(e)[:50]}")

    def _scan_desktop_path(self, path):
        self.scan_tree.clear()
        self.scan_progress.setValue(0)
        self.scan_progress.show()
        mode = getattr(self, '_scan_worker_mode', 'rapido')
        self.scan_status.setText(f"Scanning ({mode}): {path}")

        def scan_task():
            try:
                results = self.engine.scan_rapido(path)
                self.desktop_scan_done.emit(results)
            except Exception as e:
                self.desktop_scan_error.emit(str(e))

        threading.Thread(target=scan_task, daemon=True).start()

    def _on_desktop_scan_done(self, results):
        self.scan_progress.hide()
        for r in results.get("malicious", []):
            self._add_scan_item("MALICIOUS", r["path"], r.get("reason", ""), RED)
        for r in results.get("suspicious", []):
            self._add_scan_item("SUSPICIOUS", r["path"], r.get("reason", ""), YELLOW)
        for r in results.get("pentest", []):
            self._add_scan_item("PENTEST", r["path"], r.get("reason", ""), CYAN)
        malicious = len(results["malicious"])
        suspicious = len(results["suspicious"])
        safe = results["safe"]
        self.scan_status.setText(f"Done. Malicious: {malicious}, Suspicious: {suspicious}, Pentest: {len(results['pentest'])}, Safe: {safe}")
        total = safe + malicious + suspicious + len(results["pentest"])
        cur = int(self.stat_cards["scanned"].value_lbl.text() or "0")
        self.stat_cards["scanned"].set_value(str(cur+total))
        if not any([results["malicious"], results["suspicious"], results["pentest"]]):
            self._add_scan_item("SAFE", _("No threats found"), "All files are clean", GREEN)

    def _on_desktop_scan_error(self, msg):
        self.scan_progress.hide()
        self.scan_status.setText(f"Erro: {msg[:80]}")

    def _do_scan(self, path):
        self.scan_tree.clear()
        self.scan_progress.setValue(0)
        self.scan_progress.show()
        mode = getattr(self, '_scan_worker_mode', 'rapido')
        self.scan_status.setText(f"Scanning ({mode}): {path}")
        thread = ScanWorker(self.engine, path, mode=mode)
        thread.finished.connect(lambda results: self._scan_done(results))
        thread.result_found.connect(self._scan_add_result_item)
        thread.start()
        self._scan_thread = thread

    def _scan_add_result_item(self, r):
        risk = r.get("risk", "unknown")
        if risk == "malicious":
            self._add_scan_item("MALICIOUS", r["path"], r.get("reason", ""), RED)
        elif risk == "suspicious":
            self._add_scan_item("SUSPICIOUS", r["path"], r.get("reason", ""), YELLOW)
        elif risk == "pentest":
            self._add_scan_item("PENTEST", r["path"], r.get("reason", ""), CYAN)

    def _scan_done(self, results):
        self.scan_progress.hide()
        self.scan_status.setText(f"Done. Malicious: {len(results['malicious'])}, Suspicious: {len(results['suspicious'])}, Pentest: {len(results['pentest'])}, Safe: {results['safe']}")
        total = results["safe"] + len(results["malicious"])+len(results["suspicious"])+len(results["pentest"])
        cur = int(self.stat_cards["scanned"].value_lbl.text() or "0")
        self.stat_cards["scanned"].set_value(str(cur+total))
        if not any([results["malicious"],results["suspicious"],results["pentest"]]):
            self._add_scan_item("SAFE", _("No threats found"), "All files are clean", GREEN)
        if results["malicious"]:
            self._show_msg(f"Scan completo: {len(results['malicious'])} malware encontrado!", sound=True)

    def _add_scan_item(self, risk, path, reason, color):
        item = QtWidgets.QTreeWidgetItem([risk, textwrap.shorten(path, 80), reason])
        for i in range(3): item.setForeground(i, QtGui.QColor(color))
        item.setToolTip(1, path)
        self.scan_tree.addTopLevelItem(item)

    def _on_scan_level_change(self, idx):
        levels = ["light", "medium", "heavy"]
        self.engine.scan_level = levels[idx]
        self._scan_worker_mode = levels[idx]

    def _stop_scan(self):
        self.engine.scanning = False
        self.scan_progress.hide()
        self.scan_status.setText(_("Scan stopped"))
    def _clear_scan(self):
        self.scan_tree.clear()
        self.scan_status.setText(_("Ready"))

    def _scan_tree_context_menu(self, pos):
        item = self.scan_tree.itemAt(pos)
        if not item:
            return
        path = item.toolTip(1)
        if not path or not os.path.isfile(path):
            return
        menu = QtWidgets.QMenu()
        menu.addAction("📂 Abrir local do arquivo").triggered.connect(
            lambda: os.system(f'xdg-open "{os.path.dirname(path)}"'))
        menu.addSeparator()
        menu.addAction("✅ Validar (ignorar sempre)").triggered.connect(
            lambda: self._scan_validate_path(path))
        menu.addAction("📦 Mover para Quarentena").triggered.connect(
            lambda: self._scan_quarantine_path(path))
        menu.addAction("🗑 Excluir permanentemente").triggered.connect(
            lambda: self._scan_delete_path(path))
        menu.addSeparator()
        menu.addAction("🧪 Executar em Sandbox").triggered.connect(
            lambda: self._run_sandbox_file(path))
        menu.exec_(self.scan_tree.viewport().mapToGlobal(pos))

    def _run_sandbox_file(self, path):
        ok, msg = self.adv_protection.run_sandboxed(path)
        self._show_msg(msg)
        if ok and self.adv_protection.sandbox_available():
            self._show_intrusion_popup("LOW", f"Sandbox: {msg}", "Protecao Avancada", "127.0.0.1")

    def _scan_open_location(self):
        item = self.scan_tree.currentItem()
        if not item:
            self._show_msg("Selecione um arquivo na lista")
            return
        path = item.toolTip(1)
        if not path or not os.path.isfile(path):
            self._show_msg("Arquivo nao encontrado")
            return
        os.system(f'xdg-open "{os.path.dirname(path)}"')

    def _scan_validate_selected(self):
        items = self.scan_tree.selectedItems()
        if not items:
            self._show_msg("Selecione um arquivo na lista")
            return
        for item in items:
            path = item.toolTip(1)
            if path and os.path.isfile(path):
                self._scan_validate_path(path)

    def _scan_validate_path(self, path):
        self.engine.whitelist.add(path.lower())
        self.engine.save_config()
        self._show_msg(f"✅ Validado: {os.path.basename(path)}")

    def _run_selected_in_sandbox(self):
        item = self.scan_tree.currentItem()
        if not item:
            self._show_msg("Selecione um arquivo na lista")
            return
        path = item.toolTip(1)
        if not path or not os.path.isfile(path):
            self._show_msg("Arquivo nao encontrado")
            return
        self._run_sandbox_file(path)

    def _scan_quarantine_selected(self):
        items = self.scan_tree.selectedItems()
        if not items:
            return
        paths = []
        for item in items:
            p = item.toolTip(1)
            if p and os.path.isfile(p):
                paths.append(p)
        if not paths:
            return
        if len(paths) > 1:
            reply = QtWidgets.QMessageBox.question(self, "Confirmar",
                f"Mover {len(paths)} arquivo(s) para quarentena?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if reply != QtWidgets.QMessageBox.Yes:
                return
        for p in paths:
            ok, msg = self.quarantine.quarantine(p)
            if ok:
                self._remove_scan_tree_item(p)
        if len(paths) == 1:
            self._show_msg(f"📦 Quarentenado: {os.path.basename(paths[0])}")

    def _scan_quarantine_path(self, path):
        ok, msg = self.quarantine.quarantine(path)
        if ok:
            self._show_msg(f"📦 Quarentenado: {os.path.basename(path)}")
            self._remove_scan_tree_item(path)
        else:
            self._show_msg(f"Erro: {msg}")

    def _scan_delete_selected(self):
        items = self.scan_tree.selectedItems()
        if not items:
            return
        paths = []
        for item in items:
            p = item.toolTip(1)
            if p and os.path.isfile(p):
                paths.append(p)
        if not paths:
            return
        label = f"Excluir permanentemente '{os.path.basename(paths[0])}'?" if len(paths) == 1 else f"Excluir permanentemente {len(paths)} arquivo(s)?"
        reply = QtWidgets.QMessageBox.question(self, "Confirmar", label,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply != QtWidgets.QMessageBox.Yes:
            return
        deleted = 0
        for p in paths:
            try:
                os.remove(p)
                self._remove_scan_tree_item(p)
                deleted += 1
            except Exception as e:
                self._show_msg(f"Erro ao excluir {os.path.basename(p)}: {e}")
        if len(paths) == 1 and deleted > 0:
            self._show_msg(f"🗑 Excluído: {os.path.basename(paths[0])}")

    def _scan_delete_path(self, path):
        reply = QtWidgets.QMessageBox.question(self, "Confirmar",
            f"Excluir permanentemente '{os.path.basename(path)}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            try:
                os.remove(path)
                self._show_msg(f"🗑 Excluído: {os.path.basename(path)}")
                self._remove_scan_tree_item(path)
            except Exception as e:
                self._show_msg(f"Erro ao excluir: {e}")

    def _remove_scan_tree_item(self, path):
        for i in range(self.scan_tree.topLevelItemCount()):
            item = self.scan_tree.topLevelItem(i)
            if item.toolTip(1) == path:
                self.scan_tree.takeTopLevelItem(i)
                break

    # ===================== NETWORK =====================
    def _toggle_net(self):
        if self.netmon.monitoring:
            self.netmon.stop()
            self.net_status.setText("●  Monitoring: OFF")
            self.net_status.setStyleSheet(f"font-size: 13px; color: {TEXT_DIM}; background: transparent;")
            self.net_toggle.setText("▶ Start")
        else:
            self.netmon.start()
            self.net_status.setText("●  Monitoring: ON")
            self.net_status.setStyleSheet(f"font-size: 13px; color: {GREEN}; background: transparent;")
            self.net_toggle.setText("⏹ Stop")

    def _alert_context_menu(self, pos):
        item = self.alert_list.itemAt(pos)
        if not item:
            return
        path = item.data(QtCore.Qt.UserRole) or ""
        menu = QtWidgets.QMenu()
        menu.addAction("📋 Copiar texto").triggered.connect(
            lambda: QtWidgets.QApplication.clipboard().setText(item.text()))
        if path and os.path.isfile(path):
            menu.addSeparator()
            menu.addAction("📂 Abrir local do arquivo").triggered.connect(
                lambda: os.system(f'xdg-open "{os.path.dirname(path)}"'))
            menu.addSeparator()
            menu.addAction("📦 Quarentena").triggered.connect(
                lambda: self._scan_quarantine_path(path))
            menu.addAction("🗑 Excluir").triggered.connect(
                lambda: self._scan_delete_path(path))
            menu.addSeparator()
            menu.addAction("✅ Validar (ignorar sempre)").triggered.connect(
                lambda: self._scan_validate_path(path))
        menu.exec_(self.alert_list.viewport().mapToGlobal(pos))

    def _clear_alerts(self):
        self.alert_list.clear()

    def _on_net_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.net_alerts.insertItem(0, item)
        if self.net_alerts.count() > 200: self.net_alerts.takeItem(self.net_alerts.count()-1)
        ditem = QtWidgets.QListWidgetItem(f"[NET][{level}] {msg}")
        ditem.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, ditem)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)

    def _on_net_intrusion(self, severity, msg):
        parts = msg.split("|")
        message = parts[0] if len(parts) > 0 else msg
        attack_type = parts[1] if len(parts) > 1 else "Ataque de Rede"
        source_ip = parts[2] if len(parts) > 2 else ""
        self._show_intrusion_popup(severity, message, attack_type, source_ip)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[{attack_type}] {message}"))
        if self.alert_list.count() > 100:
            self.alert_list.takeItem(self.alert_list.count()-1)
        self._show_msg(f"[{attack_type}] {message}", sound=True)

    def _on_net_data(self, data):
        if data.get("type") == "arp":
            self.arp_table.setRowCount(len(data["data"]))
            for i,(ip,(hw,iface)) in enumerate(data["data"].items()):
                self.arp_table.setItem(i,0,QtWidgets.QTableWidgetItem(ip))
                self.arp_table.setItem(i,1,QtWidgets.QTableWidgetItem(hw))
                self.arp_table.setItem(i,2,QtWidgets.QTableWidgetItem(iface))

    # ===================== REALTIME =====================
    def _toggle_rt(self):
        if self.rt_protector.active:
            self.rt_protector.stop()
            self.rt_toggle.setText("▶ Start Real-Time Protection")
            self.rt_status.setText(_("Status: Stopped"))
        else:
            self.rt_protector.start()
            self.rt_toggle.setText("⏹ Stop Real-Time Protection")
            self.rt_status.setText(_("Status: Active"))

    def _on_rt_alert(self, risk, path, reason):
        self._show_msg(f"[RT] {reason}", sound=True)
        item = QtWidgets.QListWidgetItem(f"[{risk.upper()}] {path}: {reason}")
        item.setData(QtCore.Qt.UserRole, path)
        color = RED if risk == "malicious" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        if self.rt_alerts.count() > 100: self.rt_alerts.takeItem(self.rt_alerts.count()-1)
        ditem = QtWidgets.QListWidgetItem(f"[RT][{risk.upper()}] {reason}")
        ditem.setData(QtCore.Qt.UserRole, path)
        ditem.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, ditem)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
        if risk == "malicious":
            try:
                cur = int(self.stat_cards["threats"].value_lbl.text() or "0")
                self.stat_cards["threats"].set_value(str(cur + 1))
            except ValueError:
                self.stat_cards["threats"].set_value("1")
        xp_bonus = {"malicious": 20, "suspicious": 10}.get(risk, 0)
        if xp_bonus and hasattr(self.engine, 'joguin'):
            old_lv = self.engine.joguin.level
            self.engine.joguin.xp += xp_bonus
            new_lv = self.engine.joguin.level
            if new_lv > old_lv:
                self.engine.joguin.xp += new_lv * 50
            self.engine.joguin._save()

    # ===================== RANSOMEWARE =====================
    def _toggle_rw(self):
        if self.ransomware.monitoring:
            self.ransomware.stop()
            self.rw_toggle.setText("▶ Start Ransomware Detection")
            self.rw_status.setText(_("Status: Stopped"))
        else:
            self.ransomware.start()
            self.rw_toggle.setText("⏹ Stop Ransomware Detection")
            self.rw_status.setText(_("Status: Active"))

    def _on_ransomware_alert(self, level, msg):
        self._show_msg(f"[RANSOM] {msg}", sound=True)
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[RANSOM]{msg}"))
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)

    # ===================== WEB BLOCKER =====================
    def _web_block(self):
        dom = self.wb_input.text().strip()
        if not dom: return
        ok, msg = self.web_blocker.block_domain(dom)
        self._show_msg(msg)
        if ok: self._refresh_web_block()
    def _web_unblock(self):
        dom = self.wb_input.text().strip()
        if not dom: return
        ok, msg = self.web_blocker.unblock_domain(dom)
        self._show_msg(msg)
        if ok: self._refresh_web_block()
    def _refresh_web_block(self):
        self.wb_list.clear()
        for d in self.web_blocker.get_blocked():
            self.wb_list.addItem(d)

    # ===================== ANTI-PHISHING =====================
    def _check_phishing(self):
        url = self.ap_input.text().strip()
        if not url: return
        result = self.anti_phish.check_url(url)
        risk_color = RED if result["risk"]=="high" else (YELLOW if result["risk"]=="medium" else GREEN)
        txt = f"Domain: {result['domain']}\nRisk: {result['risk'].upper()} (Score: {result['score']})\n"
        if result["reasons"]: txt += f"Reasons: {', '.join(result['reasons'])}\n"
        if result["risk"] == "high":
            txt += "⚠ This URL appears to be a phishing site!\n"
            self.anti_phish.add_phishing(result["domain"])
        self.ap_result.setText(txt)
        self.ap_result.setStyleSheet(f"font-size: 11px; color: {risk_color}; background: transparent; padding: 4px; border: 1px solid {BORDER}; border-radius: 4px;")

    # ===================== FIREWALL =====================
    def _fw_detect_loop(self):
        self.firewall.detect_port_scan()
        self.firewall.detect_brute_force()

    def _fw_enable(self):
        ok, msg = self.firewall.enable()
        self.fw_status.setText(f"Firewall: {'Enabled' if ok else 'Error'}")
        self._show_msg(msg)
    def _fw_disable(self):
        ok, msg = self.firewall.disable()
        self.fw_status.setText("Firewall: Disabled")
        self._show_msg(msg)
    def _fw_flush(self):
        ok, msg = self.firewall.flush()
        self.fw_status.setText("Firewall: Disabled (flushed)")
        self._show_msg(msg)
    def _fw_block_port(self):
        port = self.port_input.text().strip()
        if port.isdigit():
            ok, msg = self.firewall.block_port(int(port))
            self._show_msg(msg)
    def _fw_allow_port(self):
        port = self.port_input.text().strip()
        if port.isdigit():
            ok, msg = self.firewall.allow_port(int(port))
            self._show_msg(msg)
    def _fw_refresh(self):
        self.fw_rules.clear()
        rules = self.firewall.list_rules()
        for r in rules: self.fw_rules.addItem(r)

    # ===================== PROCESSES =====================
    def _refresh_procs(self):
        self.proc_table.setRowCount(0)
        QtCore.QTimer.singleShot(50, self._do_refresh_procs)
    def _do_refresh_procs(self):
        procs = self.engine.get_processes()
        self.proc_table.setRowCount(len(procs))
        for i, p in enumerate(procs):
            self.proc_table.setItem(i,0,QtWidgets.QTableWidgetItem(str(p["pid"])))
            self.proc_table.setItem(i,1,QtWidgets.QTableWidgetItem(p["name"][:30]))
            self.proc_table.setItem(i,2,QtWidgets.QTableWidgetItem(f"{p['cpu']:.1f}"))
            self.proc_table.setItem(i,3,QtWidgets.QTableWidgetItem(f"{p['mem']:.2f}"))
            self.proc_table.setItem(i,4,QtWidgets.QTableWidgetItem(str(p["conns"])))
            status = "OK"; color = TEXT
            if p["suspicious"]: status = "SUSPICIOUS"; color = RED
            elif p["pentest"]: status = "ALLOWED"; color = CYAN
            item = QtWidgets.QTableWidgetItem(status)
            item.setForeground(QtGui.QColor(color))
            self.proc_table.setItem(i,5,item)

    # ===================== QUARANTINE =====================
    def _refresh_quarantine(self):
        self.q_table.setRowCount(0)
        items = self.quarantine.list_quarantined()
        self.q_table.setRowCount(len(items))
        for i, (qid, info) in enumerate(items):
            self.q_table.setItem(i,0,QtWidgets.QTableWidgetItem(qid[:8]))
            self.q_table.setItem(i,1,QtWidgets.QTableWidgetItem(textwrap.shorten(info.get("original",""),60)))
            self.q_table.setItem(i,2,QtWidgets.QTableWidgetItem(info.get("date","")[:19]))
            self.q_table.setItem(i,3,QtWidgets.QTableWidgetItem(f"{info.get('size',0)}B"))
            btn_w = QtWidgets.QWidget()
            btn_l = QtWidgets.QHBoxLayout(btn_w); btn_l.setContentsMargins(2,2,2,2)
            vt_btn = QtWidgets.QPushButton("🔍 VT")
            vt_btn.setStyleSheet(f"QPushButton {{ background: {ACCENT}; color: white; border: none; border-radius: 8px; padding: 5px 10px; font-size: 11px; }}")
            vt_btn.setToolTip("Check on VirusTotal")
            vt_btn.clicked.connect(lambda _, q=qid: self._quarantine_vt(q))
            btn_l.addWidget(vt_btn)
            r_btn = QtWidgets.QPushButton("Restore")
            r_btn.setStyleSheet(f"QPushButton {{ background: {GREEN}; color: white; border: none; border-radius: 8px; padding: 5px 14px; font-size: 11px; }}")
            r_btn.clicked.connect(lambda _, q=qid: self._quarantine_restore(q))
            btn_l.addWidget(r_btn)
            d_btn = QtWidgets.QPushButton("Delete")
            d_btn.setStyleSheet(f"QPushButton {{ background: {RED}; color: white; border: none; border-radius: 8px; padding: 5px 14px; font-size: 11px; }}")
            d_btn.clicked.connect(lambda _, q=qid: self._quarantine_delete(q))
            btn_l.addWidget(d_btn)
            self.q_table.setCellWidget(i,4,btn_w)

    def _quarantine_vt(self, qid):
        info = self.quarantine.metadata.get(qid)
        if not info or not os.path.isfile(info.get("quarantined", "")):
            self._show_msg("Arquivo nao encontrado na quarentena")
            return
        import hashlib, urllib.request, json as j
        try:
            with open(info["quarantined"], "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            self._show_msg("Erro ao ler arquivo")
            return
        api_key = os.environ.get("VT_API_KEY", "")
        if api_key:
            try:
                req = urllib.request.Request(
                    f"https://www.virustotal.com/api/v3/files/{h}",
                    headers={"x-apikey": api_key},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = j.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                self._show_msg(f"VirusTotal: {mal} malicious, {sus} suspicious ({stats.get('undetected',0)} limpos)")
            except Exception as e:
                self._show_msg(f"VT API error: {e}")
        else:
            import webbrowser
            webbrowser.open(f"https://www.virustotal.com/gui/file/{h}")
            self._show_msg(f"Abrindo VirusTotal para hash {h[:16]}...")

    def _quarantine_restore(self, qid):
        ok, msg = self.quarantine.restore(qid)
        self._show_msg(msg)
        self._refresh_quarantine()
    def _quarantine_delete(self, qid):
        ok, msg = self.quarantine.delete_permanently(qid)
        self._show_msg(msg)
        self._refresh_quarantine()
    def _quarantine_delete_all(self):
        for qid in list(self.quarantine.metadata.keys()):
            self.quarantine.delete_permanently(qid)
        self._refresh_quarantine()

    # ===================== TOOLS =====================
    def _sandbox_run(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to run in sandbox")
        if path:
            ok, msg = self.sandbox.run_in_sandbox(path)
            self._show_msg(msg)

    def _rootkit_scan(self):
        self.rk_results.setPlainText("Running rootkit scan...")
        self._rk_worker = TaskWorker(self.rootkit.full_scan)
        self._rk_worker.finished.connect(self._do_rootkit)
        self._rk_worker.error.connect(lambda e: self.rk_results.setPlainText(f"Error: {e}"))
        self._rk_worker.start()
    def _do_rootkit(self, results):
        if not results:
            self.rk_results.setPlainText("✅ No rootkits detected.\nSystem appears clean.")
            return
        txt = "⚠ Rootkit Scan Results:\n" + "="*40 + "\n"
        for k, v in results.items():
            txt += f"\n{k}: {v}\n"
        self.rk_results.setPlainText(txt)

    def _show_intrusion_popup(self, severity, msg, attack_type="", source_ip=""):
        title = "🚨 Ameaca Detectada!" if severity == "HIGH" else "⚠ Alerta de Seguranca"
        IntrusionPopup(title, msg, severity, source_ip, attack_type, self)

    def _on_rootkit_alert(self, level, msg):
        self._show_msg(f"[ROOTKIT] {msg}", sound=True)
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        item.setForeground(QtGui.QColor(RED if level == "HIGH" else YELLOW))
        self.alert_list.insertItem(0, item)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)

    # Password Manager
    def _pwd_unlock(self):
        if self.pwd_mgr.unlocked:
            self._refresh_pwd()
            return
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Master Password", "Enter master password:", QtWidgets.QLineEdit.Password)
        if ok and pwd:
            if self.pwd_mgr.unlock(pwd):
                self.pwd_unlock_btn.setText("🔓 Unlocked")
                self._refresh_pwd()
            else:
                self._show_msg("Wrong password")
    def _pwd_lock(self):
        self.pwd_mgr.lock()
        self.pwd_unlock_btn.setText("🔓 Unlock Vault")
        self.pwd_list.clear()
    def _pwd_add(self):
        if not self.pwd_mgr.unlocked:
            self._show_msg("Unlock vault first"); return
        site = self.pwd_site.text().strip()
        user = self.pwd_user.text().strip()
        pwd = self.pwd_pass.text().strip()
        if site and user and pwd:
            self.pwd_mgr.add_entry(site, user, pwd)
            self._show_msg("Entry saved")
            self.pwd_site.clear(); self.pwd_user.clear(); self.pwd_pass.clear()
            self._refresh_pwd()
    def _refresh_pwd(self):
        self.pwd_list.clear()
        if not self.pwd_mgr.unlocked:
            self.pwd_list.addItem("🔒 Vault locked - click Unlock")
            return
        for e in self.pwd_mgr.get_entries():
            item = QtWidgets.QListWidgetItem(f"{e['site']:20s} | {e['username']:20s} | {e.get('created','')[:16]}")
            item.setData(QtCore.Qt.UserRole, e["id"])
            self.pwd_list.addItem(item)

    # Scheduler
    def _sched_add(self):
        name = self.sched_name.text().strip() or "Scheduled Scan"
        path = self.sched_path.text().strip() or os.path.expanduser("~")
        hours = self.sched_hours.value()
        self.scheduler.add_task(name, path, hours)
        self._show_msg(f"Task '{name}' added (every {hours}h)")
        self._sched_refresh()
    def _sched_refresh(self):
        self.sched_list.clear()
        for t in self.scheduler.tasks:
            last = t.get("last_run","never")[:19] if t.get("last_run") else "never"
            status = "✅" if t.get("enabled") else "⏸"
            self.sched_list.addItem(f"{status} {t.get('name','?')} | Every {t.get('interval','?')}h | Path: {t.get('path','?')[:40]} | Last: {last}")
    def _on_scheduled_scan(self, task_id):
        for t in self.scheduler.tasks:
            if t["id"] == task_id:
                self._do_scan(t["path"])
                self._show_msg(f"Scheduled scan started: {t['name']}")
                break

    # Signature Updates
    def _manual_update(self):
        self.update_status.setText("Checking for updates...")
        self._update_worker = TaskWorker(self.sig_updater.check_update)
        self._update_worker.finished.connect(self._do_update)
        self._update_worker.error.connect(lambda e: self.update_status.setText(f"Error: {e}"))
        self._update_worker.start()
    def _do_update(self, n):
        self.sig_count.setText(f"Signatures: {self.sig_updater.get_signature_count()}")
        self.update_status.setText(f"Updated {n} signatures" if n else "No updates available")
    def _on_update_status(self, msg):
        self.update_status.setText(msg)

    # Game Mode
    def _on_game_mode(self, active):
        self.tray_game.setText(f"🎮  Game Mode: {'ON' if active else 'OFF'}")
        if active:
            self.tray.showMessage("DefendR", "🎮 Game Mode activated - notifications suppressed",
                                  QtWidgets.QSystemTrayIcon.Information, 2000)

    # USB Scanner
    def _on_usb_scan(self, mount):
        self.scan_status.setText(f"USB mounted: {mount} - scanning...")
    def _on_usb_alert(self, level, msg):
        self._show_msg(f"[USB] {msg}", sound=True)
        item = QtWidgets.QListWidgetItem(f"[USB][{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, item)
        if level in ("HIGH", "MEDIUM"):
            self._show_intrusion_popup(level, msg, "USB Threat", "")
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)

    # VPN
    def _vpn_add(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select OpenVPN config", filter="Config files (*.ovpn *.conf)")
        if path:
            ok, msg = self.vpn.add_config(path)
            self._show_msg(msg)
            self._refresh_vpn_list()
    def _vpn_connect(self):
        items = self.vpn_list.selectedItems()
        if not items: self._show_msg("Select a config first"); return
        config = items[0].data(QtCore.Qt.UserRole)
        if config:
            ok, msg = self.vpn.connect(config)
            self.vpn_status.setText(f"VPN: {msg}")
            self._show_msg(msg)
    def _vpn_disconnect(self):
        ok, msg = self.vpn.disconnect()
        self.vpn_status.setText("VPN: Disconnected")
        self._show_msg(msg)
    def _refresh_vpn_list(self):
        self.vpn_list.clear()
        for c in self.vpn.get_configs():
            item = QtWidgets.QListWidgetItem(os.path.basename(c))
            item.setData(QtCore.Qt.UserRole, c)
            self.vpn_list.addItem(item)

    # Network Inspector
    def _arp_scan(self):
        self.inspector_results.setPlainText("Running ARP scan (requires root + scapy)...")
        QtCore.QTimer.singleShot(100, lambda: self.net_inspector.arp_scan())
    def _router_info(self):
        self.inspector_results.setPlainText("Gathering router info...")
        self._router_worker = TaskWorker(self.net_inspector.router_info)
        self._router_worker.finished.connect(self._do_router_info)
        self._router_worker.error.connect(lambda e: self.inspector_results.setPlainText(f"Error: {e}"))
        self._router_worker.start()
    def _do_router_info(self, info):
        txt = "📡 Router Info:\n" + "="*40 + "\n"
        for k, v in info.items():
            if isinstance(v, list):
                txt += f"{k}:\n"
                for item in v: txt += f"  - {item}\n"
            else:
                txt += f"{k}: {v}\n"
        self.inspector_results.setPlainText(txt)
    def _on_inspect_result(self, rtype, data):
        if rtype == "arp_scan":
            if isinstance(data, list):
                txt = f"🔍 ARP Scan Results ({len(data)} devices):\n" + "="*40 + "\n"
                for d in data: txt += f"{d['ip']:15s} {d['mac']}\n"
                self.inspector_results.setPlainText(txt)
            else:
                self.inspector_results.setPlainText(f"Error: {data}")
        elif rtype == "error":
            self.inspector_results.setPlainText(f"Error: {data}")

    # ===================== SETTINGS =====================
    def _toggle_protection(self, enabled):
        self.engine.protection_active = enabled
        if enabled:
            self.protect_indicator.setText("●  Protected")
            self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {GREEN}; background: transparent;")
        else:
            self.protect_indicator.setText("●  Disabled")
            self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {RED}; background: transparent;")

    def _save_wl(self):
        lines = self.wl_edit.toPlainText().strip().split("\n")
        self.engine.whitelist = set(l.strip() for l in lines if l.strip())
        self.engine.save_config()
        self._show_msg(f"Whitelist saved ({len(self.engine.whitelist)} entries)")

    # ===================== AUTOSTART =====================
    def _setup_autostart(self):
        os.makedirs(os.path.dirname(self._autostart_path), exist_ok=True)
        desktop = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=DefendR\n"
            "Comment=DefendR Antivirus & Security Suite\n"
            "Exec=/usr/local/bin/defendr-sudo.sh launch\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-enabled=true\n"
            "Categories=Security;\n"
        )
        with open(self._autostart_path, "w") as f:
            f.write(desktop)

    def _remove_autostart(self):
        if os.path.exists(self._autostart_path):
            os.remove(self._autostart_path)

    def _toggle_autostart(self, enabled):
        self.autostart_enabled = enabled
        if enabled:
            self._setup_autostart()
        else:
            self._remove_autostart()
        self.engine.config_data["autostart"] = enabled
        self.engine.save_config()

    # ===================== ENTERPRISE MODE =====================
    def _toggle_enterprise_mode(self, enabled):
        if enabled:
            self._activate_enterprise()
        else:
            if not self._verify_enterprise_password():
                self.enterprise_cb.setChecked(True)
                return
            self._deactivate_enterprise()

    def _activate_enterprise(self):
        try:
            if not self._ensure_enterprise_password():
                self.enterprise_cb.setChecked(False)
                return
            self.enterprise_mode = True
            self.engine.scan_level = "heavy"
            self.engine.protection_active = True

            # Enable ALL monitors
            self.netmon.start()
            self._on_net_alert("INFO", "Network monitor ativado pelo Modo Empresarial")
            self.rt_protector.start()
            if hasattr(self, 'rt_toggle'):
                self.rt_toggle.setText("⏹ Stop Real-Time Protection")
            if hasattr(self, 'rt_status'):
                self.rt_status.setText("Status: Active")
            self.ransomware.start()
            if hasattr(self, 'rw_toggle'):
                self.rw_toggle.setText("⏹ Stop Ransomware Detection")
            if hasattr(self, 'rw_status'):
                self.rw_status.setText("Status: Active")
            self.usb_scanner.start()
            self.webcam_protector.start()
            if hasattr(self, 'wc_toggle'):
                self.wc_toggle.setText("⏹ Stop Webcam Monitor")
            if hasattr(self, 'wc_status'):
                self.wc_status.setText("Status: Active")

            # Block webcam hardware
            self.webcam_protector.block_webcam(hard=True)
            if hasattr(self, 'wc_list'):
                self.wc_list.addItem("Webcam bloqueada pelo Modo Empresarial")

            # Firewall strict mode
            self.firewall.enable()
            if hasattr(self, 'fw_status'):
                self.fw_status.setText("Firewall: ENABLED (Enterprise)")

            # Block all known malicious domains
            from defendr.constants import MALICIOUS_DOMAINS
            for domain in MALICIOUS_DOMAINS:
                self.web_blocker.block_domain(domain)

            # Schedule aggressive rootkit scans
            self._rootkit_timer = QtCore.QTimer()
            self._rootkit_timer.timeout.connect(self._run_enterprise_rootkit)
            self._rootkit_timer.start(600000)  # every 10 minutes

            # Initial rootkit scan
            self._run_enterprise_rootkit()

            # Faster monitoring
            self.monitor_timer.setInterval(2000)

            # Force process refresh more often
            self.proc_timer.setInterval(3000)

            # Update UI indicators
            self.prot_frame.hide()
            self.protect_indicator.setText("●  EMPRESARIAL")
            self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {RED}; background: rgba(255,69,58,0.08); padding: 2px 4px; border-radius: 4px; font-weight: 700;")
            self.protect_count.setText("🔥 Modo Empresarial ativo")
            self.enterprise_badge.show()
            self.setWindowTitle("DefendR - EMPRESARIAL [PROTECAO TOTAL]")
            self.tray.setToolTip("DefendR - MODO EMPRESARIAL ATIVO")

            # Dashboard stat update
            try:
                self.stat_cards["threats"].set_value("MAX")
            except Exception:
                pass

            self._show_msg("🔴 MODO EMPRESARIAL ATIVADO - Todas as protecoes em nivel maximo")
            self.sig_updater.update_signal.emit("EMPRESARIAL: Vigilancia total ativa")

            # Force autostart on (locked)
            self._setup_autostart()
            self.autostart_cb.setChecked(True)
            self.autostart_cb.setEnabled(False)
            self.autostart_enabled = True

            # Disable all protection toggles
            for btn in (self.rt_toggle, self.rw_toggle, self.wc_toggle,
                        self.wc_block_btn, self.wc_unblock_btn, self.net_toggle):
                try: btn.setEnabled(False)
                except AttributeError: pass
            for f in (self.fw_frame, self.port_frame, self.net_toggle_frame):
                try: f.hide()
                except AttributeError: pass
            if hasattr(self, 'protect_cb'):
                self.protect_cb.setEnabled(False)

            # Save state
            self.engine.config_data["enterprise_mode"] = True
            self.engine.save_config()
        except Exception as e:
            self.engine.config_data["enterprise_mode"] = False
            self.engine.save_config()
            self.enterprise_mode = False
            self.enterprise_cb.setChecked(False)
            self._show_msg(f"Erro ao ativar Modo Empresarial: {e}")

    def _deactivate_enterprise(self):
        self.enterprise_mode = False

        # Stop enterprise-specific monitors
        self.netmon.stop()
        self.rt_protector.stop()
        if hasattr(self, 'rt_toggle'):
            self.rt_toggle.setText("▶ Start Real-Time Protection")
        if hasattr(self, 'rt_status'):
            self.rt_status.setText("Status: Stopped")
        self.webcam_protector.stop()
        self.webcam_protector.unblock_webcam()
        if hasattr(self, 'wc_toggle'):
            self.wc_toggle.setText("▶ Start Webcam Monitor")
        if hasattr(self, 'wc_status'):
            self.wc_status.setText("Status: Stopped")

        # Restart normal monitors
        self.rt_protector.start()
        if hasattr(self, 'rt_toggle'):
            self.rt_toggle.setText("⏹ Stop Real-Time Protection")
        if hasattr(self, 'rt_status'):
            self.rt_status.setText("Status: Active")
        self.ransomware.start()
        if hasattr(self, 'rw_toggle'):
            self.rw_toggle.setText("⏹ Stop Ransomware Detection")
        if hasattr(self, 'rw_status'):
            self.rw_status.setText("Status: Active")
        self.usb_scanner.start()

        # Disable firewall
        self.firewall.disable()
        if hasattr(self, 'fw_status'):
            self.fw_status.setText("Firewall: Disabled")

        # Stop rootkit timer
        if hasattr(self, '_rootkit_timer'):
            self._rootkit_timer.stop()

        # Restore normal timing
        self.monitor_timer.setInterval(4000)
        self.proc_timer.setInterval(5000)

        # Update UI
        self.prot_frame.show()
        self.protect_indicator.setText("●  Protected")
        self.protect_indicator.setStyleSheet(f"font-size: 11px; color: {GREEN}; background: transparent;")
        self.protect_count.setText("0 threats blocked")
        self.enterprise_badge.hide()
        self.setWindowTitle("DefendR - Advanced Protection")
        self.tray.setToolTip("Protected by DefendR")
        self.engine.scan_level = "medium"

        # Re-enable all protection toggles
        for btn in (self.rt_toggle, self.rw_toggle, self.wc_toggle,
                    self.wc_block_btn, self.wc_unblock_btn, self.net_toggle):
            try: btn.setEnabled(True)
            except AttributeError: pass
        for f in (self.fw_frame, self.port_frame, self.net_toggle_frame):
            try: f.show()
            except AttributeError: pass
        if hasattr(self, 'protect_cb'):
            self.protect_cb.setEnabled(True)

        # Restore autostart to user preference
        self.autostart_cb.setEnabled(True)
        user_autostart = self.engine.config_data.get("autostart", False)
        self.autostart_cb.setChecked(user_autostart)

        self._show_msg("Modo Individual restaurado - Protecao normal")

    def _ensure_enterprise_password(self):
        import hashlib
        stored = self.engine.config_data.get("enterprise_password", "")
        if stored:
            return True
        while True:
            pwd, ok = QtWidgets.QInputDialog.getText(
                self, "Definir Senha do Modo Empresarial",
                "Crie uma senha forte (min 6 caracteres, 1 maiuscula, 1 numero, 1 especial):",
                QtWidgets.QLineEdit.Password)
            if not ok:
                return False
            if len(pwd) < 6:
                QtWidgets.QMessageBox.warning(self, "Senha Fraca", "Minimo 6 caracteres.")
                continue
            if not any(c.isupper() for c in pwd):
                QtWidgets.QMessageBox.warning(self, "Senha Fraca", "Precisa de pelo menos 1 letra maiuscula.")
                continue
            if not any(c.isdigit() for c in pwd):
                QtWidgets.QMessageBox.warning(self, "Senha Fraca", "Precisa de pelo menos 1 numero.")
                continue
            if not any(c in "!@#$%&*()-_=+[]{};:,.<>?/~`" for c in pwd):
                QtWidgets.QMessageBox.warning(self, "Senha Fraca", "Precisa de pelo menos 1 caractere especial (!@#$%&* etc).")
                continue
            pwd2, ok2 = QtWidgets.QInputDialog.getText(
                self, "Confirmar Senha",
                "Digite a senha novamente:",
                QtWidgets.QLineEdit.Password)
            if not ok2 or pwd != pwd2:
                QtWidgets.QMessageBox.warning(self, "Erro", "As senhas nao conferem.")
                continue
            self.engine.config_data["enterprise_password"] = hashlib.sha256(pwd.encode()).hexdigest()
            self.engine.save_config()
            return True

    def _verify_enterprise_password(self):
        import hashlib, time
        stored = self.engine.config_data.get("enterprise_password", "")
        if not stored:
            return True
        now = time.time()
        last_attempt = self.engine.config_data.get("enterprise_last_attempt", 0)
        attempts = self.engine.config_data.get("enterprise_attempts", 0)
        if attempts >= 3 and now - last_attempt < 300:
            restante = int(300 - (now - last_attempt))
            QtWidgets.QMessageBox.warning(
                self, "BLOQUEADO",
                f"Muitas tentativas incorretas. Aguarde {restante} segundos.")
            return False
        if now - last_attempt > 300:
            attempts = 0
        pwd, ok = QtWidgets.QInputDialog.getText(
            self, "Desativar Modo Empresarial",
            f"Digite a senha do Modo Empresarial para desativar ({3 - attempts} tentativas restantes):",
            QtWidgets.QLineEdit.Password)
        if not ok:
            return False
        if hashlib.sha256(pwd.encode()).hexdigest() == stored:
            self.engine.config_data["enterprise_attempts"] = 0
            self.engine.config_data["enterprise_last_attempt"] = 0
            self.engine.save_config()
            return True
        self.engine.config_data["enterprise_attempts"] = attempts + 1
        self.engine.config_data["enterprise_last_attempt"] = int(now)
        self.engine.save_config()
        if attempts + 1 >= 3:
            QtWidgets.QMessageBox.warning(
                self, "BLOQUEADO",
                "Senha incorreta 3 vezes. Modo Empresarial bloqueado por 5 minutos.")
        else:
            QtWidgets.QMessageBox.warning(
                self, "Senha incorreta",
                f"Senha incorreta. {2 - attempts} tentativa(s) restante(s).")
        return False

    def _run_enterprise_rootkit(self):
        try:
            result = self.rootkit.full_scan()
            if result:
                for key, msg in result.items():
                    self.rootkit.alert_signal.emit("HIGH", msg)
                    self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[ROOTKIT] {msg}"))
        except Exception:
            pass

    def _show_msg(self, msg, sound=False):
        self._notify_queue.append((msg, sound))
        if not self._notify_timer.isActive():
            self._notify_timer.start()

    def _process_notify(self):
        if not self._notify_queue:
            self._notify_timer.stop()
            return
        msg, sound = self._notify_queue.pop(0)
        if sound:
            _play_alert_sound()

        # Determine severity and icon from message
        icon = "dialog-information"
        urgency = "normal"
        if sound or "HIGH" in msg.upper():
            icon = "security-high"
            urgency = "critical"
        elif "[MEDIUM]" in msg.upper():
            icon = "dialog-warning"
            urgency = "normal"

        try:
            tag = msg.split("]")[0] + "]" if "]" in msg else ""
            body = msg.split("]", 1)[1].strip() if "]" in msg else msg
            summary = f"🛡 DefendR {tag}" if tag else "🛡 DefendR"
            subprocess.Popen(["notify-send",
                              f"--urgency={urgency}",
                              f"--icon={icon}",
                              f"--app-name=DefendR",
                              summary, body],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    # ===================== WEBCAM =====================
    def _toggle_webcam(self):
        if self.webcam_protector.monitoring:
            self.webcam_protector.stop()
            self.wc_toggle.setText("▶ Start Webcam Monitor")
            self.wc_status.setText(_("Status: Stopped"))
        else:
            self.webcam_protector.start()
            self.wc_toggle.setText("⏹ Stop Webcam Monitor")
            self.wc_status.setText(_("Status: Active"))

    def _on_selfprotect_alert(self, severity, msg):
        self._show_msg(f"[AUTO-DEFESA] {msg}", sound=True)
        self._show_intrusion_popup(severity, msg, "Auto-Defesa", "127.0.0.1")

    def _on_adv_alert(self, severity, msg):
        self._show_msg(f"[AVANCADA] {msg}", sound=True)
        self._show_intrusion_popup(severity, msg, "Protecao Avancada", "127.0.0.1")

    def _on_webcam_alert(self, level, msg):
        self._show_msg(f"[WEBCAM] {msg}", sound=True)
        item = QtWidgets.QListWidgetItem(f"[WEBCAM][{level}] {msg}")
        item.setForeground(QtGui.QColor(YELLOW))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[WEBCAM] {msg}"))
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
    def _on_webcam_block(self, name, pid):
        self.wc_list.addItem(f"Blocked: {name} (PID {pid})")
    def _webcam_block_device(self):
        msg = self.webcam_protector.block_webcam()
        self._show_msg(msg)
    def _webcam_unblock_device(self):
        msg = self.webcam_protector.unblock_webcam()
        self._show_msg(msg)

    # ===================== WIFI =====================
    def _wifi_scan(self):
        self.wifi_results.setPlainText("Scanning router (takes up to 60s)...")
        self._wifi_worker = TaskWorker(self.wifi_inspector.scan_router)
        self._wifi_worker.finished.connect(lambda r: self._on_wifi_result("wifi_scan", r or {"error":"No results"}))
        self._wifi_worker.error.connect(lambda e: self._on_wifi_result("wifi_scan", {"error":e}))
        self._wifi_worker.start()
    def _on_wifi_result(self, rtype, data):
        if rtype == "wifi_scan":
            if "error" in data:
                self.wifi_results.setPlainText(f"Error: {data['error']}\n\nTip: run with sudo and install nmap")
                return
            txt = f"📡 WiFi Router Scan\n{'='*40}\n"
            txt += f"Gateway: {data.get('gateway','?')}\n"
            txt += f"Open Ports: {', '.join(data.get('open_ports',['none']))}\n"
            if data.get("warnings"):
                txt += f"\n⚠ Security Issues:\n"
                for w in data["warnings"]: txt += f"  - {w}\n"
            txt += f"\nFull nmap output:\n{data.get('nmap_output','')[:2000]}"
            self.wifi_results.setPlainText(txt)
    def _on_wifi_device(self, msg):
        self.wifi_device_list.addItem(msg)
    def _wifi_start_monitor(self):
        if self.wifi_inspector.monitoring:
            self.wifi_inspector.monitoring = False
            self.wifi_monitor_btn.setText("▶ Start Continuous Monitor")
        else:
            self.wifi_inspector.start_monitoring()
            self.wifi_monitor_btn.setText("⏹ Stop Monitoring")

    # ===================== SHREDDER =====================
    def _shred_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding...")
            self._shred_worker = TaskWorker(self.shredder.shred, args=(path,))
            self._shred_worker.finished.connect(lambda r: None)
            self._shred_worker.error.connect(lambda e: self.shred_status.setText(f"Error: {e}"))
            self._shred_worker.start()
    def _shred_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to shred")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Shredding folder...")
            self._shred_worker = TaskWorker(self.shredder.shred_directory, args=(path,))
            self._shred_worker.finished.connect(lambda r: None)
            self._shred_worker.error.connect(lambda e: self.shred_status.setText(f"Error: {e}"))
            self._shred_worker.start()
    def _on_shred_progress(self, val, msg):
        self.shred_progress.setValue(val)
        self.shred_status.setText(msg)
    def _on_shred_done(self, ok, msg):
        self.shred_progress.hide()
        self.shred_status.setText(msg)
        self._show_msg(msg)

    # ===================== SOFTWARE UPDATER =====================
    def _check_soft_updates(self):
        self.su_status.setText("Checking for updates...")
        self.su_results.setPlainText("")
        self._su_worker = TaskWorker(self.soft_updater.check_updates)
        self._su_worker.finished.connect(self._do_soft_check)
        self._su_worker.error.connect(lambda e: self.su_status.setText(f"Error: {e}"))
        self._su_worker.start()
    def _do_soft_check(self, results):
        if results:
            txt = ""
            if results.get("system"):
                txt += f"System ({len(results['system'])}):\n"
                for p in results["system"][:30]: txt += f"  {p}\n"
                if len(results["system"]) > 30: txt += f"  ... and {len(results['system'])-30} more\n"
            if results.get("pip"):
                txt += f"\nPip ({len(results['pip'])}):\n"
                for p in results["pip"][:20]: txt += f"  {p}\n"
                if len(results["pip"]) > 20: txt += f"  ... and {len(results['pip'])-20} more\n"
            if not txt: txt = "All packages up to date"
            self.su_results.setPlainText(txt)
    def _on_soft_update(self, msg):
        self.su_status.setText(msg)
    def _on_soft_progress(self, val, msg):
        self.su_status.setText(msg)

    # ===================== DNS =====================
    def _dns_set(self, provider):
        ok, msg = self.dns_over_https.set_dns(provider)
        self.dns_status.setText(f"Current: {', '.join(self.dns_over_https.get_current_dns())}")
        self._show_msg(msg)
    def _dns_reset(self):
        ok, msg = self.dns_over_https.reset_dns()
        self.dns_status.setText(f"Current: {', '.join(self.dns_over_https.get_current_dns())}")
        self._show_msg(msg)
    def _dns_enable_dnssec(self):
        ok, msg = self.dns_over_https.enable_dnssec()
        self._show_msg(msg)

    # ===================== CLEANUP =====================
    def _run_cleanup(self):
        self.clean_progress.setValue(0)
        self.clean_progress.show()
        self.clean_status.setText("Cleaning...")
        self.clean_results.clear()
        self._clean_worker = TaskWorker(self.cleanup_mgr.run_cleanup)
        self._clean_worker.finished.connect(lambda r: None)
        self._clean_worker.error.connect(lambda e: self.clean_status.setText(f"Error: {e}"))
        self._clean_worker.start()
    def _on_cleanup_progress(self, val, msg):
        self.clean_progress.setValue(val)
        self.clean_status.setText(msg)
    def _on_cleanup_done(self, ok, msg):
        self.clean_progress.hide()
        self.clean_status.setText(msg)
        self._show_msg(msg)
    def _cleanup_preview(self):
        self.clean_results.clear()
        self.clean_status.setText("Gathering preview...")
        self._preview_worker = TaskWorker(self.cleanup_mgr.preview)
        self._preview_worker.finished.connect(self.cleanup_mgr.preview_signal.emit)
        self._preview_worker.error.connect(lambda e: self.clean_status.setText(f"Error: {e}"))
        self._preview_worker.start()
    def _on_cleanup_preview(self, results):
        self.clean_results.clear()
        if not results:
            self.clean_results.addItem("Nothing to clean")
            return
        total = 0
        for item in results:
            if isinstance(item, tuple) and len(item) >= 3:
                self.clean_results.addItem(f"{item[0]}: {item[2]}")
                total += item[1]
            elif isinstance(item, dict):
                for cat, items in item.items():
                    for path, size in items:
                        self.clean_results.addItem(f"{cat}: {path} ({self._fmt_size(size)})")
                        total += size
        self.clean_results.addItem(f"--- Total: {self._fmt_size(total)} ---")
        self.clean_status.setText(f"Preview: {self.clean_results.count()} items, {self._fmt_size(total)}")
    def _fmt_size(self, bytes_):
        if not bytes_: return "0 B"
        for unit in ["B","KB","MB","GB","TB"]:
            if bytes_ < 1024: return f"{bytes_:.1f} {unit}"
            bytes_ /= 1024
        return f"{bytes_:.1f} PB"

    # ===================== SHREDDER =====================
    def _shred_standard_changed(self, idx):
        key = self.shred_standard.itemData(idx)
        self.shredder.set_standard(key)
    def _shred_free_space(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select drive/partition to wipe free space")
        if path:
            self.shred_progress.setValue(0)
            self.shred_progress.show()
            self.shred_status.setText("Wiping free space...")
            self._shred_worker = TaskWorker(self.shredder.wipe_free_space, args=(path,))
            self._shred_worker.finished.connect(lambda r: None)
            self._shred_worker.error.connect(lambda e: self.shred_status.setText(f"Error: {e}"))
            self._shred_worker.start()

    # ===================== SOFTWARE UPDATER =====================
    def _su_install_all(self):
        self.su_status.setText("Installing updates...")
        self.su_results.setPlainText("")
        self._install_worker = TaskWorker(self.soft_updater.install_all)
        self._install_worker.finished.connect(lambda msg: self.su_status.setText(msg or "Done"))
        self._install_worker.error.connect(lambda e: self.su_status.setText(f"Error: {e}"))
        self._install_worker.start()
