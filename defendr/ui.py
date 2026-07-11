# Main UI: SplashScreen, MainWindow, all pages and handlers
import os, sys, json, subprocess, threading, time, socket, textwrap
from datetime import datetime
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import *
from defendr.engine import DefendREngine
from defendr.monitors import NetworkMonitor, RealTimeProtector, AntiRansomware, WebcamProtector, USBScanner, GameMode
from defendr.security import FirewallManager, WebBlocker, AntiPhishing, SandboxManager, RootkitDetector
from defendr.tools import DataShredder, SoftwareUpdater, CleanupManager, PasswordManager, VPNManager
from defendr.network_tools import NetworkInspector, WiFiInspector, DNSOverHTTPS
from defendr.quarantine import QuarantineManager
from defendr.scheduler import Scheduler, SignatureUpdater
from defendr.lang import _
from defendr.telemetry import TelemetryClient

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

    def __init__(self, engine, path):
        super().__init__()
        self.engine = engine
        self.path = path

    def run(self):
        try:
            result = self.engine.scan_path(self.path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class SplashScreen(QtWidgets.QSplashScreen):
    def __init__(self):
        self._icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        splash_img = os.path.join(os.path.dirname(__file__), "splash.png")
        if os.path.exists(splash_img):
            pixmap = QtGui.QPixmap(splash_img)
        else:
            pixmap = QtGui.QPixmap(500, 300)
            pixmap.fill(QtGui.QColor(DARK_BG))
        super().__init__(pixmap)
        self.setStyleSheet("background: transparent;")
        self.show()

    def draw(self, message, progress=0):
        splash_img = os.path.join(os.path.dirname(__file__), "splash.png")
        pix = QtGui.QPixmap(splash_img) if os.path.exists(splash_img) else QtGui.QPixmap(500, 300)
        if not os.path.exists(splash_img):
            pix.fill(QtGui.QColor(DARK_BG))
        p = QtGui.QPainter(pix)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        # Draw progress bar overlay at bottom
        bar_x, bar_y, bar_w, bar_h = 50, pix.height() - 50, pix.width() - 100, 8
        p.setPen(QtCore.Qt.NoPen)
        p.setBrush(QtGui.QColor(0, 0, 0, 100))
        p.drawRoundedRect(bar_x - 2, bar_y - 2, bar_w + 4, bar_h + 4, 6, 6)
        p.setBrush(QtGui.QColor(DARK_MID))
        p.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 4, 4)
        if progress > 0:
            p.setBrush(QtGui.QColor(ACCENT))
            p.drawRoundedRect(bar_x, bar_y, int(bar_w * progress / 100), bar_h, 4, 4)
        # Draw message
        if message:
            p.setPen(QtGui.QColor(255, 255, 255, 200))
            fnt = QtGui.QFont("-apple-system", 11)
            p.setFont(fnt)
            p.drawText(QtCore.QRect(0, bar_y - 25, pix.width(), 20), QtCore.Qt.AlignCenter, message)
        p.end()
        self.setPixmap(pix)
        self.repaint()

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
    def __init__(self):
        super().__init__()
        self.engine = DefendREngine()
        self.netmon = NetworkMonitor()
        self.netmon.alert_signal.connect(self._on_net_alert)
        self.netmon.data_signal.connect(self._on_net_data)
        self.quarantine = QuarantineManager()
        self.rt_protector = RealTimeProtector(self.engine)
        self.rt_protector.alert_signal.connect(self._on_rt_alert)
        self.firewall = FirewallManager()
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

        self.setWindowTitle(_("DefendR - Advanced Protection"))
        self.setMinimumSize(1200, 750)
        self.resize(1300, 800)
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        if os.path.exists(icon_path): self.setWindowIcon(QtGui.QIcon(icon_path))

        self._setup_ui()
        self._setup_tray()
        self._start_monitors()

    def closeEvent(self, event):
        if self.game_mode.suppress_notifications():
            event.accept()
            return
        event.ignore()
        self.hide()
        self.tray.showMessage("DefendR", _("Protecao continua ativa em segundo plano"),
                              QtWidgets.QSystemTrayIcon.Information, 2000)

    def _setup_tray(self):
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        icon = QtGui.QIcon(icon_path) if os.path.exists(icon_path) else QtGui.QIcon()
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
        self.usb_scanner.stop(); self.game_mode.stop(); self.webcam_protector.stop()
        self.engine.scanning = False
        self.monitor_timer.stop()
        self.proc_timer.stop()
        self.hide(); self.tray.hide()
        QtCore.QTimer.singleShot(100, QtWidgets.QApplication.quit)

    def _switch_page(self, key):
        pages = {"dashboard":0,"scanner":1,"realtime":2,"firewall":3,"network":4,
                 "processes":5,"quarantine":6,"tools":7,"reporterror":8,"hdscan":9,"settings":10}
        idx = pages.get(key, 0)
        self.content_stack.setCurrentIndex(idx)
        if key == "network": self._update_dns()

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
        nav_group = QtWidgets.QButtonGroup()
        for key, icon, label in nav_items:
            btn = SidebarButton(label, icon)
            btn.clicked.connect(lambda checked, k=key: self._switch_page(k))
            nav_group.addButton(btn)
            sidebar_layout.addWidget(btn)
            self.nav_btns.append(btn)
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

        self.nav_btns[0].setChecked(True)

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

        # Alerts
        alert_frame = QtWidgets.QFrame()
        alert_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        alert_layout = QtWidgets.QVBoxLayout(alert_frame)
        alert_header = QtWidgets.QLabel("📋  Security Events")
        alert_header.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {TEXT}; background: transparent;")
        alert_layout.addWidget(alert_header)
        self.alert_list = QtWidgets.QListWidget()
        self.alert_list.setStyleSheet(f"QListWidget {{ background: rgba(28,28,30,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QListWidget::item {{ padding: 8px 12px; border-bottom: 1px solid {DARK_MID}; }} QListWidget::item:selected {{ background: {ACCENT}; }}")
        alert_layout.addWidget(self.alert_list)
        layout.addWidget(alert_frame, 1)
        self.content_stack.addWidget(w)

    # ===== SCANNER =====
    def _build_scanner(self):
        w, layout = self._page_widget()
        self._page_header(layout, _("🔍  File Scanner"), "Scan files/directories, USB auto-scan, scheduled scans")
        btn_frame = QtWidgets.QWidget()
        btn_frame.setStyleSheet("background: transparent;")
        btn_layout = QtWidgets.QHBoxLayout(btn_frame)
        for text, handler in [("📁 Scan File", self._scan_file),("📂 Scan Folder", self._scan_dir),
                               ("⏹ Stop", self._stop_scan),("🗑 Clear", self._clear_scan),
                               ("📀 Scan USB", self._scan_usb_manual)]:
            btn_layout.addWidget(self._btn(text, handler))
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
        layout.addWidget(self.scan_tree, 1)
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
        wc_btn_row.addWidget(self.wc_toggle)
        self.wc_block_btn = self._btn(_("🔴 Block Webcam"), self._webcam_block_device)
        wc_btn_row.addWidget(self.wc_block_btn)
        self.wc_unblock_btn = self._btn(_("🟢 Unblock Webcam"), self._webcam_unblock_device)
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
        wb_input_row.addWidget(self._btn(_("Block"), self._web_block))
        wb_input_row.addWidget(self._btn(_("Unblock"), self._web_unblock))
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

        fw_frame = QtWidgets.QFrame()
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
        port_frame = QtWidgets.QFrame()
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
        toggle_frame = QtWidgets.QWidget()
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
        self.q_table.setColumnWidth(0,100); self.q_table.setColumnWidth(1,250); self.q_table.setColumnWidth(2,140); self.q_table.setColumnWidth(3,60)
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
        ball_frame = QtWidgets.QFrame()
        ball_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 16px;")
        ball_l = QtWidgets.QVBoxLayout(ball_frame)
        ball_l.setAlignment(QtCore.Qt.AlignCenter)
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
        ball_l.addWidget(self.hd_ball_btn)
        self.hd_ball_label = QtWidgets.QLabel(_("Click to scan your HD"))
        self.hd_ball_label.setStyleSheet(f"font-size: 14px; color: {ACCENT_LIGHT}; background: transparent;")
        self.hd_ball_label.setAlignment(QtCore.Qt.AlignCenter)
        ball_l.addWidget(self.hd_ball_label)
        layout.addWidget(ball_frame, 0, QtCore.Qt.AlignCenter)
        self.hd_progress = QtWidgets.QProgressBar()
        self.hd_progress.setStyleSheet(f"QProgressBar {{ background: rgba(44,44,46,0.6); border: none; border-radius: 8px; height: 8px; text-align: center; font-size: 10px; color: {TEXT}; }} QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {ACCENT_LIGHT}); border-radius: 8px; }}")
        self.hd_progress.hide()
        layout.addWidget(self.hd_progress)
        self.hd_status = QtWidgets.QLabel(_("Ready"))
        self.hd_status.setStyleSheet(f"font-size: 12px; color: {TEXT_DIM}; background: transparent;")
        layout.addWidget(self.hd_status)
        hd_tabs = QtWidgets.QTabWidget()
        hd_tabs.setStyleSheet(f"QTabWidget::pane {{ background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }} QTabBar::tab {{ background: transparent; color: {TEXT_DIM}; padding: 8px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 4px 2px; }} QTabBar::tab:selected {{ background: {ACCENT}; color: white; font-weight: 600; }} QTabBar::tab:hover {{ color: {TEXT}; }} QTabBar {{ background: rgba(44,44,46,0.4); border-radius: 10px; padding: 2px; }}")

        results_w = QtWidgets.QWidget()
        results_l = QtWidgets.QVBoxLayout(results_w)
        self.hd_results_tree = QtWidgets.QTreeWidget()
        self.hd_results_tree.setHeaderLabels([_("Risk"), _("Path"), _("Reason")])
        self.hd_results_tree.setColumnWidth(0, 90)
        self.hd_results_tree.setColumnWidth(2, 300)
        self.hd_results_tree.setStyleSheet(f"QTreeWidget {{ background: rgba(36,36,38,0.6); border: 1px solid {BORDER}; border-radius: 10px; color: {TEXT}; font-size: 12px; }} QTreeWidget::item {{ padding: 6px 8px; border-bottom: 1px solid {DARK_MID}; }} QHeaderView::section {{ background: rgba(44,44,46,0.8); color: {ACCENT_LIGHT}; border: none; padding: 6px 8px; font-size: 12px; font-weight: 600; }}")
        results_l.addWidget(self.hd_results_tree)
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

    def _hd_start_scan(self):
        self.hd_results_tree.clear()
        self.hd_recs_list.clear()
        self.hd_progress.setValue(0)
        self.hd_progress.show()
        self.hd_ball_btn.setText("⏳")
        self.hd_ball_btn.setEnabled(False)
        self.hd_status.setText(_("Scanning drives..."))
        self._hd_worker = ScanWorker(self.engine, "/mnt/defendr")
        self._hd_worker.finished.connect(self._hd_scan_done)
        self._hd_worker.start()

    def _hd_scan_done(self, results):
        self.hd_progress.hide()
        self.hd_ball_btn.setText("✓")
        self.hd_ball_btn.setEnabled(True)
        malicious = len(results["malicious"])
        suspicious = len(results["suspicious"])
        safe = results["safe"]
        total = malicious + suspicious + safe + len(results["pentest"])
        self.hd_ball_label.setText(_("Scan complete: %d files") % total)
        for r in results["malicious"]:
            item = QtWidgets.QTreeWidgetItem([_("MALICIOUS"), r["path"], r["reason"]])
            for i in range(3): item.setForeground(i, QtGui.QColor(RED))
            self.hd_results_tree.addTopLevelItem(item)
        for r in results["suspicious"]:
            item = QtWidgets.QTreeWidgetItem([_("SUSPICIOUS"), r["path"], r["reason"]])
            for i in range(3): item.setForeground(i, QtGui.QColor(YELLOW))
            self.hd_results_tree.addTopLevelItem(item)
        for r in results["pentest"]:
            item = QtWidgets.QTreeWidgetItem([_("ALLOWED"), r["path"], r["reason"]])
            for i in range(3): item.setForeground(i, QtGui.QColor(CYAN))
            self.hd_results_tree.addTopLevelItem(item)
        if not any([results["malicious"], results["suspicious"], results["pentest"]]):
            item = QtWidgets.QTreeWidgetItem([_("SAFE"), _("No threats found"), _("All files are clean")])
            for i in range(3): item.setForeground(i, QtGui.QColor(GREEN))
            self.hd_results_tree.addTopLevelItem(item)
        if safe > 0:
            self.hd_recs_list.addItem(_("✅ %d clean files - no action needed") % safe)
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
            du = psutil.disk_usage("/mnt/defendr")
            pct = du.used / du.total * 100
            self.hd_recs_list.addItem(_("📊 /mnt/defendr: %dGB / %dGB (%d%% used)") % (du.used//(1024**3), du.total//(1024**3), pct))
            if pct > 90:
                self.hd_recs_list.addItem(_("🔴 WARNING: Disk almost full - free up space"))
            elif pct > 75:
                self.hd_recs_list.addItem(_("🟡 Disk usage above 75% - consider cleanup"))
        except Exception:
            pass
        if self.telemetry.is_registered():
            self.telemetry.send_scan_result("hd_scan", {
                "malicious": malicious, "suspicious": suspicious, "safe": safe,
            })
        self._refresh_drives()

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
        gen_l = QtWidgets.QVBoxLayout(gen_w)

        prot_frame = QtWidgets.QFrame()
        prot_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        prot_l = QtWidgets.QVBoxLayout(prot_frame)
        prot_l.addWidget(QtWidgets.QLabel("Protection"))
        self.protect_cb = QtWidgets.QCheckBox("Enable real-time protection")
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
        self.gm_cb.setStyleSheet(f"QCheckBox {{ color: {TEXT}; font-size: 12px; }}")
        self.gm_cb.toggled.connect(lambda v: self.game_mode.start() if v else self.game_mode.stop())
        gm_l.addWidget(self.gm_cb)
        gen_l.addWidget(gm_frame)

        # Software Updates
        su_frame = QtWidgets.QFrame()
        su_frame.setStyleSheet(f"background: rgba(36,36,38,0.8); border: 1px solid {BORDER}; border-radius: 14px;")
        su_l = QtWidgets.QVBoxLayout(su_frame)
        su_l.addWidget(QtWidgets.QLabel("Software Updater"))
        su_l.addWidget(QtWidgets.QLabel("Check for outdated system packages and pip packages"))
        su_btn_row = QtWidgets.QHBoxLayout()
        su_btn_row.addWidget(self._btn(_("🔍 Check for Updates"), self._check_soft_updates))
        self.su_install_btn = self._btn(_("📥 Install All Updates"), self._su_install_all)
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
        tabs.addTab(gen_w, "General")

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

    # ===================== MONITORS =====================
    def _start_monitors(self):
        self.monitor_timer = QtCore.QTimer()
        self.monitor_timer.timeout.connect(self._update_stats)
        self.monitor_timer.start(4000)
        self.proc_timer = QtCore.QTimer()
        self.proc_timer.timeout.connect(self._refresh_procs)
        self.proc_timer.start(5000)
        self._update_dns()
        self._refresh_procs()
        # Auto-start background protections
        self.rt_protector.start()
        self.rt_toggle.setText("⏹ Stop Real-Time Protection")
        self.rt_status.setText(_("Status: Active"))
        self.ransomware.start()
        self.rw_toggle.setText("⏹ Stop Ransomware Detection")
        self.rw_status.setText(_("Status: Active"))
        self.usb_scanner.start()

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
        except Exception: pass

    def _update_dns(self):
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf") as f:
                    servers = [l.split()[1] for l in f if l.startswith("nameserver")]
                self.dns_label.setText("\n".join(servers) if servers else "None configured")
        except Exception: pass

    # ===================== SCANNER =====================
    def _scan_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to scan")
        if path: self._do_scan(path)
    def _scan_dir(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if path: self._do_scan(path)
    def _scan_usb_manual(self):
        for d in ["/media","/run/media","/mnt"]:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    fp = os.path.join(d,f)
                    if os.path.ismount(fp):
                        self._do_scan(fp)
                        return
        self.scan_status.setText("No USB mounts found")

    def _do_scan(self, path):
        self.scan_tree.clear()
        self.scan_progress.setValue(0)
        self.scan_progress.show()
        self.scan_status.setText(f"Scanning: {path}")
        thread = ScanWorker(self.engine, path)
        thread.finished.connect(lambda results: self._scan_done(results))
        thread.start()
        self._scan_thread = thread

    def _scan_done(self, results):
        self.scan_progress.hide()
        self.scan_status.setText(f"Done. Malicious: {len(results['malicious'])}, Suspicious: {len(results['suspicious'])}, Pentest: {len(results['pentest'])}, Safe: {results['safe']}")
        total = results["safe"] + len(results["malicious"])+len(results["suspicious"])+len(results["pentest"])
        cur = int(self.stat_cards["scanned"].value_lbl.text() or "0")
        self.stat_cards["scanned"].set_value(str(cur+total))
        for r in results["malicious"]:
            self._add_scan_item("MALICIOUS", r["path"], r["reason"], RED)
        for r in results["suspicious"]:
            self._add_scan_item("SUSPICIOUS", r["path"], r["reason"], YELLOW)
        for r in results["pentest"]:
            self._add_scan_item("PENTEST", r["path"], r["reason"], CYAN)
        if not any([results["malicious"],results["suspicious"],results["pentest"]]):
            self._add_scan_item("SAFE", _("No threats found"), "All files are clean", GREEN)

    def _add_scan_item(self, risk, path, reason, color):
        item = QtWidgets.QTreeWidgetItem([risk, textwrap.shorten(path, 80), reason])
        for i in range(3): item.setForeground(i, QtGui.QColor(color))
        item.setToolTip(1, path)
        self.scan_tree.addTopLevelItem(item)

    def _on_scan_level_change(self, idx):
        levels = ["light", "medium", "heavy"]
        self.engine.scan_level = levels[idx]

    def _stop_scan(self):
        self.engine.scanning = False
        self.scan_progress.hide()
        self.scan_status.setText(_("Scan stopped"))
    def _clear_scan(self):
        self.scan_tree.clear()
        self.scan_status.setText(_("Ready"))

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
        item = QtWidgets.QListWidgetItem(f"[{risk.upper()}] {path}: {reason}")
        color = RED if risk == "malicious" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        if self.rt_alerts.count() > 100: self.rt_alerts.takeItem(self.rt_alerts.count()-1)
        ditem = QtWidgets.QListWidgetItem(f"[RT][{risk.upper()}] {reason}")
        ditem.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, ditem)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
        if risk == "malicious":
            cur = int(self.stat_cards["threats"].value_lbl.text() or "0")
            self.stat_cards["threats"].set_value(str(cur + 1))

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
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        color = RED if level == "HIGH" else YELLOW
        item.setForeground(QtGui.QColor(color))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[RANSOM]{msg}"))
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
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
            r_btn = QtWidgets.QPushButton("Restore")
            r_btn.setStyleSheet(f"QPushButton {{ background: {GREEN}; color: white; border: none; border-radius: 8px; padding: 5px 14px; font-size: 11px; }}")
            r_btn.clicked.connect(lambda _, q=qid: self._quarantine_restore(q))
            btn_l.addWidget(r_btn)
            d_btn = QtWidgets.QPushButton("Delete")
            d_btn.setStyleSheet(f"QPushButton {{ background: {RED}; color: white; border: none; border-radius: 8px; padding: 5px 14px; font-size: 11px; }}")
            d_btn.clicked.connect(lambda _, q=qid: self._quarantine_delete(q))
            btn_l.addWidget(d_btn)
            self.q_table.setCellWidget(i,4,btn_w)

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

    def _on_rootkit_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[{level}] {msg}")
        item.setForeground(QtGui.QColor(RED if level == "HIGH" else YELLOW))
        self.alert_list.insertItem(0, item)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
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
        item = QtWidgets.QListWidgetItem(f"[USB][{level}] {msg}")
        color = RED if level == "HIGH" else (YELLOW if level == "MEDIUM" else TEXT)
        item.setForeground(QtGui.QColor(color))
        self.alert_list.insertItem(0, item)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
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

    def _show_msg(self, msg):
        self.tray.showMessage("DefendR", msg, QtWidgets.QSystemTrayIcon.Information, 3000)

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

    def _on_webcam_alert(self, level, msg):
        item = QtWidgets.QListWidgetItem(f"[WEBCAM][{level}] {msg}")
        item.setForeground(QtGui.QColor(YELLOW))
        self.rt_alerts.insertItem(0, item)
        self.alert_list.insertItem(0, QtWidgets.QListWidgetItem(f"[WEBCAM] {msg}"))
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
        if self.alert_list.count() > 100: self.alert_list.takeItem(self.alert_list.count()-1)
    def _on_webcam_block(self, msg):
        self.wc_list.addItem(msg)
    def _webcam_block_device(self):
        ok, msg = self.webcam_protector.block_webcam()
        self._show_msg(msg)
    def _webcam_unblock_device(self):
        ok, msg = self.webcam_protector.unblock_webcam()
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
