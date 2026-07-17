# DefendR package
import os, sys, socket, threading, subprocess
from PyQt5 import QtCore, QtGui, QtWidgets
from defendr.constants import DARK_BG, DARK_CARD, DARK_MID, TEXT, ACCENT
from defendr.ui import MainWindow, SplashScreen
from defendr.lang import _
from defendr.constants import CONFIG_DIR

def main():
    if "--restart" in sys.argv:
        import time
        time.sleep(0.5)
    LOCK_PORT = 48123
    lock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lock_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lock_sock.bind(("127.0.0.1", LOCK_PORT))
        lock_sock.listen(1)
    except OSError:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", LOCK_PORT)); s.sendall(b"raise"); s.close()
        except Exception: pass
        sys.exit(0)

    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(DARK_BG))
    palette.setColor(QtGui.QPalette.Background, QtGui.QColor(DARK_BG))
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(DARK_CARD))
    palette.setColor(QtGui.QPalette.Text, QtGui.QColor(TEXT))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(TEXT))
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(ACCENT))
    palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("white"))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(ACCENT))
    palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor("white"))
    app.setPalette(palette)
    font = QtGui.QFont("Consolas", 10)
    app.setFont(font)

    splash = SplashScreen()
    splash.draw(_("Initializing..."), 0)
    app.processEvents()

    splash_steps = [
        (6, _("Initializing engine...")),
        (22, _("Loading signatures...")),
        (42, _("Starting modules...")),
        (62, _("Configuring firewall...")),
        (82, _("Preparing interface...")),
        (97, _("Almost ready...")),
    ]
    splash_idx = [0]

    def advance_splash():
        if splash_idx[0] < len(splash_steps):
            pct, msg = splash_steps[splash_idx[0]]
            splash.draw(msg, pct)
            splash_idx[0] += 1
        else:
            timer.stop()
            window = MainWindow()
            splash.finish(window)

            def listen_raise():
                while True:
                    try:
                        conn, addr = lock_sock.accept()
                        data = conn.recv(1024)
                        if data == b"raise":
                            window.raise_(); window.activateWindow(); window.show(); window.tray.show()
                        conn.close()
                    except Exception: break
            threading.Thread(target=listen_raise, daemon=True).start()

            if os.geteuid() != 0:
                QtCore.QTimer.singleShot(3000, lambda: window.tray.showMessage(
                    "DefendR", _("Run with sudo for full firewall and network monitoring."),
                    QtWidgets.QSystemTrayIcon.Information, 3000))

    timer = QtCore.QTimer()
    timer.timeout.connect(advance_splash)
    timer.start(600)
    sys.exit(app.exec())

if __name__ == "__main__":
    if not os.environ.get("DISPLAY"):
        print("DefendR requires a graphical display to run.")
        sys.exit(1)
    main()
