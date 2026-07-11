#!/usr/bin/env python3
"""DefendR Installer Wizard - 7 Languages"""

import os, sys, subprocess, shutil

LANG = {}
ICON_SRC = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
DEFENDR_DIR = os.path.dirname(os.path.abspath(__file__))
DEFENDR_SCRIPT = os.path.join(DEFENDR_DIR, "defendr")
SPLASH_PATH = os.path.join(DEFENDR_DIR, "defendr", "splash.png")

LANGS = {
    "pt": {
        "title": "Instalador DefendR",
        "welcome": "Bem-vindo ao DefendR!",
        "desc": "Antivírus avançado com firewall, proteção em tempo real e ferramentas de segurança.",
        "select_lang": "Selecione o idioma da instalação:",
        "files_title": "Arquivos do DefendR",
        "files_desc": "O executável principal está destacado abaixo:",
        "dep_title": "Verificando Dependências",
        "dep_desc": "Verificando pacotes necessários...",
        "dep_ok": "OK",
        "dep_missing": "Ausente",
        "dep_optional": "Opcional",
        "dep_install": "Deseja instalar as dependências opcionais?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (interface gráfica)",
            "psutil": "psutil (monitoramento do sistema)",
        },
        "opt_deps": {
            "firejail": "firejail (sandbox)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (scan de rede)",
            "lsof": "lsof (monitor de portas)",
        },
        "sudo_title": "Permissões de Root",
        "sudo_desc": "Algumas funcionalidades precisam de root:\n• Firewall (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Bloqueio de webcam (modprobe)\n• ARP scan",
        "sudo_ask": "Criar atalho com sudo para evitar problemas?",
        "sudo_yes": "Criar atalho com pkexec (recomendado)",
        "sudo_no": "Usar sem root (notificações silenciosas)",
        "install_title": "Instalando",
        "install_desc": "Configurando DefendR no sistema...",
        "installing_icon": "Copiando ícones...",
        "installing_desktop": "Criando atalho no menu...",
        "installing_desktop2": "Criando atalho na Área de Trabalho...",
        "done_title": "Instalação Concluída",
        "done_desc": "DefendR foi instalado com sucesso!",
        "start_now": "Iniciar DefendR agora",
        "finish": "Concluir",
        "cancel": "Cancelar",
        "next": "Próximo >",
        "back": "< Voltar",
        "installing_opt": "Instalando pacotes opcionais...",
        "sudo_fix_msg": "Digite sua senha sudo quando solicitado",
        "err_pyqt": "PyQt5 é obrigatório. Instale com: sudo apt install python3-pyqt5",
        "err_sudo_install": "Erro ao instalar pacotes. Tente manualmente:",
    },
    "en": {
        "title": "DefendR Installer",
        "welcome": "Welcome to DefendR!",
        "desc": "Advanced antivirus with firewall, real-time protection and security tools.",
        "select_lang": "Select installation language:",
        "files_title": "DefendR Files",
        "files_desc": "The main executable is highlighted below:",
        "dep_title": "Checking Dependencies",
        "dep_desc": "Checking required packages...",
        "dep_ok": "OK",
        "dep_missing": "Missing",
        "dep_optional": "Optional",
        "dep_install": "Install optional dependencies?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (GUI)",
            "psutil": "psutil (system monitor)",
        },
        "opt_deps": {
            "firejail": "firejail (sandbox)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (network scan)",
            "lsof": "lsof (port monitor)",
        },
        "sudo_title": "Root Permissions",
        "sudo_desc": "Some features require root:\n• Firewall (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Webcam block (modprobe)\n• ARP scan",
        "sudo_ask": "Create sudo shortcut to avoid issues?",
        "sudo_yes": "Create pkexec shortcut (recommended)",
        "sudo_no": "Run without root (silent notifications)",
        "install_title": "Installing",
        "install_desc": "Setting up DefendR on your system...",
        "installing_icon": "Copying icons...",
        "installing_desktop": "Creating menu shortcut...",
        "installing_desktop2": "Creating Desktop shortcut...",
        "done_title": "Installation Complete",
        "done_desc": "DefendR has been installed successfully!",
        "start_now": "Start DefendR now",
        "finish": "Finish",
        "cancel": "Cancel",
        "next": "Next >",
        "back": "< Back",
        "installing_opt": "Installing optional packages...",
        "sudo_fix_msg": "Enter your sudo password when prompted",
        "err_pyqt": "PyQt5 is required. Install with: sudo apt install python3-pyqt5",
        "err_sudo_install": "Error installing packages. Try manually:",
    },
    "es": {
        "title": "Instalador DefendR",
        "welcome": "¡Bienvenido a DefendR!",
        "desc": "Antivirus avanzado con firewall, protección en tiempo real y herramientas de seguridad.",
        "select_lang": "Seleccione el idioma de instalación:",
        "files_title": "Archivos de DefendR",
        "files_desc": "El ejecutable principal está resaltado abajo:",
        "dep_title": "Verificando Dependencias",
        "dep_desc": "Verificando paquetes necesarios...",
        "dep_ok": "OK",
        "dep_missing": "Faltante",
        "dep_optional": "Opcional",
        "dep_install": "¿Instalar dependencias opcionales?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (interfaz gráfica)",
            "psutil": "psutil (monitoreo)",
        },
        "opt_deps": {
            "firejail": "firejail (sandbox)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (scan de red)",
            "lsof": "lsof (monitor de puertos)",
        },
        "sudo_title": "Permisos de Root",
        "sudo_desc": "Algunas funciones requieren root:\n• Firewall (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Bloqueo webcam (modprobe)\n• ARP scan",
        "sudo_ask": "¿Crear acceso directo con sudo?",
        "sudo_yes": "Crear con pkexec (recomendado)",
        "sudo_no": "Usar sin root (notificaciones silenciosas)",
        "install_title": "Instalando",
        "install_desc": "Configurando DefendR en el sistema...",
        "installing_icon": "Copiando iconos...",
        "installing_desktop": "Creando acceso en menú...",
        "installing_desktop2": "Creando acceso en Escritorio...",
        "done_title": "Instalación Completa",
        "done_desc": "¡DefendR se instaló correctamente!",
        "start_now": "Iniciar DefendR ahora",
        "finish": "Finalizar",
        "cancel": "Cancelar",
        "next": "Siguiente >",
        "back": "< Atrás",
        "installing_opt": "Instalando paquetes opcionales...",
        "sudo_fix_msg": "Ingrese su contraseña sudo cuando se solicite",
        "err_pyqt": "PyQt5 es obligatorio. Instale con: sudo apt install python3-pyqt5",
        "err_sudo_install": "Error instalando paquetes. Intente manualmente:",
    },
    "fr": {
        "title": "Installateur DefendR",
        "welcome": "Bienvenue sur DefendR !",
        "desc": "Antivirus avancé avec pare-feu, protection en temps réel et outils de sécurité.",
        "select_lang": "Choisissez la langue d'installation :",
        "files_title": "Fichiers de DefendR",
        "files_desc": "L'exécutable principal est mis en évidence ci-dessous :",
        "dep_title": "Vérification des Dépendances",
        "dep_desc": "Vérification des paquets requis...",
        "dep_ok": "OK",
        "dep_missing": "Manquant",
        "dep_optional": "Optionnel",
        "dep_install": "Installer les dépendances optionnelles ?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (interface graphique)",
            "psutil": "psutil (surveillance)",
        },
        "opt_deps": {
            "firejail": "firejail (sandbox)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (scan réseau)",
            "lsof": "lsof (moniteur ports)",
        },
        "sudo_title": "Permissions Root",
        "sudo_desc": "Certaines fonctions nécessitent root :\n• Pare-feu (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Blocage webcam (modprobe)\n• Scan ARP",
        "sudo_ask": "Créer un raccourci sudo ?",
        "sudo_yes": "Créer avec pkexec (recommandé)",
        "sudo_no": "Utiliser sans root (notifications silencieuses)",
        "install_title": "Installation",
        "install_desc": "Configuration de DefendR...",
        "installing_icon": "Copie des icônes...",
        "installing_desktop": "Création du raccourci menu...",
        "installing_desktop2": "Création du raccourci Bureau...",
        "done_title": "Installation Terminée",
        "done_desc": "DefendR a été installé avec succès !",
        "start_now": "Lancer DefendR maintenant",
        "finish": "Terminer",
        "cancel": "Annuler",
        "next": "Suivant >",
        "back": "< Retour",
        "installing_opt": "Installation des paquets optionnels...",
        "sudo_fix_msg": "Entrez votre mot de passe sudo lorsque demandé",
        "err_pyqt": "PyQt5 est requis. Installez avec : sudo apt install python3-pyqt5",
        "err_sudo_install": "Erreur d'installation. Essayez manuellement :",
    },
    "de": {
        "title": "DefendR Installer",
        "welcome": "Willkommen bei DefendR!",
        "desc": "Erweitertes Antivirus mit Firewall, Echtzeitschutz und Sicherheitstools.",
        "select_lang": "Installationssprache wählen:",
        "files_title": "DefendR Dateien",
        "files_desc": "Die ausführbare Hauptdatei ist unten hervorgehoben:",
        "dep_title": "Abhängigkeiten prüfen",
        "dep_desc": "Prüfe erforderliche Pakete...",
        "dep_ok": "OK",
        "dep_missing": "Fehlt",
        "dep_optional": "Optional",
        "dep_install": "Optionale Abhängigkeiten installieren?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (Benutzeroberfläche)",
            "psutil": "psutil (Systemüberwachung)",
        },
        "opt_deps": {
            "firejail": "firejail (Sandbox)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (Netzwerkscan)",
            "lsof": "lsof (Portmonitor)",
        },
        "sudo_title": "Root-Berechtigungen",
        "sudo_desc": "Einige Funktionen benötigen root:\n• Firewall (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Webcam-Sperre (modprobe)\n• ARP-Scan",
        "sudo_ask": "Sudo-Verknüpfung erstellen?",
        "sudo_yes": "Mit pkexec erstellen (empfohlen)",
        "sudo_no": "Ohne Root ausführen (stille Benachrichtigungen)",
        "install_title": "Installieren",
        "install_desc": "DefendR wird eingerichtet...",
        "installing_icon": "Kopiere Symbole...",
        "installing_desktop": "Erstelle Menüverknüpfung...",
        "installing_desktop2": "Erstelle Desktop-Verknüpfung...",
        "done_title": "Installation Abgeschlossen",
        "done_desc": "DefendR wurde erfolgreich installiert!",
        "start_now": "DefendR jetzt starten",
        "finish": "Fertigstellen",
        "cancel": "Abbrechen",
        "next": "Weiter >",
        "back": "< Zurück",
        "installing_opt": "Installiere optionale Pakete...",
        "sudo_fix_msg": "Geben Sie Ihr sudo-Passwort ein wenn aufgefordert",
        "err_pyqt": "PyQt5 wird benötigt. Installieren mit: sudo apt install python3-pyqt5",
        "err_sudo_install": "Fehler bei Paketinstallation. Manuell versuchen:",
    },
    "it": {
        "title": "Installazione DefendR",
        "welcome": "Benvenuto in DefendR!",
        "desc": "Antivirus avanzato con firewall, protezione in tempo reale e strumenti di sicurezza.",
        "select_lang": "Seleziona la lingua di installazione:",
        "files_title": "File di DefendR",
        "files_desc": "L'eseguibile principale è evidenziato qui sotto:",
        "dep_title": "Verifica Dipendenze",
        "dep_desc": "Verifica pacchetti richiesti...",
        "dep_ok": "OK",
        "dep_missing": "Mancante",
        "dep_optional": "Opzionale",
        "dep_install": "Installare dipendenze opzionali?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (interfaccia grafica)",
            "psutil": "psutil (monitoraggio sistema)",
        },
        "opt_deps": {
            "firejail": "firejail (sandbox)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (scan rete)",
            "lsof": "lsof (monitor porte)",
        },
        "sudo_title": "Permessi di Root",
        "sudo_desc": "Alcune funzioni richiedono root:\n• Firewall (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Blocco webcam (modprobe)\n• Scan ARP",
        "sudo_ask": "Creare collegamento sudo?",
        "sudo_yes": "Crea con pkexec (consigliato)",
        "sudo_no": "Esegui senza root (notifiche silenziose)",
        "install_title": "Installazione",
        "install_desc": "Configurazione DefendR in corso...",
        "installing_icon": "Copio icone...",
        "installing_desktop": "Creo collegamento menu...",
        "installing_desktop2": "Creo collegamento Desktop...",
        "done_title": "Installazione Completata",
        "done_desc": "DefendR è stato installato con successo!",
        "start_now": "Avvia DefendR ora",
        "finish": "Fine",
        "cancel": "Annulla",
        "next": "Avanti >",
        "back": "< Indietro",
        "installing_opt": "Installazione pacchetti opzionali...",
        "sudo_fix_msg": "Inserisci la password sudo quando richiesto",
        "err_pyqt": "PyQt5 è richiesto. Installa con: sudo apt install python3-pyqt5",
        "err_sudo_install": "Errore installazione pacchetti. Prova manualmente:",
    },
    "ru": {
        "title": "Установщик DefendR",
        "welcome": "Добро пожаловать в DefendR!",
        "desc": "Продвинутый антивирус с файрволом, защитой в реальном времени и инструментами безопасности.",
        "select_lang": "Выберите язык установки:",
        "files_title": "Файлы DefendR",
        "files_desc": "Основной исполняемый файл выделен ниже:",
        "dep_title": "Проверка зависимостей",
        "dep_desc": "Проверка необходимых пакетов...",
        "dep_ok": "OK",
        "dep_missing": "Отсутствует",
        "dep_optional": "Опционально",
        "dep_install": "Установить опциональные зависимости?",
        "deps": {
            "python3": "Python 3",
            "PyQt5": "PyQt5 (графический интерфейс)",
            "psutil": "psutil (мониторинг системы)",
        },
        "opt_deps": {
            "firejail": "firejail (песочница)",
            "openvpn": "openvpn (VPN)",
            "nmap": "nmap (сканирование сети)",
            "lsof": "lsof (монитор портов)",
        },
        "sudo_title": "Права Root",
        "sudo_desc": "Некоторые функции требуют root:\n• Файрвол (iptables)\n• DNS-over-HTTPS (resolvectl)\n• Блокировка веб-камеры (modprobe)\n• ARP сканирование",
        "sudo_ask": "Создать ярлык с sudo?",
        "sudo_yes": "Создать с pkexec (рекомендуется)",
        "sudo_no": "Запускать без root (тихие уведомления)",
        "install_title": "Установка",
        "install_desc": "Настройка DefendR в системе...",
        "installing_icon": "Копирование иконок...",
        "installing_desktop": "Создание ярлыка в меню...",
        "installing_desktop2": "Создание ярлыка на Рабочем столе...",
        "done_title": "Установка Завершена",
        "done_desc": "DefendR успешно установлен!",
        "start_now": "Запустить DefendR сейчас",
        "finish": "Завершить",
        "cancel": "Отмена",
        "next": "Далее >",
        "back": "< Назад",
        "installing_opt": "Установка опциональных пакетов...",
        "sudo_fix_msg": "Введите пароль sudo при запросе",
        "err_pyqt": "PyQt5 обязателен. Установите: sudo apt install python3-pyqt5",
        "err_sudo_install": "Ошибка установки пакетов. Попробуйте вручную:",
    },
}

def _(key):
    return LANG.get(key, key)

def detect_lang():
    lang = os.environ.get("LANG", "pt").split("_")[0]
    if lang not in LANGS: lang = "en"
    return lang

def check_deps():
    deps = {"python3": True, "PyQt5": False, "psutil": False}
    try:
        import PyQt5
        deps["PyQt5"] = True
    except: pass
    try:
        import psutil
        deps["psutil"] = True
    except: pass
    return deps

def check_optional():
    opt = {}
    for cmd in ["firejail", "openvpn", "nmap", "lsof"]:
        opt[cmd] = shutil.which(cmd) is not None
    return opt

def run_with_sudo(cmd):
    full = ["sudo"] + (cmd if isinstance(cmd, list) else cmd.split())
    return subprocess.run(full, capture_output=True, text=True)

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
    HAS_PYQT = True
except:
    HAS_PYQT = False

class InstallWizard(QtWidgets.QWizard):
    def __init__(self):
        super().__init__()
        lang_code = detect_lang()
        global LANG
        LANG = LANGS[lang_code]
        self.lang_code = lang_code
        self.use_sudo = True
        self.install_optional = True

        self.setWindowTitle(_("title"))
        self.setMinimumSize(520, 440)
        self.resize(560, 460)
        icon_path = os.path.expanduser("~/.local/share/icons/hicolor/256x256/apps/defendr.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QtGui.QIcon(icon_path))

        self.setStyleSheet("""
            QWizard { background: #1c1c1e; }
            QWizard QLabel { color: #f5f5f7; font-size: 13px; }
            QWizard QLabel#title { color: #ffffff; font-size: 22px; font-weight: 700; }
            QWizard QLabel#sub { color: #8e8e93; font-size: 13px; }
            QWizard QPushButton { background: #7c4dff; color: white; border: none; border-radius: 20px; padding: 8px 24px; font-size: 13px; font-weight: 600; }
            QWizard QPushButton:hover { background: #b388ff; }
            QWizard QPushButton:disabled { background: #3a3a3c; color: #8e8e93; }
            QWizard QRadioButton, QWizard QCheckBox { color: #f5f5f7; font-size: 13px; }
            QWizard QComboBox { background: #2c2c2e; color: #f5f5f7; border: 1px solid #3a3a3c; border-radius: 10px; padding: 8px 12px; font-size: 13px; }
            QWizard QProgressBar { background: #2c2c2e; border: none; border-radius: 8px; height: 8px; text-align: center; }
            QWizard QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7c4dff,stop:1 #b388ff); border-radius: 8px; }
            QWizard QListWidget { background: #242426; color: #f5f5f7; border: 1px solid #3a3a3c; border-radius: 10px; font-size: 12px; }
            QWizard QTextEdit { background: #242426; color: #f5f5f7; border: 1px solid #3a3a3c; border-radius: 10px; font-size: 12px; padding: 8px; }
            QWizard QGroupBox { color: #f5f5f7; border: 1px solid #3a3a3c; border-radius: 14px; margin-top: 10px; padding-top: 14px; font-size: 13px; }
            QWizard QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
        """)

        self.setPage(0, LangPage(self))
        self.setPage(1, FilesPage(self))
        self.setPage(2, DepsPage(self))
        self.setPage(3, SudoPage(self))
        self.setPage(4, InstallPage(self))
        self.setPage(5, DonePage(self))

        self.setStartId(0)
        self.setButtonText(QtWidgets.QWizard.NextButton, _("next"))
        self.setButtonText(QtWidgets.QWizard.BackButton, _("back"))
        self.setButtonText(QtWidgets.QWizard.CancelButton, _("cancel"))
        self.setButtonText(QtWidgets.QWizard.FinishButton, _("finish"))

        self.currentIdChanged.connect(self._on_page)

    def _on_page(self, page_id):
        self.setButtonText(QtWidgets.QWizard.NextButton, _("next"))
        self.setButtonText(QtWidgets.QWizard.BackButton, _("back"))
        self.setButtonText(QtWidgets.QWizard.CancelButton, _("cancel"))
        self.setButtonText(QtWidgets.QWizard.FinishButton, _("finish"))

class LangPage(QtWidgets.QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.wiz = parent
        self.setTitle("")
        self.setSubTitle("")
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignCenter)
        # Splash image
        splash_lbl = QtWidgets.QLabel()
        splash_lbl.setAlignment(QtCore.Qt.AlignCenter)
        if os.path.exists(SPLASH_PATH):
            pix = QtGui.QPixmap(SPLASH_PATH)
            pix = pix.scaled(400, 200, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
            splash_lbl.setPixmap(pix)
        else:
            splash_lbl.setText("⚔")
            splash_lbl.setStyleSheet("font-size: 48px; color: #b388ff;")
        layout.addWidget(splash_lbl)
        title = QtWidgets.QLabel(_("welcome"))
        title.setObjectName("title")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        sub = QtWidgets.QLabel(_("desc"))
        sub.setObjectName("sub")
        sub.setAlignment(QtCore.Qt.AlignCenter)
        sub.setWordWrap(True)
        layout.addWidget(sub)
        layout.addSpacing(16)
        layout.addWidget(QtWidgets.QLabel(_("select_lang")))
        self.combo = QtWidgets.QComboBox()
        lang_names = {"pt": "Português", "en": "English", "es": "Español",
                      "fr": "Français", "de": "Deutsch", "it": "Italiano", "ru": "Русский"}
        for code in LANGS:
            self.combo.addItem(lang_names.get(code, code), code)
        self.combo.setCurrentIndex(list(LANGS.keys()).index(detect_lang()))
        layout.addWidget(self.combo)
        layout.addStretch()
        self.setLayout(layout)

    def validatePage(self):
        code = self.combo.currentData()
        global LANG
        LANG = LANGS[code]
        self.wiz.lang_code = code
        self.wiz.setButtonText(QtWidgets.QWizard.NextButton, _("next"))
        self.wiz.setButtonText(QtWidgets.QWizard.BackButton, _("back"))
        self.wiz.setButtonText(QtWidgets.QWizard.CancelButton, _("cancel"))
        self.wiz.setButtonText(QtWidgets.QWizard.FinishButton, _("finish"))
        return True

class FilesPage(QtWidgets.QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.wiz = parent
        self.setTitle("")
        self.setSubTitle("")
        layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(_("files_title"))
        title.setObjectName("title")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        sub = QtWidgets.QLabel(_("files_desc"))
        sub.setObjectName("sub")
        sub.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(sub)
        layout.addSpacing(8)
        self.file_list = QtWidgets.QListWidget()
        layout.addWidget(self.file_list)
        layout.addStretch()
        self.setLayout(layout)

    def initializePage(self):
        self.file_list.clear()
        items = []
        for f in sorted(os.listdir(DEFENDR_DIR)):
            fp = os.path.join(DEFENDR_DIR, f)
            if f.startswith(".") or f == "__pycache__":
                continue
            is_dir = os.path.isdir(fp)
            is_exec = f == "defendr" or f == "run.sh"
            is_installer = f == "install.py"
            name = f + "/" if is_dir else f
            if is_exec:
                icon = "⚡"
                color = "#7c4dff"
                weight = "700"
                prefix = "▶  "
            elif is_installer:
                icon = "📦"
                color = "#00e676"
                weight = "600"
                prefix = "   "
            elif is_dir:
                icon = "📁"
                color = "#b0b0b0"
                weight = "400"
                prefix = "   "
            else:
                icon = "📄"
                color = "#8e8e93"
                weight = "400"
                prefix = "   "
            item = QtWidgets.QListWidgetItem(f"  {icon}  {prefix}{name}")
            item.setForeground(QtGui.QColor(color))
            fnt = item.font()
            fnt.setWeight(QtGui.QFont.Bold if weight == "700" else QtGui.QFont.Normal)
            item.setFont(fnt)
            items.append((is_exec, item))
        items.sort(key=lambda x: (not x[0], x[1].text()))
        for _, item in items:
            self.file_list.addItem(item)

    def validatePage(self):
        return True

class DepsPage(QtWidgets.QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.wiz = parent
        self.setTitle("")
        self.setSubTitle("")
        layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(_("dep_title"))
        title.setObjectName("title")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        sub = QtWidgets.QLabel(_("dep_desc"))
        sub.setObjectName("sub")
        sub.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(sub)
        layout.addSpacing(8)
        self.dep_list = QtWidgets.QListWidget()
        layout.addWidget(self.dep_list)
        self.opt_group = QtWidgets.QGroupBox(_("dep_optional"))
        self.opt_group.setStyleSheet("QGroupBox{color:#e0e0e0;border:1px solid #3d2b5e;border-radius:4px;margin-top:8px;padding-top:12px;} QGroupBox::title{subcontrol-origin:margin;left:8px;padding:0 4px;}")
        opt_l = QtWidgets.QVBoxLayout()
        self.opt_cb = QtWidgets.QCheckBox("firejail · openvpn · nmap · lsof")
        self.opt_cb.setChecked(True)
        opt_l.addWidget(self.opt_cb)
        self.opt_group.setLayout(opt_l)
        layout.addWidget(self.opt_group)
        layout.addStretch()
        self.setLayout(layout)

    def initializePage(self):
        self.dep_list.clear()
        deps = check_deps()
        for pkg, ok in deps.items():
            name = _("deps").get(pkg, pkg)
            status = _("dep_ok") if ok else _("dep_missing")
            color = "#00e676" if ok else "#ff5252"
            item = QtWidgets.QListWidgetItem(f"  {name}:  ")
            item2 = QtWidgets.QListWidgetItem(status)
            item2.setForeground(QtGui.QColor(color))
            self.dep_list.addItem(item)
            self.dep_list.addItem(item2)
        self.dep_list.addItem("")
        opt = check_optional()
        for pkg, ok in opt.items():
            name = _("opt_deps").get(pkg, pkg)
            status = _("dep_ok") if ok else _("dep_missing")
            color = "#00e676" if ok else "#ffab00"
            item = QtWidgets.QListWidgetItem(f"  {name}:  ")
            item2 = QtWidgets.QListWidgetItem(status)
            item2.setForeground(QtGui.QColor(color))
            self.dep_list.addItem(item)
            self.dep_list.addItem(item2)
        deps = check_deps()
        if not deps["PyQt5"]:
            QtWidgets.QMessageBox.critical(self, _("err_pyqt"), _("err_pyqt"))
        self.opt_cb.setText(_("dep_install"))

    def validatePage(self):
        self.wiz.install_optional = self.opt_cb.isChecked()
        deps = check_deps()
        if not deps["PyQt5"]:
            QtWidgets.QMessageBox.critical(self, _("err_pyqt"), _("err_pyqt"))
            return False
        return True

class SudoPage(QtWidgets.QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.wiz = parent
        self.setTitle("")
        layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(_("sudo_title"))
        title.setObjectName("title")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        sub = QtWidgets.QLabel(_("sudo_desc"))
        sub.setObjectName("sub")
        sub.setWordWrap(True)
        layout.addWidget(sub)
        layout.addSpacing(12)
        self.rb_yes = QtWidgets.QRadioButton(_("sudo_yes"))
        self.rb_yes.setChecked(True)
        self.rb_no = QtWidgets.QRadioButton(_("sudo_no"))
        layout.addWidget(self.rb_yes)
        layout.addWidget(self.rb_no)
        layout.addStretch()
        self.setLayout(layout)

    def validatePage(self):
        self.wiz.use_sudo = self.rb_yes.isChecked()
        return True

class InstallPage(QtWidgets.QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.wiz = parent
        self.setTitle("")
        self.setCommitPage(True)
        layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(_("install_title"))
        title.setObjectName("title")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        sub = QtWidgets.QLabel(_("install_desc"))
        sub.setObjectName("sub")
        sub.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(sub)
        layout.addSpacing(8)
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        layout.addWidget(self.progress)
        self.status = QtWidgets.QLabel("")
        self.status.setStyleSheet("color:#b0b0b0;font-size:11px;")
        layout.addWidget(self.status)
        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(120)
        layout.addWidget(self.log)
        layout.addStretch()
        self.setLayout(layout)
        self.installed = False

    def initializePage(self):
        self.wiz.setButtonText(QtWidgets.QWizard.NextButton, _("next"))
        self.progress.setValue(0)
        self.log.clear()
        self.status.setText(_("installing_icon"))
        QtCore.QTimer.singleShot(100, self._do_install)

    def _do_install(self):
        try:
            self.progress.setValue(5)
            self.log.append(_("installing_icon"))
            QtWidgets.QApplication.processEvents()
            icon_sizes = [16, 32, 48, 64, 256]
            svg_src = os.path.expanduser("~/.local/share/icons/hicolor/scalable/apps/defendr.svg")
            for size in icon_sizes:
                dst = os.path.expanduser(f"~/.local/share/icons/hicolor/{size}x{size}/apps/defendr.png")
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.exists(svg_src):
                    subprocess.run(["convert", "-background", "none", "-resize", f"{size}x{size}", svg_src, dst],
                                   capture_output=True, timeout=30)
            self.progress.setValue(25)
            QtWidgets.QApplication.processEvents()

            self.log.append(_("installing_desktop"))
            desktop_entry = f"""[Desktop Entry]
Name=DefendR
Comment=Advanced Antivirus & Security Suite
Exec={sys.executable} {DEFENDR_SCRIPT}
Icon=defendr
Terminal=false
Type=Application
Categories=Security;Utility;
StartupNotify=true
"""
            menu_path = os.path.expanduser("~/.local/share/applications/defendr.desktop")
            os.makedirs(os.path.dirname(menu_path), exist_ok=True)
            with open(menu_path, "w") as f: f.write(desktop_entry)
            os.chmod(menu_path, 0o755)
            self.progress.setValue(50)
            QtWidgets.QApplication.processEvents()

            self.log.append(_("installing_desktop2"))
            desk_path = os.path.expanduser("~/Área de trabalho/defendr.desktop")
            if not os.path.exists(desk_path):
                desk_path = os.path.expanduser("~/Desktop/defendr.desktop")
            if self.wiz.use_sudo:
                sudo_entry = f"""[Desktop Entry]
Name=DefendR (Root)
Comment=DefendR Antivirus (with root privileges)
Exec=pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY {sys.executable} {DEFENDR_SCRIPT}
Icon=defendr
Terminal=false
Type=Application
Categories=Security;Utility;
StartupNotify=true
"""
                sudo_path = os.path.expanduser("~/.local/share/applications/defendr-root.desktop")
                with open(sudo_path, "w") as f: f.write(sudo_entry)
                os.chmod(sudo_path, 0o755)
                self.log.append("  ✓ Atalho root criado")
            self.progress.setValue(60)
            QtWidgets.QApplication.processEvents()

            if self.wiz.install_optional:
                self.status.setText(_("installing_opt"))
                self.log.append(_("installing_opt"))
                to_install = []
                opt = check_optional()
                for pkg, ok in opt.items():
                    if not ok: to_install.append(pkg)
                if to_install:
                    self.log.append(f"  Instalando: {' '.join(to_install)}")
                    r = run_with_sudo(["apt", "install", "-y"] + to_install)
                    if r.returncode != 0:
                        self.log.append(f"  ⚠ {_('err_sudo_install')} {' '.join(to_install)}")
                    else:
                        self.log.append("  ✓ OK")
                else:
                    self.log.append("  Todos já instalados")
            self.progress.setValue(85)
            QtWidgets.QApplication.processEvents()

            self.log.append("  ✓ Instalação concluída")
            self.progress.setValue(100)
            self.status.setText(_("done_desc"))
            self.installed = True
            os.makedirs(os.path.expanduser("~/.defendr"), exist_ok=True)
            with open(os.path.expanduser("~/.defendr/installed"), "w") as f:
                f.write(f"lang={self.wiz.lang_code}\nsudo={self.wiz.use_sudo}\n")
        except Exception as e:
            self.log.append(f"  ✗ Erro: {e}")
            self.installed = False

    def validatePage(self):
        return self.installed

    def isComplete(self):
        return self.installed

class DonePage(QtWidgets.QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.wiz = parent
        self.setTitle("")
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignCenter)
        splash_lbl = QtWidgets.QLabel()
        splash_lbl.setAlignment(QtCore.Qt.AlignCenter)
        if os.path.exists(SPLASH_PATH):
            pix = QtGui.QPixmap(SPLASH_PATH)
            pix = pix.scaled(300, 150, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
            splash_lbl.setPixmap(pix)
        else:
            splash_lbl.setText("⚔")
            splash_lbl.setStyleSheet("font-size: 48px; color: #b388ff;")
        layout.addWidget(splash_lbl)
        title = QtWidgets.QLabel(_("done_title"))
        title.setObjectName("title")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)
        sub = QtWidgets.QLabel(_("done_desc"))
        sub.setObjectName("sub")
        sub.setAlignment(QtCore.Qt.AlignCenter)
        sub.setWordWrap(True)
        layout.addWidget(sub)
        layout.addSpacing(16)
        self.start_cb = QtWidgets.QCheckBox(_("start_now"))
        self.start_cb.setChecked(True)
        layout.addWidget(self.start_cb)
        layout.addStretch()
        self.setLayout(layout)

    def initializePage(self):
        self.wiz.setButtonText(QtWidgets.QWizard.FinishButton, _("finish"))

def main():
    global HAS_PYQT
    if not HAS_PYQT:
        print("PyQt5 nao encontrado. Tentando instalar automaticamente...")
        r = subprocess.run(["sudo", "apt", "install", "-y", "python3-pyqt5"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print("PyQt5 instalado com sucesso!")
            import importlib
            importlib.invalidate_caches()
            try:
                import PyQt5
                HAS_PYQT = True
            except Exception as e:
                print(f"Erro ao carregar PyQt5: {e}")
                sys.exit(1)
        else:
            print("Falha ao instalar PyQt5. Instale manualmente:")
            print("  sudo apt install python3-pyqt5")
            if r.stderr:
                print(f"Erro: {r.stderr}")
            sys.exit(1)
    from PyQt5 import QtWidgets, QtCore, QtGui
    app = QtWidgets.QApplication(sys.argv)
    wizard = InstallWizard()
    if wizard.exec_() == QtWidgets.QDialog.Accepted:
        if hasattr(wizard, "start_cb") and wizard.start_cb.isChecked():
            subprocess.Popen([sys.executable, DEFENDR_SCRIPT])
    sys.exit(0)

if __name__ == "__main__":
    main()
