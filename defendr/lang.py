# Translation system - 7 languages
import os
from defendr.constants import CONFIG_DIR

APP_LANGS = {
    "pt": {
        "DefendR - Advanced Protection": "DefendR - Protecao Avancada",
        "Dashboard": "Dashboard",
        "📊  Dashboard": "📊  Dashboard",
        "⚙  Process Monitor": "⚙  Monitor de Processos",
        "🔍  File Scanner": "🔍  Scanner de Arquivos",
        "🛡  Real-Time Protection": "🛡  Protecao em Tempo Real",
        "🔒  Firewall": "🔒  Firewall",
        "🌐  Network": "🌐  Rede",
        "📦  Quarantine": "📦  Quarentena",
        "🧰  Tools": "🧰  Ferramentas",
        "🔧  Settings": "🔧  Configuracoes",
        "▶ Start Real-Time Protection": "▶ Iniciar Protecao",
        "⏹ Stop Real-Time Protection": "⏹ Parar Protecao",
        "▶ Start Ransomware Detection": "▶ Iniciar Anti-Ransomware",
        "⏹ Stop Ransomware Detection": "⏹ Parar Anti-Ransomware",
        "▶ Start Webcam Monitor": "▶ Iniciar Webcam",
        "⏹ Stop Webcam Monitor": "⏹ Parar Webcam",
        "🔴 Block Webcam": "🔴 Bloquear Webcam",
        "🟢 Unblock Webcam": "🟢 Desbloquear Webcam",
        "Block": "Bloquear",
        "Unblock": "Desbloquear",
        "Check URL": "Verificar URL",
        "🛡 Enable Firewall": "🛡 Ativar Firewall",
        "Disable Firewall": "Desativar Firewall",
        "🔄 Flush Rules": "🔄 Limpar Regras",
        "Block Port": "Bloquear Porta",
        "Allow Port": "Liberar Porta",
        "🔄 Refresh Rules": "🔄 Atualizar Regras",
        "▶ Start": "▶ Iniciar",
        "⏹ Stop": "⏹ Parar",
        "🔍 ARP Scan Network": "🔍 Varredura ARP",
        "📡 Router Info": "📡 Info Roteador",
        "📡 Scan Router": "📡 Escanear Roteador",
        "▶ Start Continuous Monitor": "▶ Monitor Continuo",
        "⏹ Stop Monitoring": "⏹ Parar Monitor",
        "📂 Add Config": "📂 Adicionar Config",
        "▶ Connect": "▶ Conectar",
        "⏹ Disconnect": "⏹ Desconectar",
        "Reset to Default": "Restaurar Padrao",
        "🔒 Enable DNSSEC": "🔒 Ativar DNSSEC",
        "🔄 Refresh": "🔄 Atualizar",
        "🗑 Delete All": "🗑 Excluir Tudo",
        "📁 Select File & Run": "📁 Selecionar e Executar",
        "🔍 Run Rootkit Scan": "🔍 Escanear Rootkit",
        "🔓 Unlock Vault": "🔓 Destravar Cofre",
        "🔒 Lock": "🔒 Travar",
        "💾 Save Entry": "💾 Salvar",
        "➕ Add": "➕ Adicionar",
        "📁 Shred File": "📁 Destruir Arquivo",
        "📂 Shred Folder": "📂 Destruir Pasta",
        "🧹 Wipe Free Space": "🧹 Limpar Espaco Livre",
        "🧹 Run Cleanup": "🧹 Executar Limpeza",
        "👁 Preview Cleanup": "👁 Visualizar",
        "🔄 Check for Updates": "🔄 Verificar Atualizacoes",
        "📥 Install All Updates": "📥 Instalar Tudo",
        "🔍 Check for Updates": "🔍 Verificar Atualizacoes",
        "Enable Game Mode": "Ativar Game Mode",
        "Disable Game Mode": "Desativar Game Mode",
        "Open DefendR": "Abrir DefendR",
        "Quit": "Sair",
        "Game Mode": "Game Mode",
        "Protected by DefendR": "Protegido por DefendR",
        "No threats": "Nenhuma ameaca",
        "threat(s) found": "ameaca(s) encontrada(s)",
        "Run with sudo for full firewall and network monitoring.": "Execute com sudo para monitoramento completo de firewall e rede.",
        "Protecao continua ativa em segundo plano": "Protecao continua ativa em segundo plano",
        "DefendR": "DefendR",
        "Status: Stopped": "Status: Parado",
        "Status: Active": "Status: Ativo",
    },
    "en": {},
    "es": {
        "DefendR - Advanced Protection": "DefendR - Proteccion Avanzada",
        "📊  Dashboard": "📊  Panel",
        "🔍  File Scanner": "🔍  Escaner",
        "🛡  Real-Time Protection": "🛡  Proteccion en Tiempo Real",
        "🔒  Firewall": "🔒  Cortafuegos",
        "🌐  Network": "🌐  Red",
        "📦  Quarantine": "📦  Cuarentena",
        "🧰  Tools": "🧰  Herramientas",
        "🔧  Settings": "🔧  Ajustes",
        "▶ Start": "▶ Iniciar",
        "⏹ Stop": "⏹ Parar",
        "Block": "Bloquear",
        "Unblock": "Desbloquear",
        "Open DefendR": "Abrir DefendR",
        "Quit": "Salir",
    },
    "fr": {
        "DefendR - Advanced Protection": "DefendR - Protection Avancee",
        "📊  Dashboard": "📊  Tableau",
        "🔍  File Scanner": "🔍  Scanner",
        "🛡  Real-Time Protection": "🛡  Protection Temps Reel",
        "🔒  Firewall": "🔒  Pare-feu",
        "🌐  Network": "🌐  Reseau",
        "📦  Quarantine": "📦  Quarantaine",
        "🧰  Tools": "🧰  Outils",
        "🔧  Settings": "🔧  Parametres",
        "Block": "Bloquer",
        "Unblock": "Debloquer",
        "Open DefendR": "Ouvrir DefendR",
        "Quit": "Quitter",
    },
    "de": {
        "DefendR - Advanced Protection": "DefendR - Erweiterter Schutz",
        "📊  Dashboard": "📊  Ubersicht",
        "🔍  File Scanner": "🔍  Scanner",
        "🛡  Real-Time Protection": "🛡  Echtzeitschutz",
        "🔒  Firewall": "🔒  Firewall",
        "🌐  Network": "🌐  Netzwerk",
        "📦  Quarantine": "📦  Quarantane",
        "🧰  Tools": "🧰  Werkzeuge",
        "🔧  Settings": "🔧  Einstellungen",
        "Block": "Sperren",
        "Unblock": "Entsperren",
        "Open DefendR": "DefendR offnen",
        "Quit": "Beenden",
    },
    "it": {
        "DefendR - Advanced Protection": "DefendR - Protezione Avanzata",
        "📊  Dashboard": "📊  Dashboard",
        "🔍  File Scanner": "🔍  Scanner",
        "🛡  Real-Time Protection": "🛡  Protezione in Tempo Reale",
        "🔒  Firewall": "🔒  Firewall",
        "🌐  Network": "🌐  Rete",
        "📦  Quarantine": "📦  Quarantena",
        "🧰  Tools": "🧰  Strumenti",
        "🔧  Settings": "🔧  Impostazioni",
        "Block": "Blocca",
        "Unblock": "Sblocca",
        "Open DefendR": "Apri DefendR",
        "Quit": "Esci",
    },
    "ru": {
        "DefendR - Advanced Protection": "DefendR - Rasshirennaya zashchita",
        "📊  Dashboard": "📊  Panel",
        "🔍  File Scanner": "🔍  Skaner",
        "🛡  Real-Time Protection": "🛡  Zashchita v realnom vremeni",
        "🔒  Firewall": "🔒  Faivol",
        "🌐  Network": "🌐  Set",
        "📦  Quarantine": "📦  Karantin",
        "🧰  Tools": "🧰  Instrumenty",
        "🔧  Settings": "🔧  Nastroiki",
        "Block": "Blokirovat",
        "Unblock": "Razblokirovat",
        "Open DefendR": "Otkryt DefendR",
        "Quit": "Vyiti",
    },
}

def detect_app_lang():
    installed_file = os.path.join(CONFIG_DIR, "installed")
    if os.path.exists(installed_file):
        try:
            with open(installed_file) as f:
                for line in f:
                    if line.startswith("lang="):
                        code = line.strip().split("=", 1)[1]
                        if code in APP_LANGS: return code
        except Exception: pass
    lang = os.environ.get("LANG", "pt").split("_")[0]
    return lang if lang in APP_LANGS else "en"

CURRENT_LANG = detect_app_lang()


def _(text):
    return APP_LANGS.get(CURRENT_LANG, APP_LANGS["en"]).get(text, text)

def set_language(code):
    global CURRENT_LANG
    if code in APP_LANGS:
        CURRENT_LANG = code
        return True
    return False
