#!/usr/bin/env python3
"""DefendR Uninstaller - removes all files and system entries"""

import os, sys, subprocess, shutil, configparser

DEFENDR_DIR = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")

def get_desktop_dir():
    user_dirs = os.path.join(HOME, ".config/user-dirs.dirs")
    if os.path.exists(user_dirs):
        cp = configparser.ConfigParser()
        try:
            cp.read(user_dirs)
            val = cp.get("User Dirs", "XDG_DESKTOP_DIR", fallback="").strip('"')
            if val:
                return os.path.expandvars(val)
        except Exception:
            pass
    for d in [os.path.join(HOME, "Área de trabalho"), os.path.join(HOME, "Desktop"),
              os.path.join(HOME, "桌面"), os.path.join(HOME, "Escritorio")]:
        if os.path.isdir(d):
            return d
    return os.path.join(HOME, "Desktop")

def remove_items():
    removed = []

    # Icons
    icon_base = os.path.join(HOME, ".local/share/icons/hicolor")
    for size in os.listdir(icon_base) if os.path.isdir(icon_base) else []:
        icon_file = os.path.join(icon_base, size, "apps", "defendr.png")
        if os.path.exists(icon_file):
            os.remove(icon_file)
            removed.append(icon_file)
    svg_icon = os.path.join(icon_base, "scalable/apps/defendr.svg")
    if os.path.exists(svg_icon):
        os.remove(svg_icon)
        removed.append(svg_icon)

    # Desktop entries
    apps_dir = os.path.join(HOME, ".local/share/applications")
    for f in ["defendr.desktop", "defendr-root.desktop"]:
        fp = os.path.join(apps_dir, f)
        if os.path.exists(fp):
            os.remove(fp)
            removed.append(fp)

    # Desktop shortcut
    desk_dir = get_desktop_dir()
    desk_path = os.path.join(desk_dir, "defendr.desktop")
    if os.path.exists(desk_path):
        os.remove(desk_path)
        removed.append(desk_path)

    # Sudo helper script
    sudo_script = "/usr/local/bin/defendr-sudo.sh"
    if os.path.exists(sudo_script):
        try:
            os.remove(sudo_script)
            removed.append(sudo_script)
        except PermissionError:
            subprocess.run(["sudo", "rm", sudo_script], capture_output=True)
            removed.append(f"{sudo_script} (sudo)")

    # Config & quarantine dirs
    for d in [os.path.join(HOME, ".defendr"), os.path.join(HOME, ".defendr_quarantine")]:
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
            removed.append(d)

    # Stop flag
    stop_flag = os.path.join(DEFENDR_DIR, ".defendr_stop")
    if os.path.exists(stop_flag):
        os.remove(stop_flag)
        removed.append(stop_flag)

    return removed

def main():
    from PyQt5 import QtWidgets, QtCore, QtGui

    app = QtWidgets.QApplication(sys.argv)

    resp = QtWidgets.QMessageBox.question(
        None, "Desinstalar DefendR",
        "Tem certeza que deseja desinstalar o DefendR?\n\n"
        "Todos os arquivos serão removidos:\n"
        f"• {DEFENDR_DIR}/ (código fonte)\n"
        "• Ícones e atalhos do sistema\n"
        "• Configurações (~/.defendr)\n"
        "• Quarentena (~/.defendr_quarantine)\n\n"
        "Esta ação não pode ser desfeita.",
        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        QtWidgets.QMessageBox.No,
    )
    if resp != QtWidgets.QMessageBox.Yes:
        return

    # Remove system files
    removed = remove_items()

    # Remove DefendR source directory
    try:
        shutil.rmtree(DEFENDR_DIR, ignore_errors=True)
        removed.append(DEFENDR_DIR)
    except Exception as e:
        QtWidgets.QMessageBox.warning(None, "Aviso",
            f"Não foi possível remover {DEFENDR_DIR}:\n{e}\n\nRemova manualmente.")

    msg = "DefendR desinstalado com sucesso!\n\n"
    msg += f"{len(removed)} itens removidos."
    QtWidgets.QMessageBox.information(None, "Desinstalação Concluída", msg)
    sys.exit(0)

if __name__ == "__main__":
    main()
