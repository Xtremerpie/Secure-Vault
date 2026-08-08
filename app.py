"""
app.py — SecureVault V2 entry point.

Run with:
    pip install -r requirements.txt
    python app.py
"""

import os
import sys

from PySide6.QtWidgets import QApplication

from ui.login_dialog import LoginDialog
from ui.main_window import MainWindow

STORAGE_VAULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage", "vaults")


def main():
    os.makedirs(STORAGE_VAULTS_DIR, exist_ok=True)
    app = QApplication(sys.argv)
    app.setApplicationName("SecureVault")

    login = LoginDialog(default_vaults_dir=STORAGE_VAULTS_DIR)
    if login.exec() != LoginDialog.Accepted or login.engine is None:
        sys.exit(0)

    window = MainWindow(login.engine)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
