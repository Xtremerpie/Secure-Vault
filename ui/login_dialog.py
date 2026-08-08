"""
ui/login_dialog.py — the startup dialog: unlock an existing vault or
create a new one.
"""

from __future__ import annotations

import os

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QFileDialog, QMessageBox
)

from core.vault import VaultEngine, WrongPassword, VaultError


class LoginDialog(QDialog):
    def __init__(self, parent=None, default_vaults_dir: str = ""):
        super().__init__(parent)
        self.setWindowTitle("SecureVault")
        self.setMinimumWidth(420)
        self.engine: VaultEngine | None = None
        self.default_vaults_dir = default_vaults_dir

        layout = QVBoxLayout(self)
        title = QLabel("<h2>SecureVault</h2>")
        subtitle = QLabel("Your files, encrypted at rest, normal everywhere else.")
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_unlock_tab(), "Unlock vault")
        tabs.addTab(self._build_recovery_tab(), "Unlock with recovery key")
        tabs.addTab(self._build_create_tab(), "New vault")
        layout.addWidget(tabs)

    # ---------- Unlock ----------

    def _build_unlock_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self.unlock_path = QLineEdit()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_existing)
        path_row = QHBoxLayout()
        path_row.addWidget(self.unlock_path)
        path_row.addWidget(browse_btn)
        form.addRow("Vault folder:", path_row)

        self.unlock_password = QLineEdit()
        self.unlock_password.setEchoMode(QLineEdit.Password)
        self.unlock_password.returnPressed.connect(self._do_unlock)
        form.addRow("Password:", self.unlock_password)

        unlock_btn = QPushButton("Unlock")
        unlock_btn.clicked.connect(self._do_unlock)
        form.addRow(unlock_btn)

        return w

    def _browse_existing(self):
        path = QFileDialog.getExistingDirectory(self, "Select vault folder", self.default_vaults_dir)
        if path:
            self.unlock_path.setText(path)

    def _do_unlock(self):
        path = self.unlock_path.text().strip()
        password = self.unlock_password.text()
        if not path or not password:
            QMessageBox.warning(self, "Missing info", "Choose a vault folder and enter your password.")
            return
        try:
            self.engine = VaultEngine.unlock(path, password)
            self.accept()
        except WrongPassword:
            QMessageBox.critical(self, "Incorrect password", "That password doesn't match this vault.")
        except VaultError as e:
            QMessageBox.critical(self, "Error", str(e))

    # ---------- Recovery key ----------

    def _build_recovery_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        note = QLabel("Use this if you've forgotten your password but saved\nthe recovery key shown when the vault was created.")
        note.setStyleSheet("color: #888;")
        form.addRow(note)

        self.recovery_path = QLineEdit()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_recovery)
        path_row = QHBoxLayout()
        path_row.addWidget(self.recovery_path)
        path_row.addWidget(browse_btn)
        form.addRow("Vault folder:", path_row)

        self.recovery_key_input = QLineEdit()
        self.recovery_key_input.setPlaceholderText("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX")
        self.recovery_key_input.returnPressed.connect(self._do_recovery_unlock)
        form.addRow("Recovery key:", self.recovery_key_input)

        unlock_btn = QPushButton("Unlock with recovery key")
        unlock_btn.clicked.connect(self._do_recovery_unlock)
        form.addRow(unlock_btn)

        return w

    def _browse_recovery(self):
        path = QFileDialog.getExistingDirectory(self, "Select vault folder", self.default_vaults_dir)
        if path:
            self.recovery_path.setText(path)

    def _do_recovery_unlock(self):
        path = self.recovery_path.text().strip()
        recovery_key = self.recovery_key_input.text().strip()
        if not path or not recovery_key:
            QMessageBox.warning(self, "Missing info", "Choose a vault folder and enter the recovery key.")
            return
        try:
            self.engine = VaultEngine.unlock_with_recovery(path, recovery_key)
            QMessageBox.information(
                self, "Unlocked with recovery key",
                "You're in. Consider setting a new password from the toolbar "
                "(Change Password...) since you needed the recovery key."
            )
            self.accept()
        except WrongPassword:
            QMessageBox.critical(self, "Incorrect recovery key", "That recovery key doesn't match this vault.")
        except VaultError as e:
            QMessageBox.critical(self, "Error", str(e))

    # ---------- Create ----------

    def _build_create_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self.create_path = QLineEdit()
        browse_btn = QPushButton("Choose location...")
        browse_btn.clicked.connect(self._browse_new)
        path_row = QHBoxLayout()
        path_row.addWidget(self.create_path)
        path_row.addWidget(browse_btn)
        form.addRow("New vault folder:", path_row)

        self.create_password = QLineEdit()
        self.create_password.setEchoMode(QLineEdit.Password)
        form.addRow("Password:", self.create_password)

        self.create_password_confirm = QLineEdit()
        self.create_password_confirm.setEchoMode(QLineEdit.Password)
        self.create_password_confirm.returnPressed.connect(self._do_create)
        form.addRow("Confirm password:", self.create_password_confirm)

        create_btn = QPushButton("Create vault")
        create_btn.clicked.connect(self._do_create)
        form.addRow(create_btn)

        return w

    def _browse_new(self):
        base = QFileDialog.getExistingDirectory(self, "Choose parent folder", self.default_vaults_dir)
        if base:
            self.create_path.setText(os.path.join(base, "MyVault.svault"))

    def _do_create(self):
        path = self.create_path.text().strip()
        pw = self.create_password.text()
        pw2 = self.create_password_confirm.text()

        if not path or not pw:
            QMessageBox.warning(self, "Missing info", "Choose a location and set a password.")
            return
        if pw != pw2:
            QMessageBox.warning(self, "Password mismatch", "Passwords don't match.")
            return
        if len(pw) < 6:
            QMessageBox.warning(self, "Weak password", "Use at least 6 characters.")
            return

        try:
            self.engine = VaultEngine.create(path, pw)
            self.accept()
        except VaultError as e:
            QMessageBox.critical(self, "Error", str(e))
