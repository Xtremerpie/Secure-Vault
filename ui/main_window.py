"""
ui/main_window.py — the Vault Explorer window. Looks and behaves like a
normal file manager; every read/write underneath goes through the
encrypted VaultEngine + TempWorkspace + VaultWatcher trio in core/.
"""

from __future__ import annotations

import io
import os
from datetime import datetime

from PySide6.QtCore import Qt, QUrl, QTimer, QObject, Signal, QByteArray, QMimeData, QPointF
from PySide6.QtGui import QDesktopServices, QAction, QDrag, QPixmap, QImage
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem, QLineEdit, QToolBar, QLabel, QMenu, QInputDialog,
    QMessageBox, QFileDialog, QStatusBar, QTextEdit, QStackedWidget,
    QDialog, QListWidget, QListWidgetItem, QPushButton, QAbstractItemView
)

from core.vault import VaultEngine, VaultError, PathExists
from core.workspace import TempWorkspace
from core.watcher import VaultWatcher

try:
    from PySide6.QtPdf import QPdfDocument
    HAVE_QTPDF = True
except ImportError:
    HAVE_QTPDF = False

FOLDER_ICON = "\U0001F4C1"   # (folder)
FILE_ICONS = {
    "txt": "\U0001F4C4", "docx": "\U0001F4D8", "doc": "\U0001F4D8",
    "pdf": "\U0001F4D5", "png": "\U0001F5BC", "jpg": "\U0001F5BC",
    "jpeg": "\U0001F5BC", "gif": "\U0001F5BC", "mp4": "\U0001F3A5",
    "mov": "\U0001F3A5", "mp3": "\U0001F3B5", "wav": "\U0001F3B5",
}
DEFAULT_FILE_ICON = "\U0001F4C4"
TEXT_PREVIEW_EXTS = {"txt", "md", "json", "py", "csv", "log", "yml", "yaml"}
IMAGE_PREVIEW_EXTS = {"png", "jpg", "jpeg", "gif", "bmp"}
PDF_PREVIEW_EXTS = {"pdf"}

AUTO_LOCK_IDLE_MS = 10 * 60 * 1000  # 10 minutes

INTERNAL_MOVE_MIME = "application/x-securevault-path"


def human_size(n: int) -> str:
    n = float(n)
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class _SyncSignal(QObject):
    """The file watcher fires its callback from a background thread
    (threading.Timer). Qt widgets may only be touched from the GUI thread,
    so the callback emits this signal instead of calling into the UI
    directly — Qt marshals the emit across threads via a queued
    connection automatically."""
    synced = Signal(str)


class FileListWidget(QTreeWidget):
    """The right-hand pane — behaves like a normal file list: accepts
    drag-and-drop from the OS (import), and can itself be dragged from to
    move items into a folder (either in the tree, or onto a folder row
    here)."""

    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDropIndicatorShown(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._drag_start_pos = None

    # --- starting an internal drag (to move items) ---

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_start_pos = event.position()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if (event.buttons() & Qt.LeftButton) and self._drag_start_pos is not None:
            distance = (event.position() - self._drag_start_pos).manhattanLength()
            if distance >= 12:
                self._start_internal_drag()
                self._drag_start_pos = None
                return
        super().mouseMoveEvent(event)

    def _start_internal_drag(self):
        items = self.selectedItems()
        if not items:
            return
        paths = [item.data(0, Qt.UserRole) for item in items]
        mime = QMimeData()
        mime.setData(INTERNAL_MOVE_MIME, QByteArray("\n".join(paths).encode("utf-8")))
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.exec(Qt.MoveAction)

    # --- accepting drops (either OS files, or an internal move onto a folder row) ---

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasFormat(INTERNAL_MOVE_MIME):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasFormat(INTERNAL_MOVE_MIME):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        mime = event.mimeData()
        if mime.hasFormat(INTERNAL_MOVE_MIME):
            target_item = self.itemAt(event.position().toPoint())
            dest_folder = self.main_window.current_folder
            if target_item is not None and target_item.data(0, Qt.UserRole + 1) == "folder":
                dest_folder = target_item.data(0, Qt.UserRole)
            paths = bytes(mime.data(INTERNAL_MOVE_MIME)).decode("utf-8").split("\n")
            self.main_window.move_paths(paths, dest_folder)
            event.acceptProposedAction()
        elif mime.hasUrls():
            local_paths = [url.toLocalFile() for url in mime.urls() if url.isLocalFile()]
            self.main_window.import_external_paths(local_paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class VaultTreeWidget(QTreeWidget):
    """The left-hand folder tree — also accepts an internal-move drop to
    relocate files/folders."""

    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(INTERNAL_MOVE_MIME):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat(INTERNAL_MOVE_MIME):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        mime = event.mimeData()
        if mime.hasFormat(INTERNAL_MOVE_MIME):
            target_item = self.itemAt(event.position().toPoint())
            if target_item is None:
                return
            dest_folder = target_item.data(0, Qt.UserRole)
            paths = bytes(mime.data(INTERNAL_MOVE_MIME)).decode("utf-8").split("\n")
            self.main_window.move_paths(paths, dest_folder)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class VersionHistoryDialog(QDialog):
    def __init__(self, parent, engine: VaultEngine, vault_path: str):
        super().__init__(parent)
        self.engine = engine
        self.vault_path = vault_path
        self.restored = False

        self.setWindowTitle(f"Version history — {os.path.basename(vault_path)}")
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)

        self.list = QListWidget()
        layout.addWidget(self.list)
        self._populate()

        btn_row = QHBoxLayout()
        restore_btn = QPushButton("Restore selected version")
        restore_btn.clicked.connect(self._restore_selected)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(restore_btn)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    def _populate(self):
        self.list.clear()
        versions = self.engine.list_versions(self.vault_path)
        if not versions:
            self.list.addItem("No earlier versions yet — edit and save this file at least once.")
            return
        for v in versions:
            when = datetime.fromtimestamp(v["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            item = QListWidgetItem(f"{when}  ({human_size(v['size'])})")
            item.setData(Qt.UserRole, v["version_id"])
            self.list.addItem(item)

    def _restore_selected(self):
        item = self.list.currentItem()
        if item is None or item.data(Qt.UserRole) is None:
            return
        version_id = item.data(Qt.UserRole)
        confirm = QMessageBox.question(
            self, "Restore version",
            "Restore this version as the current content? "
            "(The current content will itself be saved as a new version first.)"
        )
        if confirm == QMessageBox.Yes:
            self.engine.restore_version(self.vault_path, version_id)
            self.restored = True
            self.accept()


class MainWindow(QMainWindow):
    def __init__(self, engine: VaultEngine):
        super().__init__()
        self.engine = engine
        self.workspace = TempWorkspace(engine)

        self._sync_signal = _SyncSignal()
        self._sync_signal.synced.connect(self._on_file_synced)

        self.watcher = VaultWatcher(self.workspace, on_synced=self._sync_signal.synced.emit)
        self.watcher.start()

        self.current_folder = "/"
        self.showing_search_results = False

        self.setWindowTitle(f"SecureVault — {os.path.basename(engine.vault_dir)}")
        self.resize(1040, 640)

        self._build_ui()
        self._refresh_tree()
        self._refresh_file_list()

        self._idle_timer = QTimer(self)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.timeout.connect(self._auto_lock)
        self._reset_idle_timer()

        if engine.recovery_key:
            QTimer.singleShot(200, self._show_recovery_key_once)

    # ---------- UI construction ----------

    def _build_ui(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        def add_action(text, handler):
            act = QAction(text, self)
            act.triggered.connect(handler)
            toolbar.addAction(act)
            return act

        add_action("New Folder", self.action_new_folder)
        add_action("New File", self.action_new_file)
        toolbar.addSeparator()
        add_action("Import Files...", self.action_import_files)
        add_action("Import Folder...", self.action_import_folder)
        add_action("Export...", self.action_export_selected)
        toolbar.addSeparator()
        add_action("Rename", self.action_rename_selected)
        add_action("Delete", self.action_delete_selected)
        add_action("Version History...", self.action_version_history)
        toolbar.addSeparator()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search this vault...")
        self.search_box.setFixedWidth(200)
        self.search_box.returnPressed.connect(self.action_search)
        toolbar.addWidget(self.search_box)

        toolbar.addSeparator()
        add_action("Change Password...", self.action_change_password)
        add_action("New Recovery Key...", self.action_regenerate_recovery_key)
        toolbar.addSeparator()
        lock_action = add_action("Lock Vault", self.action_lock)
        toolbar.widgetForAction(lock_action).setStyleSheet("font-weight: bold;")

        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(6, 6, 6, 6)

        path_row = QHBoxLayout()
        up_toolbar = QToolBar()
        self.up_btn = QAction("\u2191 Up", self)
        self.up_btn.triggered.connect(self.action_go_up)
        up_toolbar.addAction(self.up_btn)
        self.path_label = QLabel("/")
        self.path_label.setStyleSheet("font-family: monospace; padding: 4px;")
        path_row.addWidget(up_toolbar)
        path_row.addWidget(self.path_label)
        path_row.addStretch()
        outer.addLayout(path_row)

        splitter = QSplitter(Qt.Horizontal)

        self.tree = VaultTreeWidget(self)
        self.tree.setHeaderLabel("Vault")
        self.tree.itemClicked.connect(self._on_tree_item_clicked)
        splitter.addWidget(self.tree)

        self.file_list = FileListWidget(self)
        self.file_list.setHeaderLabels(["Name", "Type", "Size", "Modified"])
        self.file_list.setColumnWidth(0, 260)
        self.file_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.file_list.itemClicked.connect(self._on_item_clicked)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self._show_context_menu)
        splitter.addWidget(self.file_list)

        self.preview = QStackedWidget()
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_image = QLabel()
        self.preview_image.setAlignment(Qt.AlignCenter)
        self.preview_empty = QLabel("Select a file to preview")
        self.preview_empty.setAlignment(Qt.AlignCenter)
        self.preview_empty.setStyleSheet("color: #888;")
        self.preview.addWidget(self.preview_empty)
        self.preview.addWidget(self.preview_text)
        self.preview.addWidget(self.preview_image)
        splitter.addWidget(self.preview)

        splitter.setSizes([220, 480, 300])
        outer.addWidget(splitter)

        self.setCentralWidget(central)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self._set_status(f"Unlocked — {engine_dir_display(self.engine.vault_dir)}")

    def _set_status(self, text: str):
        self.status.showMessage(text, 6000)

    # ---------- recovery key ----------

    def _show_recovery_key_once(self):
        key = self.engine.recovery_key
        QMessageBox.information(
            self, "Save your recovery key",
            "This vault has a recovery key that can unlock it if you ever "
            "forget your password. It will only be shown once — write it "
            "down somewhere safe now:\n\n"
            f"{key}\n\n"
            "Anyone with this key can unlock the vault, so store it like a "
            "password, not like a hint."
        )
        self.engine.recovery_key = None  # clear from memory once acknowledged

    def action_change_password(self):
        new_pw, ok = QInputDialog.getText(self, "Change password", "New password:", QLineEdit.Password)
        if not ok or not new_pw:
            return
        if len(new_pw) < 6:
            QMessageBox.warning(self, "Weak password", "Use at least 6 characters.")
            return
        confirm, ok = QInputDialog.getText(self, "Change password", "Confirm new password:", QLineEdit.Password)
        if not ok or confirm != new_pw:
            QMessageBox.warning(self, "Mismatch", "Passwords didn't match — password not changed.")
            return
        self.engine.change_password(new_pw)
        self._set_status("Password changed.")

    def action_regenerate_recovery_key(self):
        confirm = QMessageBox.question(
            self, "New recovery key",
            "This replaces the vault's recovery key — the old one will stop working. Continue?"
        )
        if confirm != QMessageBox.Yes:
            return
        new_key = self.engine.regenerate_recovery_key()
        QMessageBox.information(
            self, "New recovery key",
            f"Your new recovery key (write it down now, it won't be shown again):\n\n{new_key}"
        )
        self.engine.recovery_key = None

    # ---------- idle / auto-lock ----------

    def _reset_idle_timer(self):
        self._idle_timer.start(AUTO_LOCK_IDLE_MS)

    def _auto_lock(self):
        QMessageBox.information(self, "Auto-locked", "Vault auto-locked after being idle.")
        self.action_lock()

    def eventFilter(self, obj, event):
        self._reset_idle_timer()
        return super().eventFilter(obj, event)

    # ---------- tree (folder hierarchy) ----------

    def _refresh_tree(self):
        self.tree.clear()
        root_item = QTreeWidgetItem([f"{FOLDER_ICON} / (root)"])
        root_item.setData(0, Qt.UserRole, "/")
        root_item.setData(0, Qt.UserRole + 1, "folder")
        self.tree.addTopLevelItem(root_item)
        self._populate_tree_children(root_item, "/")
        self.tree.expandAll()

    def _populate_tree_children(self, parent_item: QTreeWidgetItem, path: str):
        try:
            children = self.engine.list_dir(path)
        except VaultError:
            return
        for child in children:
            if child["type"] != "folder":
                continue
            child_path = f"{path.rstrip('/')}/{child['name']}"
            item = QTreeWidgetItem([f"{FOLDER_ICON} {child['name']}"])
            item.setData(0, Qt.UserRole, child_path)
            item.setData(0, Qt.UserRole + 1, "folder")
            parent_item.addChild(item)
            self._populate_tree_children(item, child_path)

    def _on_tree_item_clicked(self, item: QTreeWidgetItem, _col: int):
        path = item.data(0, Qt.UserRole)
        self.current_folder = path
        self.showing_search_results = False
        self._refresh_file_list()
        self._reset_idle_timer()

    # ---------- file list (current folder contents) ----------

    def _refresh_file_list(self):
        self.path_label.setText(self.current_folder)
        self.file_list.clear()
        try:
            children = self.engine.list_dir(self.current_folder)
        except VaultError as e:
            self._set_status(str(e))
            return

        for child in children:
            self._add_file_row(child, self.current_folder)

    def _add_file_row(self, node: dict, parent_path: str, full_path_override: str | None = None):
        full_path = full_path_override or f"{parent_path.rstrip('/')}/{node['name']}"
        if node["type"] == "folder":
            item = QTreeWidgetItem([f"{FOLDER_ICON} {node['name']}", "Folder", "", ""])
        else:
            icon = FILE_ICONS.get(node.get("ext", "").lower(), DEFAULT_FILE_ICON)
            size = human_size(node.get("size", 0))
            mtime = node.get("mtime")
            mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime else ""
            item = QTreeWidgetItem([f"{icon} {node['name']}", node.get("ext", "").upper() or "File", size, mtime_str])
        item.setData(0, Qt.UserRole, full_path)
        item.setData(0, Qt.UserRole + 1, node["type"])
        self.file_list.addTopLevelItem(item)
        return item

    def _selected_paths(self) -> list[tuple[str, str]]:
        out = []
        for item in self.file_list.selectedItems():
            out.append((item.data(0, Qt.UserRole), item.data(0, Qt.UserRole + 1)))
        return out

    def _on_item_clicked(self, item: QTreeWidgetItem, _col: int):
        self._reset_idle_timer()
        path = item.data(0, Qt.UserRole)
        node_type = item.data(0, Qt.UserRole + 1)
        if node_type != "file":
            self.preview.setCurrentWidget(self.preview_empty)
            return
        self._show_preview(path)

    def _on_item_double_clicked(self, item: QTreeWidgetItem, _col: int):
        self._reset_idle_timer()
        path = item.data(0, Qt.UserRole)
        node_type = item.data(0, Qt.UserRole + 1)
        if node_type == "folder":
            self.current_folder = path
            self.showing_search_results = False
            self._refresh_file_list()
        else:
            self.open_file(path)

    def open_file(self, vault_path: str):
        try:
            local_path = self.workspace.open_file(vault_path)
        except VaultError as e:
            QMessageBox.critical(self, "Error", str(e))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(local_path))
        self._set_status(f"Opened {vault_path} — changes auto-sync back into the vault on save")

    def open_selected_files(self):
        """Opens every selected file (not just the first) — used by the
        context menu and double-click-equivalent multi-open."""
        opened = 0
        for path, node_type in self._selected_paths():
            if node_type == "file":
                self.open_file(path)
                opened += 1
        if opened == 0:
            self._set_status("No files selected to open.")

    def move_paths(self, vault_paths: list[str], dest_folder: str):
        moved = 0
        for path in vault_paths:
            if not path or path == dest_folder:
                continue
            try:
                self.engine.move(path, dest_folder)
                new_path = f"{dest_folder.rstrip('/')}/{os.path.basename(path)}"
                self.workspace.remap_path(path, new_path)
                moved += 1
            except VaultError as e:
                QMessageBox.warning(self, "Couldn't move", f"{path}: {e}")
        if moved:
            self._refresh_tree()
            self._refresh_file_list()
            self._set_status(f"Moved {moved} item(s) to {dest_folder}")

    # ---------- preview (real thumbnails, not placeholders) ----------

    def _show_preview(self, vault_path: str):
        ext = os.path.splitext(vault_path)[1].lstrip(".").lower()
        try:
            if ext in TEXT_PREVIEW_EXTS:
                data = self.engine.preview_bytes(vault_path, max_bytes=200_000)
                self.preview_text.setPlainText(data.decode("utf-8", errors="replace"))
                self.preview.setCurrentWidget(self.preview_text)

            elif ext in IMAGE_PREVIEW_EXTS:
                data = self.engine.preview_bytes(vault_path, max_bytes=25 * 1024 * 1024)
                image = QImage()
                if image.loadFromData(data):
                    pixmap = QPixmap.fromImage(image)
                    self.preview_image.setPixmap(
                        pixmap.scaled(320, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    )
                    self.preview.setCurrentWidget(self.preview_image)
                else:
                    self.preview_text.setPlainText("Couldn't decode image for preview.")
                    self.preview.setCurrentWidget(self.preview_text)

            elif ext in PDF_PREVIEW_EXTS and HAVE_QTPDF:
                self._show_pdf_preview(vault_path)

            elif ext in PDF_PREVIEW_EXTS:
                self.preview_text.setPlainText("PDF preview requires the PySide6 QtPdf module "
                                                "(not available in this environment). Double-click to open.")
                self.preview.setCurrentWidget(self.preview_text)

            else:
                self.preview_text.setPlainText(f"No inline preview for .{ext} files.\nDouble-click to open.")
                self.preview.setCurrentWidget(self.preview_text)
        except Exception as e:
            self.preview_text.setPlainText(f"Couldn't preview file: {e}")
            self.preview.setCurrentWidget(self.preview_text)

    def _show_pdf_preview(self, vault_path: str):
        # QPdfDocument needs a real file path, not raw bytes — extract into
        # the temp workspace (same as opening it) so we're only ever
        # putting plaintext where the user already agreed it's acceptable.
        local_path = self.workspace.open_file(vault_path)
        doc = QPdfDocument(self)
        doc.load(local_path)
        if doc.pageCount() < 1:
            self.preview_text.setPlainText("Couldn't render PDF preview.")
            self.preview.setCurrentWidget(self.preview_text)
            return
        page_size = doc.pagePointSize(0)
        target_width = 320
        scale = target_width / max(page_size.width(), 1)
        image = doc.render(0, (page_size * scale).toSize())
        self.preview_image.setPixmap(QPixmap.fromImage(image))
        self.preview.setCurrentWidget(self.preview_image)

    # ---------- context menu ----------

    def _show_context_menu(self, pos):
        menu = QMenu(self)
        selection = self._selected_paths()

        if selection:
            menu.addAction("Open").triggered.connect(self.open_selected_files)
            menu.addAction("Rename").triggered.connect(self.action_rename_selected)
            menu.addAction("Delete").triggered.connect(self.action_delete_selected)
            menu.addAction("Export...").triggered.connect(self.action_export_selected)
            if len(selection) == 1 and selection[0][1] == "file":
                menu.addAction("Version History...").triggered.connect(self.action_version_history)
            menu.addSeparator()

        menu.addAction("New Folder").triggered.connect(self.action_new_folder)
        menu.addAction("New File").triggered.connect(self.action_new_file)
        menu.addAction("Import Files...").triggered.connect(self.action_import_files)
        menu.exec(self.file_list.viewport().mapToGlobal(pos))

    # ---------- toolbar actions ----------

    def action_new_folder(self):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")
        if ok and name:
            try:
                self.engine.mkdir(f"{self.current_folder.rstrip('/')}/{name}")
                self._refresh_tree()
                self._refresh_file_list()
                self._set_status(f"Created folder {name}")
            except PathExists:
                QMessageBox.warning(self, "Exists", f"'{name}' already exists here.")
            except VaultError as e:
                QMessageBox.critical(self, "Error", str(e))

    def action_new_file(self):
        name, ok = QInputDialog.getText(self, "New File", "File name (e.g. notes.txt):")
        if ok and name:
            try:
                self.engine.touch(f"{self.current_folder.rstrip('/')}/{name}", b"")
                self._refresh_file_list()
                self._set_status(f"Created {name}")
            except PathExists:
                QMessageBox.warning(self, "Exists", f"'{name}' already exists here.")
            except VaultError as e:
                QMessageBox.critical(self, "Error", str(e))

    def action_import_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Import files into vault")
        if paths:
            self.import_external_paths(paths)

    def action_import_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Import folder into vault")
        if path:
            self.import_external_paths([path])

    def import_external_paths(self, local_paths: list[str]):
        imported = 0
        for p in local_paths:
            try:
                if os.path.isdir(p):
                    self.engine.import_folder(p, self.current_folder)
                else:
                    self.engine.import_file(p, self.current_folder)
                imported += 1
            except PathExists:
                QMessageBox.warning(self, "Exists", f"'{os.path.basename(p)}' already exists here.")
            except VaultError as e:
                QMessageBox.critical(self, "Import error", str(e))
        if imported:
            self._refresh_tree()
            self._refresh_file_list()
            self._set_status(f"Imported {imported} item(s)")

    def action_export_selected(self):
        selection = self._selected_paths()
        files = [p for p, t in selection if t == "file"]
        if not files:
            QMessageBox.information(self, "Export", "Select at least one file (folder export not supported yet).")
            return
        if len(files) == 1:
            name = os.path.basename(files[0])
            dest, _ = QFileDialog.getSaveFileName(self, "Export file to...", name)
            if dest:
                try:
                    self.engine.export_file(files[0], dest)
                    self._set_status(f"Exported to {dest}")
                except VaultError as e:
                    QMessageBox.critical(self, "Export error", str(e))
        else:
            dest_dir = QFileDialog.getExistingDirectory(self, "Export files to folder...")
            if dest_dir:
                count = 0
                for f in files:
                    try:
                        self.engine.export_file(f, os.path.join(dest_dir, os.path.basename(f)))
                        count += 1
                    except VaultError as e:
                        QMessageBox.warning(self, "Export error", f"{f}: {e}")
                self._set_status(f"Exported {count} file(s) to {dest_dir}")

    def action_rename_selected(self):
        selection = self._selected_paths()
        if not selection:
            return
        vault_path, _ = selection[0]
        old_name = os.path.basename(vault_path)
        new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=old_name)
        if ok and new_name and new_name != old_name:
            try:
                self.engine.rename(vault_path, new_name)
                self._refresh_tree()
                self._refresh_file_list()
                self._set_status(f"Renamed to {new_name}")
            except VaultError as e:
                QMessageBox.critical(self, "Error", str(e))

    def action_delete_selected(self):
        selection = self._selected_paths()
        if not selection:
            return
        names = ", ".join(os.path.basename(p) for p, _ in selection)
        confirm = QMessageBox.question(self, "Delete", f"Permanently delete {names} from the vault?")
        if confirm != QMessageBox.Yes:
            return
        for vault_path, _ in selection:
            try:
                self.engine.delete(vault_path)
            except VaultError as e:
                QMessageBox.critical(self, "Error", str(e))
        self._refresh_tree()
        self._refresh_file_list()
        self._set_status("Deleted")

    def action_version_history(self):
        selection = self._selected_paths()
        files = [p for p, t in selection if t == "file"]
        if len(files) != 1:
            QMessageBox.information(self, "Version History", "Select exactly one file first.")
            return
        dlg = VersionHistoryDialog(self, self.engine, files[0])
        dlg.exec()
        if dlg.restored:
            self._refresh_file_list()
            item = self.file_list.currentItem()
            if item:
                self._show_preview(files[0])
            self._set_status(f"Restored a previous version of {os.path.basename(files[0])}")

    def action_go_up(self):
        if self.current_folder in ("/", ""):
            return
        parent = "/".join(self.current_folder.rstrip("/").split("/")[:-1]) or "/"
        self.current_folder = parent
        self.showing_search_results = False
        self._refresh_file_list()

    def action_search(self):
        query = self.search_box.text().strip()
        if not query:
            self._refresh_file_list()
            self.showing_search_results = False
            return
        results = self.engine.search(query, by="name")
        self.file_list.clear()
        self.path_label.setText(f"Search results for '{query}'")
        self.showing_search_results = True
        for r in results:
            self._add_file_row(r["node"], parent_path="", full_path_override=r["path"])
        self._set_status(f"{len(results)} result(s)")

    def action_lock(self):
        self.watcher.stop()
        self.workspace.close()
        self.engine.lock()
        self._set_status("Vault locked.")
        self.close()

    def _on_file_synced(self, local_path: str):
        vault_path = self.workspace.vault_path_for_local(local_path)
        self._set_status(f"Auto-synced changes to {vault_path or local_path}")
        if vault_path and self.showing_search_results is False:
            self._refresh_file_list()

    # ---------- window lifecycle ----------

    def closeEvent(self, event):
        if self.engine.is_unlocked:
            self.watcher.stop()
            self.workspace.close()
            self.engine.lock()
        event.accept()


def engine_dir_display(path: str) -> str:
    return os.path.basename(path.rstrip("/\\")) or path
