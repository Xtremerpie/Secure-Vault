"""
Headless smoke test for the GUI layer. This sandbox has no display, so we
use Qt's offscreen platform plugin and drive the MainWindow's methods
directly (not real mouse/keyboard events) to make sure everything wires up,
imports cleanly, and the vault operations triggered from the UI actually
work end to end — including the V2.1 additions: recovery key, version
history, thumbnails, in-app move, and multi-file open.

Run with:
    QT_QPA_PLATFORM=offscreen python3 smoke_test_gui.py
"""
import os
import shutil
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from core.vault import VaultEngine
from ui.main_window import MainWindow, VersionHistoryDialog

TMP = "/tmp/securevault_gui_smoke"
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP)

app = QApplication(sys.argv)

vault_dir = os.path.join(TMP, "smoke.svault")
engine = VaultEngine.create(vault_dir, "smoketestpassword")
recovery_key = engine.recovery_key
assert recovery_key, "recovery key should be generated on create"
print("vault created, recovery key generated:", recovery_key[:9] + "...")

win = MainWindow(engine)
print("MainWindow constructed OK")
# recovery key dialog would normally show via QTimer.singleShot; clear manually for the rest of the test
win.engine.recovery_key = None

# --- folders/files ---
win.engine.mkdir("/Documents")
win.engine.mkdir("/Documents/School")
win.engine.mkdir("/Photos")
win.engine.touch("/Documents/School/notes.txt", b"physics notes")
win._refresh_tree()
win._refresh_file_list()
print("tree top-level items:", win.tree.topLevelItemCount())

win.current_folder = "/Documents/School"
win._refresh_file_list()
assert win.file_list.topLevelItemCount() == 1

# --- open + watcher auto re-encrypt (regression check) ---
local_path = win.workspace.open_file("/Documents/School/notes.txt")
assert os.path.exists(local_path)
with open(local_path, "wb") as f:
    f.write(b"physics notes -- edited externally")
time.sleep(1.5)
reopened = VaultEngine.unlock(vault_dir, "smoketestpassword")
assert reopened.preview_bytes("/Documents/School/notes.txt") == b"physics notes -- edited externally"
reopened.lock()
print("watcher auto re-encrypt OK (regression)")

# --- version history now has an entry from that edit ---
versions = win.engine.list_versions("/Documents/School/notes.txt")
assert len(versions) == 1, f"expected 1 version, got {len(versions)}"
print("version history recorded the pre-edit content OK")

dlg = VersionHistoryDialog(win, win.engine, "/Documents/School/notes.txt")
assert dlg.list.count() == 1
win.engine.restore_version("/Documents/School/notes.txt", versions[0]["version_id"])
assert win.engine.preview_bytes("/Documents/School/notes.txt") == b"physics notes"
print("restore_version brought back original content OK")

# --- in-app move (drag-and-drop equivalent) ---
win.move_paths(["/Documents/School"], "/Photos")
assert win.engine.exists("/Photos/School/notes.txt")
assert not win.engine.exists("/Documents/School")
print("move_paths (drag-to-move code path) OK")

# --- import (external drag-drop path) ---
ext_file = os.path.join(TMP, "external.txt")
with open(ext_file, "w") as f:
    f.write("dropped in from outside")
win.current_folder = "/"
win.import_external_paths([ext_file])
assert win.engine.exists("/external.txt")
print("import_external_paths OK")

# --- real image thumbnail rendering ---
try:
    from PIL import Image
    img_path = os.path.join(TMP, "test.png")
    Image.new("RGB", (40, 40), color=(200, 30, 30)).save(img_path)
    win.engine.import_file(img_path, "/")
    win._show_preview("/test.png")
    assert win.preview.currentWidget() is win.preview_image
    assert win.preview_image.pixmap() is not None and not win.preview_image.pixmap().isNull()
    print("real image thumbnail rendering OK")
except ImportError:
    print("Pillow not installed — skipping image thumbnail sub-test (core feature unaffected)")

# --- multi-file open (selection-based, not just first) ---
win.current_folder = "/"
win._refresh_file_list()
win.engine.touch("/multi1.txt", b"a")
win.engine.touch("/multi2.txt", b"b")
win._refresh_file_list()
win.file_list.selectAll()
opened_calls = []
win.open_file = lambda p: opened_calls.append(p)
win.open_selected_files()
assert len(opened_calls) >= 2, f"expected multi-open to call open_file per file, got {opened_calls}"
print("multi-file open OK, opened:", opened_calls)

# --- recovery key actually unlocks ---
win.watcher.stop()
win.workspace.close()
win.engine.lock()
recovered_engine = VaultEngine.unlock_with_recovery(vault_dir, recovery_key)
assert recovered_engine.is_unlocked
assert recovered_engine.exists("/Photos/School/notes.txt")
print("recovery key unlock OK")
recovered_engine.lock()

# --- change password then confirm old password fails, new one works ---
engine2 = VaultEngine.unlock(vault_dir, "smoketestpassword")
engine2.change_password("newpassword456")
engine2.lock()
try:
    VaultEngine.unlock(vault_dir, "smoketestpassword")
    raise AssertionError("old password should no longer work")
except Exception as e:
    assert "incorrect" in str(e).lower() or "WrongPassword" in type(e).__name__
engine3 = VaultEngine.unlock(vault_dir, "newpassword456")
assert engine3.is_unlocked
engine3.lock()
print("change_password OK")

print("\nALL GUI SMOKE TESTS PASSED (including V2.1 features)")
