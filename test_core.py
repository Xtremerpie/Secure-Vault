"""
Test suite for SecureVault V2 core (no GUI). Run with:
    python -m pytest test_core.py -v
"""

import os
import shutil
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import crypto
from core.vault import VaultEngine, WrongPassword, PathNotFound, PathExists
from core.workspace import TempWorkspace
from core.watcher import VaultWatcher


TMP_ROOT = "/tmp/securevault_test"


@pytest.fixture(autouse=True)
def clean_tmp():
    shutil.rmtree(TMP_ROOT, ignore_errors=True)
    os.makedirs(TMP_ROOT)
    yield
    shutil.rmtree(TMP_ROOT, ignore_errors=True)


def vault_path(name="test.svault"):
    return os.path.join(TMP_ROOT, name)


# ---------- crypto ----------

def test_crypto_roundtrip_small():
    key = crypto.derive_key("hunter2", crypto.new_salt(), iterations=1000)
    blob = crypto.encrypt_bytes(key, b"hello world")
    assert crypto.decrypt_bytes(key, blob) == b"hello world"


def test_crypto_wrong_key_fails():
    salt = crypto.new_salt()
    key1 = crypto.derive_key("correct", salt, iterations=1000)
    key2 = crypto.derive_key("wrong", salt, iterations=1000)
    blob = crypto.encrypt_bytes(key1, b"secret")
    with pytest.raises(Exception):
        crypto.decrypt_bytes(key2, blob)


def test_crypto_chunked_file_roundtrip():
    key = crypto.derive_key("pw", crypto.new_salt(), iterations=1000)
    src = os.path.join(TMP_ROOT, "plain.bin")
    enc = os.path.join(TMP_ROOT, "enc.bin")
    dec = os.path.join(TMP_ROOT, "dec.bin")

    data = os.urandom(5 * 1024 * 1024 + 137)  # not an exact multiple of chunk size
    with open(src, "wb") as f:
        f.write(data)

    crypto.encrypt_file_chunked(key, src, enc, chunk_size=1024 * 1024)
    crypto.decrypt_file_chunked(key, enc, dec)

    with open(dec, "rb") as f:
        assert f.read() == data

    # encrypted file should not contain the plaintext anywhere
    with open(enc, "rb") as f:
        enc_bytes = f.read()
    assert data[:1000] not in enc_bytes


def test_crypto_chunked_empty_file():
    key = crypto.derive_key("pw", crypto.new_salt(), iterations=1000)
    src = os.path.join(TMP_ROOT, "empty.bin")
    enc = os.path.join(TMP_ROOT, "empty.enc")
    dec = os.path.join(TMP_ROOT, "empty.dec")
    open(src, "wb").close()
    crypto.encrypt_file_chunked(key, src, enc)
    crypto.decrypt_file_chunked(key, enc, dec)
    assert os.path.getsize(dec) == 0


# ---------- vault create / unlock ----------

def test_create_and_unlock():
    v = VaultEngine.create(vault_path(), "correct horse battery staple")
    v.lock()
    v2 = VaultEngine.unlock(vault_path(), "correct horse battery staple")
    assert v2.is_unlocked
    assert v2.list_dir("/") == []


def test_wrong_password_rejected():
    VaultEngine.create(vault_path(), "realpassword").lock()
    with pytest.raises(WrongPassword):
        VaultEngine.unlock(vault_path(), "wrongpassword")


def test_cannot_double_create():
    VaultEngine.create(vault_path(), "pw")
    with pytest.raises(Exception):
        VaultEngine.create(vault_path(), "pw2")


# ---------- folders & files ----------

def test_mkdir_and_list():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/Documents")
    v.mkdir("/Documents/School")
    v.mkdir("/Photos")
    top = {c["name"] for c in v.list_dir("/")}
    assert top == {"Documents", "Photos"}
    sub = {c["name"] for c in v.list_dir("/Documents")}
    assert sub == {"School"}


def test_mkdir_duplicate_raises():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/Documents")
    with pytest.raises(PathExists):
        v.mkdir("/Documents")


def test_touch_creates_file_with_content():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/notes.txt", b"hello vault")
    node = v.get_node("/notes.txt")
    assert node["type"] == "file"
    assert node["size"] == len(b"hello vault")
    data = v.preview_bytes("/notes.txt")
    assert data == b"hello vault"


def test_rename_file_and_folder():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/Docs")
    v.touch("/Docs/a.txt", b"x")
    v.rename("/Docs/a.txt", "b.txt")
    assert not v.exists("/Docs/a.txt")
    assert v.exists("/Docs/b.txt")
    v.rename("/Docs", "Documents")
    assert v.exists("/Documents/b.txt")


def test_move_file_between_folders():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/A")
    v.mkdir("/B")
    v.touch("/A/file.txt", b"content")
    v.move("/A/file.txt", "/B")
    assert not v.exists("/A/file.txt")
    assert v.exists("/B/file.txt")
    assert v.preview_bytes("/B/file.txt") == b"content"


def test_delete_file_removes_blob():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/x.txt", b"data")
    node = v.get_node("/x.txt")
    blob_path = os.path.join(v.vault_dir, "blobs", f"{node['id']}.enc")
    assert os.path.exists(blob_path)
    v.delete("/x.txt")
    assert not v.exists("/x.txt")
    assert not os.path.exists(blob_path)


def test_delete_folder_recursively_removes_blobs():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/Folder")
    v.touch("/Folder/a.txt", b"a")
    v.touch("/Folder/b.txt", b"b")
    node_a = v.get_node("/Folder/a.txt")
    node_b = v.get_node("/Folder/b.txt")
    blob_a = os.path.join(v.vault_dir, "blobs", f"{node_a['id']}.enc")
    blob_b = os.path.join(v.vault_dir, "blobs", f"{node_b['id']}.enc")
    v.delete("/Folder")
    assert not os.path.exists(blob_a)
    assert not os.path.exists(blob_b)
    assert not v.exists("/Folder")


def test_path_not_found_raises():
    v = VaultEngine.create(vault_path(), "pw")
    with pytest.raises(PathNotFound):
        v.get_node("/nope.txt")


# ---------- import / export ----------

def test_import_and_export_file():
    v = VaultEngine.create(vault_path(), "pw")
    src = os.path.join(TMP_ROOT, "external.docx")
    with open(src, "wb") as f:
        f.write(b"fake docx content " * 1000)

    v.import_file(src, "/")
    assert v.exists("/external.docx")

    out = os.path.join(TMP_ROOT, "exported.docx")
    v.export_file("/external.docx", out)
    with open(src, "rb") as f1, open(out, "rb") as f2:
        assert f1.read() == f2.read()


def test_import_folder_recursive():
    v = VaultEngine.create(vault_path(), "pw")
    src_dir = os.path.join(TMP_ROOT, "srcfolder", "nested")
    os.makedirs(src_dir)
    with open(os.path.join(src_dir, "deep.txt"), "wb") as f:
        f.write(b"deep content")
    with open(os.path.join(TMP_ROOT, "srcfolder", "top.txt"), "wb") as f:
        f.write(b"top content")

    v.import_folder(os.path.join(TMP_ROOT, "srcfolder"), "/")
    assert v.exists("/srcfolder/top.txt")
    assert v.exists("/srcfolder/nested/deep.txt")
    assert v.preview_bytes("/srcfolder/nested/deep.txt") == b"deep content"


# ---------- search ----------

def test_search_by_name_and_ext():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/Docs")
    v.touch("/Docs/Report.docx", b"1")
    v.touch("/Docs/Photo.png", b"2")
    v.touch("/Summary.docx", b"3")

    by_name = v.search("report")
    assert len(by_name) == 1
    assert by_name[0]["path"] == "/Docs/Report.docx"

    by_ext = v.search("docx", by="ext")
    paths = {r["path"] for r in by_ext}
    assert paths == {"/Docs/Report.docx", "/Summary.docx"}


# ---------- workspace + watcher: the "acts like a normal folder" flow ----------

def test_open_edit_autoresync_via_watcher():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/notes.txt", b"original content")

    ws = TempWorkspace(v)
    watcher = VaultWatcher(ws, debounce_seconds=0.3)
    watcher.start()
    try:
        local_path = ws.open_file("/notes.txt")
        assert os.path.exists(local_path)
        with open(local_path, "rb") as f:
            assert f.read() == b"original content"

        # Simulate an external app (e.g. Notepad/Word) editing and saving the file.
        with open(local_path, "wb") as f:
            f.write(b"edited by external app")

        time.sleep(1.0)  # let the debounced watcher fire

        # The vault blob should now reflect the edit, independent of the temp file.
        v2 = VaultEngine.unlock(vault_path(), "pw")
        assert v2.preview_bytes("/notes.txt") == b"edited by external app"
    finally:
        watcher.stop()
        ws.close()


def test_workspace_close_wipes_temp_dir():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/secret.txt", b"top secret")
    ws = TempWorkspace(v)
    local_path = ws.open_file("/secret.txt")
    assert os.path.exists(local_path)
    root = ws.root
    ws.close()
    assert not os.path.exists(root)


def test_workspace_remap_path_after_move_keeps_sync_working():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/A")
    v.mkdir("/B")
    v.touch("/A/file.txt", b"original")
    ws = TempWorkspace(v)
    local_path = ws.open_file("/A/file.txt")

    v.move("/A/file.txt", "/B")
    ws.remap_path("/A/file.txt", "/B/file.txt")

    with open(local_path, "wb") as f:
        f.write(b"edited after move")
    synced = ws.sync_change(local_path)
    assert synced is True
    assert v.preview_bytes("/B/file.txt") == b"edited after move"
    ws.close()


def test_workspace_sync_never_crashes_on_orphaned_tracked_file():
    """If a tracked file's vault path disappears (moved/deleted) WITHOUT a
    remap_path call, sync should skip it quietly rather than raise —
    this is what close()/lock() relies on to never crash."""
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/A")
    v.touch("/A/file.txt", b"original")
    ws = TempWorkspace(v)
    local_path = ws.open_file("/A/file.txt")

    v.delete("/A/file.txt")  # no remap_path call — path now genuinely gone

    with open(local_path, "wb") as f:
        f.write(b"orphaned edit")
    synced = ws.sync_change(local_path)  # must not raise
    assert synced is False
    ws.close()  # must also not raise


def test_lock_then_reopen_persists_all_changes():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/A")
    v.touch("/A/file.txt", b"persisted content")
    v.lock()

    v2 = VaultEngine.unlock(vault_path(), "pw")
    assert v2.exists("/A/file.txt")
    assert v2.preview_bytes("/A/file.txt") == b"persisted content"


def test_manifest_and_blobs_are_actually_encrypted_on_disk():
    v = VaultEngine.create(vault_path(), "pw")
    v.mkdir("/SecretFolderName")
    v.touch("/SecretFolderName/passwords.txt", b"admin:hunter2")
    v.lock()

    manifest_bytes = open(os.path.join(vault_path(), "manifest.enc"), "rb").read()
    assert b"SecretFolderName" not in manifest_bytes
    assert b"passwords.txt" not in manifest_bytes

    blobs_dir = os.path.join(vault_path(), "blobs")
    for dirpath, _dirnames, filenames in os.walk(blobs_dir):
        for fname in filenames:
            blob_bytes = open(os.path.join(dirpath, fname), "rb").read()
            assert b"hunter2" not in blob_bytes


# ---------- recovery key ----------

def test_recovery_key_unlocks_vault():
    v = VaultEngine.create(vault_path(), "mypassword")
    recovery = v.recovery_key
    assert recovery is not None
    v.touch("/file.txt", b"content")
    v.lock()

    v2 = VaultEngine.unlock_with_recovery(vault_path(), recovery)
    assert v2.is_unlocked
    assert v2.preview_bytes("/file.txt") == b"content"


def test_wrong_recovery_key_rejected():
    VaultEngine.create(vault_path(), "mypassword").lock()
    with pytest.raises(WrongPassword):
        VaultEngine.unlock_with_recovery(vault_path(), "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG")


def test_change_password_then_unlock_with_new_password():
    v = VaultEngine.create(vault_path(), "oldpassword")
    v.touch("/f.txt", b"data")
    v.change_password("newpassword")
    v.lock()

    with pytest.raises(WrongPassword):
        VaultEngine.unlock(vault_path(), "oldpassword")

    v2 = VaultEngine.unlock(vault_path(), "newpassword")
    assert v2.preview_bytes("/f.txt") == b"data"


def test_change_password_does_not_break_recovery_key():
    v = VaultEngine.create(vault_path(), "oldpassword")
    recovery = v.recovery_key
    v.change_password("newpassword")
    v.lock()

    v2 = VaultEngine.unlock_with_recovery(vault_path(), recovery)
    assert v2.is_unlocked


def test_regenerate_recovery_key_invalidates_old_one():
    v = VaultEngine.create(vault_path(), "pw")
    old_recovery = v.recovery_key
    new_recovery = v.regenerate_recovery_key()
    assert new_recovery != old_recovery
    v.lock()

    with pytest.raises(WrongPassword):
        VaultEngine.unlock_with_recovery(vault_path(), old_recovery)
    v2 = VaultEngine.unlock_with_recovery(vault_path(), new_recovery)
    assert v2.is_unlocked


# ---------- version history ----------

def test_editing_a_file_creates_a_version_of_the_old_content():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/notes.txt", b"version 1")

    ws = TempWorkspace(v)
    local = ws.open_file("/notes.txt")
    with open(local, "wb") as f:
        f.write(b"version 2")
    ws.sync_change(local)

    versions = v.list_versions("/notes.txt")
    assert len(versions) == 1
    assert v.preview_bytes("/notes.txt") == b"version 2"
    ws.close()


def test_restore_version_brings_back_old_content():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/notes.txt", b"version 1")
    ws = TempWorkspace(v)
    local = ws.open_file("/notes.txt")

    with open(local, "wb") as f:
        f.write(b"version 2")
    ws.sync_change(local)

    versions = v.list_versions("/notes.txt")
    assert v.preview_bytes("/notes.txt") == b"version 2"

    v.restore_version("/notes.txt", versions[0]["version_id"])
    assert v.preview_bytes("/notes.txt") == b"version 1"

    # restoring itself created a new version snapshot of "version 2"
    versions_after = v.list_versions("/notes.txt")
    assert len(versions_after) == 2
    ws.close()


def test_version_history_capped_at_max():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/f.txt", b"v0")
    ws = TempWorkspace(v)
    local = ws.open_file("/f.txt")

    for i in range(1, 10):
        with open(local, "wb") as f:
            f.write(f"v{i}".encode())
        ws.sync_change(local)

    versions = v.list_versions("/f.txt")
    assert len(versions) <= 5
    assert v.preview_bytes("/f.txt") == b"v9"
    ws.close()


def test_delete_file_also_removes_version_blobs():
    v = VaultEngine.create(vault_path(), "pw")
    v.touch("/f.txt", b"v0")
    ws = TempWorkspace(v)
    local = ws.open_file("/f.txt")
    with open(local, "wb") as f:
        f.write(b"v1")
    ws.sync_change(local)
    node_id = v.get_node("/f.txt")["id"]
    versions_dir = os.path.join(v.vault_dir, "blobs", "versions", node_id)
    assert os.path.exists(versions_dir)
    ws.close()

    v.delete("/f.txt")
    assert not os.path.exists(versions_dir)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
