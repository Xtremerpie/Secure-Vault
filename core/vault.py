"""
core/vault.py — the vault engine: manifest (folder tree) management and all
file operations (create, delete, rename, move, import, export, search,
version history).

Key architecture (V2.1): a random 256-bit master key does all the actual
data encryption. The master key itself is never derived from the password
directly — instead it's *wrapped* (encrypted) once under a password-derived
key and once under a recovery-key-derived key, both stored in vault.meta.
This means:
  - Unlocking with either the password or the recovery key yields the same
    master key, so both work.
  - Changing the password, or rotating the recovery key, only needs to
    re-wrap the small master key — not re-encrypt every file.

On-disk layout of a vault directory:

    myvault.svault/
        vault.meta          plaintext JSON: kdf params + wrapped master key
                             (both password- and recovery-wrapped copies)
        manifest.enc          encrypted JSON: the whole folder/file tree
        blobs/
            <uuid>.enc          chunked-encrypted current file contents
            versions/
                <uuid>/
                    <version_id>.enc   snapshots of previous contents
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from . import crypto

MAX_VERSIONS_PER_FILE = 5


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class PathNotFound(VaultError):
    pass


class PathExists(VaultError):
    pass


def _split_path(path: str) -> list[str]:
    return [p for p in path.replace("\\", "/").split("/") if p]


def generate_recovery_key() -> str:
    """A human-typeable, high-entropy recovery key: 32 base32 chars in
    dash-separated groups of 4, e.g. ABCD-EFGH-JKMN-... (160 bits)."""
    raw = secrets.token_bytes(20)
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [b32[i:i + 4] for i in range(0, len(b32), 4)]
    return "-".join(groups)


def _normalize_recovery_key(s: str) -> str:
    return s.strip().upper()


@dataclass
class VaultEngine:
    vault_dir: str
    key: Optional[bytes] = None          # the master data-encryption key
    tree: Optional[dict] = None          # root folder node once unlocked
    recovery_key: Optional[str] = None   # only set right after create(); shown once
    _dirty: bool = False

    # ---------- lifecycle ----------

    @staticmethod
    def create(vault_dir: str, password: str) -> "VaultEngine":
        if os.path.exists(vault_dir) and os.listdir(vault_dir):
            raise VaultError(f"{vault_dir} already exists and is not empty")
        os.makedirs(vault_dir, exist_ok=True)
        os.makedirs(os.path.join(vault_dir, "blobs"), exist_ok=True)
        os.makedirs(os.path.join(vault_dir, "blobs", "versions"), exist_ok=True)

        master_key = os.urandom(crypto.KEY_LEN)

        pw_salt = crypto.new_salt()
        pw_key = crypto.derive_key(password, pw_salt)
        wrapped_password = crypto.encrypt_bytes(pw_key, master_key)

        recovery_key_str = generate_recovery_key()
        rec_salt = crypto.new_salt()
        rec_key = crypto.derive_key(recovery_key_str, rec_salt)
        wrapped_recovery = crypto.encrypt_bytes(rec_key, master_key)

        meta = {
            "version": 3,
            "kdf": "pbkdf2_sha256",
            "iterations": crypto.DEFAULT_ITERATIONS,
            "salt": pw_salt.hex(),
            "wrapped_key_password": wrapped_password.hex(),
            "recovery_salt": rec_salt.hex(),
            "wrapped_key_recovery": wrapped_recovery.hex(),
        }
        VaultEngine._write_meta(vault_dir, meta)

        engine = VaultEngine(vault_dir=vault_dir, key=master_key)
        engine.tree = {"type": "folder", "name": "", "children": []}
        engine.recovery_key = recovery_key_str
        engine._save_manifest()
        return engine

    @staticmethod
    def unlock(vault_dir: str, password: str) -> "VaultEngine":
        meta = VaultEngine._read_meta(vault_dir)
        salt = bytes.fromhex(meta["salt"])
        pw_key = crypto.derive_key(password, salt, meta.get("iterations", crypto.DEFAULT_ITERATIONS))
        try:
            master_key = crypto.decrypt_bytes(pw_key, bytes.fromhex(meta["wrapped_key_password"]))
        except Exception:
            raise WrongPassword("incorrect password")

        engine = VaultEngine(vault_dir=vault_dir, key=master_key)
        engine._load_manifest()
        return engine

    @staticmethod
    def unlock_with_recovery(vault_dir: str, recovery_key_str: str) -> "VaultEngine":
        meta = VaultEngine._read_meta(vault_dir)
        salt = bytes.fromhex(meta["recovery_salt"])
        rec_key = crypto.derive_key(
            _normalize_recovery_key(recovery_key_str), salt,
            meta.get("iterations", crypto.DEFAULT_ITERATIONS)
        )
        try:
            master_key = crypto.decrypt_bytes(rec_key, bytes.fromhex(meta["wrapped_key_recovery"]))
        except Exception:
            raise WrongPassword("incorrect recovery key")

        engine = VaultEngine(vault_dir=vault_dir, key=master_key)
        engine._load_manifest()
        return engine

    def lock(self) -> None:
        if self._dirty:
            self._save_manifest()
        if self.key:
            self.key = b"\x00" * len(self.key)
        self.key = None
        self.tree = None
        self.recovery_key = None

    @property
    def is_unlocked(self) -> bool:
        return self.key is not None and self.tree is not None

    def _require_unlocked(self):
        if not self.is_unlocked:
            raise VaultError("vault is locked")

    # ---------- password / recovery key management ----------

    def change_password(self, new_password: str) -> None:
        self._require_unlocked()
        meta = self._read_meta(self.vault_dir)
        new_salt = crypto.new_salt()
        new_pw_key = crypto.derive_key(new_password, new_salt)
        wrapped = crypto.encrypt_bytes(new_pw_key, self.key)
        meta["salt"] = new_salt.hex()
        meta["wrapped_key_password"] = wrapped.hex()
        self._write_meta(self.vault_dir, meta)

    def regenerate_recovery_key(self) -> str:
        """Invalidates the old recovery key and returns a new one. The
        caller MUST show this to the user immediately — it is not stored
        anywhere in plaintext and cannot be retrieved again."""
        self._require_unlocked()
        meta = self._read_meta(self.vault_dir)
        new_recovery = generate_recovery_key()
        new_salt = crypto.new_salt()
        rec_key = crypto.derive_key(new_recovery, new_salt)
        wrapped = crypto.encrypt_bytes(rec_key, self.key)
        meta["recovery_salt"] = new_salt.hex()
        meta["wrapped_key_recovery"] = wrapped.hex()
        self._write_meta(self.vault_dir, meta)
        self.recovery_key = new_recovery
        return new_recovery

    @staticmethod
    def _meta_path(vault_dir: str) -> str:
        return os.path.join(vault_dir, "vault.meta")

    @staticmethod
    def _read_meta(vault_dir: str) -> dict:
        path = VaultEngine._meta_path(vault_dir)
        if not os.path.exists(path):
            raise VaultError(f"{vault_dir} is not a SecureVault directory")
        with open(path) as f:
            return json.load(f)

    @staticmethod
    def _write_meta(vault_dir: str, meta: dict) -> None:
        tmp = VaultEngine._meta_path(vault_dir) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp, VaultEngine._meta_path(vault_dir))

    # ---------- manifest persistence ----------

    def _manifest_path(self) -> str:
        return os.path.join(self.vault_dir, "manifest.enc")

    def _blobs_dir(self) -> str:
        return os.path.join(self.vault_dir, "blobs")

    def _versions_dir(self, file_id: str) -> str:
        return os.path.join(self._blobs_dir(), "versions", file_id)

    def _save_manifest(self) -> None:
        self._require_unlocked()
        data = json.dumps(self.tree).encode("utf-8")
        blob = crypto.encrypt_bytes(self.key, data)
        tmp_path = self._manifest_path() + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(blob)
        os.replace(tmp_path, self._manifest_path())
        self._dirty = False

    def _load_manifest(self) -> None:
        path = self._manifest_path()
        if not os.path.exists(path):
            self.tree = {"type": "folder", "name": "", "children": []}
            return
        with open(path, "rb") as f:
            blob = f.read()
        data = crypto.decrypt_bytes(self.key, blob)
        self.tree = json.loads(data.decode("utf-8"))

    def flush(self) -> None:
        if self._dirty:
            self._save_manifest()

    # ---------- tree navigation ----------

    def _find(self, path: str, create_missing_dirs: bool = False) -> tuple[dict, dict, str]:
        self._require_unlocked()
        parts = _split_path(path)
        node = self.tree
        parent = None
        if not parts:
            return None, self.tree, ""
        for i, part in enumerate(parts):
            if node["type"] != "folder":
                raise PathNotFound(path)
            match = next((c for c in node["children"] if c["name"] == part), None)
            is_last = i == len(parts) - 1
            if match is None:
                if is_last:
                    return node, None, part
                if create_missing_dirs:
                    new_folder = {"type": "folder", "name": part, "children": []}
                    node["children"].append(new_folder)
                    node, parent = new_folder, node
                    continue
                raise PathNotFound(path)
            parent, node = node, match
            if is_last:
                return parent, node, part
        return parent, node, parts[-1]

    def list_dir(self, path: str = "/") -> list[dict]:
        _, node, _ = self._find(path)
        if node is None:
            raise PathNotFound(path)
        if node["type"] != "folder":
            raise VaultError(f"{path} is not a folder")
        return sorted(node["children"], key=lambda c: (c["type"] != "folder", c["name"].lower()))

    def exists(self, path: str) -> bool:
        try:
            _, node, _ = self._find(path)
            return node is not None
        except PathNotFound:
            return False

    def get_node(self, path: str) -> dict:
        _, node, _ = self._find(path)
        if node is None:
            raise PathNotFound(path)
        return node

    # ---------- folder / file operations ----------

    def mkdir(self, path: str) -> None:
        parent, node, name = self._find(path)
        if node is not None:
            raise PathExists(path)
        parent["children"].append({"type": "folder", "name": name, "children": []})
        self._dirty = True
        self._save_manifest()

    def touch(self, path: str, content: bytes = b"") -> None:
        parent, node, name = self._find(path)
        if node is not None:
            raise PathExists(path)
        file_id = uuid.uuid4().hex
        blob_path = os.path.join(self._blobs_dir(), f"{file_id}.enc")

        tmp_src = blob_path + ".src.tmp"
        with open(tmp_src, "wb") as f:
            f.write(content)
        crypto.encrypt_file_chunked(self.key, tmp_src, blob_path)
        os.remove(tmp_src)

        parent["children"].append({
            "type": "file",
            "name": name,
            "id": file_id,
            "size": len(content),
            "mtime": time.time(),
            "ext": os.path.splitext(name)[1].lstrip("."),
            "versions": [],
        })
        self._dirty = True
        self._save_manifest()

    def delete(self, path: str) -> None:
        parent, node, name = self._find(path)
        if node is None:
            raise PathNotFound(path)
        self._delete_blobs_recursive(node)
        parent["children"] = [c for c in parent["children"] if c["name"] != name]
        self._dirty = True
        self._save_manifest()

    def _delete_blobs_recursive(self, node: dict) -> None:
        if node["type"] == "file":
            blob_path = os.path.join(self._blobs_dir(), f"{node['id']}.enc")
            _secure_delete(blob_path)
            secure_delete_tree(self._versions_dir(node["id"]))
        else:
            for child in node.get("children", []):
                self._delete_blobs_recursive(child)

    def rename(self, path: str, new_name: str) -> None:
        parent, node, _ = self._find(path)
        if node is None:
            raise PathNotFound(path)
        if any(c["name"] == new_name for c in parent["children"] if c is not node):
            raise PathExists(new_name)
        node["name"] = new_name
        if node["type"] == "file":
            node["ext"] = os.path.splitext(new_name)[1].lstrip(".")
        self._dirty = True
        self._save_manifest()

    def move(self, path: str, dest_folder_path: str) -> None:
        parent, node, name = self._find(path)
        if node is None:
            raise PathNotFound(path)
        _, dest_node, _ = self._find(dest_folder_path)
        if dest_node is None or dest_node["type"] != "folder":
            raise PathNotFound(dest_folder_path)
        if dest_node is node:
            raise VaultError("cannot move a folder into itself")
        if any(c["name"] == name for c in dest_node["children"]):
            raise PathExists(f"{dest_folder_path}/{name}")
        parent["children"] = [c for c in parent["children"] if c is not node]
        dest_node["children"].append(node)
        self._dirty = True
        self._save_manifest()

    # ---------- import / export (explicit, whole-file) ----------

    def import_file(self, src_path: str, dest_folder_path: str, name: Optional[str] = None) -> None:
        name = name or os.path.basename(src_path)
        _, dest_node, _ = self._find(dest_folder_path)
        if dest_node is None or dest_node["type"] != "folder":
            raise PathNotFound(dest_folder_path)
        if any(c["name"] == name for c in dest_node["children"]):
            raise PathExists(name)

        file_id = uuid.uuid4().hex
        blob_path = os.path.join(self._blobs_dir(), f"{file_id}.enc")
        crypto.encrypt_file_chunked(self.key, src_path, blob_path)

        dest_node["children"].append({
            "type": "file",
            "name": name,
            "id": file_id,
            "size": os.path.getsize(src_path),
            "mtime": time.time(),
            "ext": os.path.splitext(name)[1].lstrip("."),
            "versions": [],
        })
        self._dirty = True
        self._save_manifest()

    def import_folder(self, src_dir: str, dest_folder_path: str) -> None:
        base_name = os.path.basename(os.path.normpath(src_dir))
        new_vault_folder = f"{dest_folder_path.rstrip('/')}/{base_name}"
        self.mkdir(new_vault_folder)
        for entry in sorted(os.listdir(src_dir)):
            full = os.path.join(src_dir, entry)
            if os.path.isdir(full):
                self.import_folder(full, new_vault_folder)
            else:
                self.import_file(full, new_vault_folder, name=entry)

    def export_file(self, vault_path: str, dest_path: str) -> None:
        node = self.get_node(vault_path)
        if node["type"] != "file":
            raise VaultError(f"{vault_path} is a folder, not a file")
        blob_path = os.path.join(self._blobs_dir(), f"{node['id']}.enc")
        crypto.decrypt_file_chunked(self.key, blob_path, dest_path)

    def preview_bytes(self, vault_path: str, max_bytes: int = 65536) -> bytes:
        node = self.get_node(vault_path)
        if node["type"] != "file":
            raise VaultError(f"{vault_path} is a folder, not a file")
        blob_path = os.path.join(self._blobs_dir(), f"{node['id']}.enc")
        return crypto.decrypt_file_chunked_to_bytes(self.key, blob_path, max_bytes=max_bytes)

    # ---------- workspace sync (used by TempWorkspace / Watcher) ----------

    def extract_node_to(self, vault_path: str, local_path: str) -> dict:
        node = self.get_node(vault_path)
        if node["type"] != "file":
            raise VaultError(f"{vault_path} is a folder, not a file")
        blob_path = os.path.join(self._blobs_dir(), f"{node['id']}.enc")
        crypto.decrypt_file_chunked(self.key, blob_path, local_path)
        return node

    def ingest_local_change(self, vault_path: str, local_path: str) -> None:
        """Re-encrypt a temp-workspace file's current contents back into its
        blob, snapshotting the previous contents as a version first."""
        node = self.get_node(vault_path)
        if node["type"] != "file":
            raise VaultError(f"{vault_path} is a folder, not a file")
        blob_path = os.path.join(self._blobs_dir(), f"{node['id']}.enc")

        if os.path.exists(blob_path):
            self._snapshot_version(node, blob_path)

        crypto.encrypt_file_chunked(self.key, local_path, blob_path)
        node["size"] = os.path.getsize(local_path)
        node["mtime"] = time.time()
        self._dirty = True
        self._save_manifest()

    def _snapshot_version(self, node: dict, current_blob_path: str) -> None:
        """Copy the current (about-to-be-replaced) blob into the versions
        folder verbatim — it's already encrypted with the same key, so no
        re-encryption needed — and record it in the manifest."""
        versions_dir = self._versions_dir(node["id"])
        os.makedirs(versions_dir, exist_ok=True)
        version_id = uuid.uuid4().hex
        version_path = os.path.join(versions_dir, f"{version_id}.enc")
        shutil.copy2(current_blob_path, version_path)

        versions = node.setdefault("versions", [])
        versions.append({
            "version_id": version_id,
            "timestamp": time.time(),
            "size": node.get("size", 0),
        })
        while len(versions) > MAX_VERSIONS_PER_FILE:
            old = versions.pop(0)
            _secure_delete(os.path.join(versions_dir, f"{old['version_id']}.enc"))

    def list_versions(self, vault_path: str) -> list[dict]:
        node = self.get_node(vault_path)
        if node["type"] != "file":
            raise VaultError(f"{vault_path} is a folder, not a file")
        return sorted(node.get("versions", []), key=lambda v: v["timestamp"], reverse=True)

    def restore_version(self, vault_path: str, version_id: str) -> None:
        """Restore a previous version as the current content. The content
        being replaced is itself snapshotted first, so this is non-destructive."""
        node = self.get_node(vault_path)
        if node["type"] != "file":
            raise VaultError(f"{vault_path} is a folder, not a file")
        versions_dir = self._versions_dir(node["id"])
        version_path = os.path.join(versions_dir, f"{version_id}.enc")
        if not os.path.exists(version_path):
            raise VaultError("that version no longer exists")

        blob_path = os.path.join(self._blobs_dir(), f"{node['id']}.enc")
        target_version = next((v for v in node.get("versions", []) if v["version_id"] == version_id), None)

        if os.path.exists(blob_path):
            self._snapshot_version(node, blob_path)

        shutil.copy2(version_path, blob_path)
        if target_version:
            node["size"] = target_version["size"]
        node["mtime"] = time.time()
        self._dirty = True
        self._save_manifest()

    # ---------- search ----------

    def search(self, query: str, by: str = "name") -> list[dict]:
        results = []
        query_l = query.lower()

        def walk(node: dict, path: str):
            for child in node.get("children", []):
                child_path = f"{path}/{child['name']}"
                matched = False
                if by == "name" and query_l in child["name"].lower():
                    matched = True
                elif by == "ext" and child["type"] == "file" and child.get("ext", "").lower() == query_l.lstrip("."):
                    matched = True
                elif by == "folder" and child["type"] == "folder" and query_l in child["name"].lower():
                    matched = True
                if matched:
                    results.append({"path": child_path, "node": child})
                if child["type"] == "folder":
                    walk(child, child_path)

        walk(self.tree, "")
        return results


def _secure_delete(path: str) -> None:
    if not os.path.exists(path):
        return
    try:
        length = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        os.remove(path)


def secure_delete_tree(root: str) -> None:
    if not os.path.exists(root):
        return
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        for fname in filenames:
            _secure_delete(os.path.join(dirpath, fname))
    shutil.rmtree(root, ignore_errors=True)
