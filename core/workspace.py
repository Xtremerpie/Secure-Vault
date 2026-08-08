"""
core/workspace.py — manages the secure temporary workspace a vault decrypts
individual files into when the user opens them (lazy, not the whole vault
at once — see README for why).
"""

from __future__ import annotations

import os
import stat
import tempfile

from . import vault as vault_mod


class TempWorkspace:
    def __init__(self, engine: "vault_mod.VaultEngine"):
        self.engine = engine
        self.root = tempfile.mkdtemp(prefix="securevault_")
        self._restrict_permissions(self.root)
        self.vault_to_local: dict[str, str] = {}
        self.local_to_vault: dict[str, str] = {}

    @staticmethod
    def _restrict_permissions(path: str) -> None:
        try:
            os.chmod(path, stat.S_IRWXU)  # rwx for owner only (POSIX)
        except OSError:
            pass  # best-effort; no-op on platforms that don't support it

    def _local_path_for(self, vault_path: str) -> str:
        rel = vault_path.replace("\\", "/").lstrip("/")
        local = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(local), exist_ok=True)
        return local

    def open_file(self, vault_path: str) -> str:
        """Decrypt (if not already extracted) and return a real local path
        that can be handed to the OS to open in the default application."""
        existing = self.vault_to_local.get(vault_path)
        if existing and os.path.exists(existing):
            return existing

        local_path = self._local_path_for(vault_path)
        self.engine.extract_node_to(vault_path, local_path)
        self.vault_to_local[vault_path] = local_path
        self.local_to_vault[local_path] = vault_path
        return local_path

    def register_new_local_file(self, vault_path: str, local_path: str) -> None:
        """Used when a file is created directly in the workspace (e.g. 'New File')."""
        self.vault_to_local[vault_path] = local_path
        self.local_to_vault[local_path] = vault_path

    def vault_path_for_local(self, local_path: str) -> str | None:
        return self.local_to_vault.get(local_path)

    def sync_change(self, local_path: str) -> bool:
        """Re-encrypt a locally-modified file back into the vault. Returns
        True if it was a tracked file and got synced. If the file was
        moved/renamed/deleted in the vault since it was opened (and never
        remapped via remap_path), this skips it rather than raising —
        losing sync for an orphaned temp file is safer than crashing."""
        vault_path = self.local_to_vault.get(local_path)
        if not vault_path or not os.path.exists(local_path):
            return False
        try:
            self.engine.ingest_local_change(vault_path, local_path)
            return True
        except Exception:
            return False

    def remap_path(self, old_vault_path: str, new_vault_path: str) -> None:
        """Call this after a move/rename in the vault so any already-open
        temp files under the old path keep syncing correctly under the
        new one. Handles both a single file and a whole moved folder
        (prefix rewrite)."""
        for local_path, vpath in list(self.local_to_vault.items()):
            if vpath == old_vault_path or vpath.startswith(old_vault_path.rstrip("/") + "/"):
                new_vpath = new_vault_path + vpath[len(old_vault_path):]
                self.local_to_vault[local_path] = new_vpath
                self.vault_to_local.pop(vpath, None)
                self.vault_to_local[new_vpath] = local_path

    def sync_all(self) -> None:
        for local_path in list(self.local_to_vault.keys()):
            if os.path.exists(local_path):
                self.sync_change(local_path)

    def close(self) -> None:
        """Sync any pending changes, then securely wipe the whole workspace."""
        self.sync_all()
        vault_mod.secure_delete_tree(self.root)
        self.vault_to_local.clear()
        self.local_to_vault.clear()
