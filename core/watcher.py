"""
core/watcher.py — watches the temp workspace with `watchdog` and
automatically re-encrypts a file back into the vault a short moment after
it's saved (debounced, so we don't fire on every intermediate write an
editor makes while saving).
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .workspace import TempWorkspace


class _DebouncedHandler(FileSystemEventHandler):
    def __init__(self, workspace: TempWorkspace, on_synced: Optional[Callable[[str], None]],
                 debounce_seconds: float):
        self.workspace = workspace
        self.on_synced = on_synced
        self.debounce_seconds = debounce_seconds
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def _schedule(self, path: str) -> None:
        with self._lock:
            existing = self._timers.get(path)
            if existing:
                existing.cancel()
            timer = threading.Timer(self.debounce_seconds, self._fire, args=(path,))
            timer.daemon = True
            self._timers[path] = timer
            timer.start()

    def _fire(self, path: str) -> None:
        with self._lock:
            self._timers.pop(path, None)
        try:
            synced = self.workspace.sync_change(path)
        except Exception:
            synced = False
        if synced and self.on_synced:
            self.on_synced(path)

    def on_modified(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)


class VaultWatcher:
    """Watches a TempWorkspace's root directory and keeps the vault in sync
    with whatever an external application (Word, an image editor, ...)
    saves there."""

    def __init__(self, workspace: TempWorkspace, on_synced: Optional[Callable[[str], None]] = None,
                 debounce_seconds: float = 1.2):
        self.workspace = workspace
        self._handler = _DebouncedHandler(workspace, on_synced, debounce_seconds)
        self._observer: Optional[Observer] = None

    def start(self) -> None:
        if self._observer:
            return
        self._observer = Observer()
        self._observer.schedule(self._handler, self.workspace.root, recursive=True)
        self._observer.start()

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)
            self._observer = None
