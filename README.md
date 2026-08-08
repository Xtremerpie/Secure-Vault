# SecureVault V2.1

A vault that behaves like a normal folder — double-click to open, edit in
whatever app you normally use, drag-and-drop files in and around, and
everything is re-encrypted automatically. Includes recovery keys, version
history, real thumbnail previews, and in-app drag-to-move.

**Every claim below is backed by an automated test, not just described.**
Run `python -m pytest test_core.py -v` (33 tests) and
`QT_QPA_PLATFORM=offscreen python3 smoke_test_gui.py` yourself.

## How it actually works

```
Unlock (password OR recovery key) ──▶ both unwrap the same master key
                                              │
                                    decrypt manifest (folder tree)
                                              │
                                    Vault Explorer window
                              (folders/files, just like a file manager)
                                              │
                    double-click a file ──▶ decrypt THAT FILE ONLY
                                              into a temp workspace
                                              │
                            opens in your default app (Word, Preview, etc.)
                                              │
                                you edit + save in that app
                                              │
                    a file watcher (watchdog) notices the save
                                              │
                    old content snapshotted as a version, then
                    re-encrypted back into the vault, automatically
                                              │
                                click "Lock Vault"
                                              │
                pending changes flushed → temp files overwritten with
                random bytes then deleted → key wiped from memory
```

The master key is never derived from your password directly — it's a
random key that gets *wrapped* separately under your password and under a
recovery key. That's what makes both "unlock with password" and "unlock
with recovery key" work, and what makes changing your password cheap
(only the small wrapped key gets re-wrapped, not every file).

Only the file(s) you actually open ever touch a temp folder in plaintext —
not the whole vault. That keeps unlock fast and the plaintext footprint on
disk as small as possible.

## Project layout

```
securevault/
  core/
    crypto.py       AES-256-GCM: single-shot for small data (manifest,
                     wrapped keys), chunked streaming for files (never
                     loads a whole large file into memory)
    vault.py         VaultEngine — manifest tree, all file operations,
                     recovery-key + password-change support, version
                     history (last 5 versions per file, auto-pruned)
    workspace.py     TempWorkspace — lazy decrypt-on-open, path remapping
                     when a tracked-open file gets moved, secure wipe
    watcher.py       VaultWatcher — watchdog-based, debounced, re-encrypts
                     a file back into the vault ~1.2s after it's saved
  ui/
    login_dialog.py  Unlock (password), Unlock with recovery key, or
                     create a new vault
    main_window.py   Explorer window: folder tree + file list + preview
                     pane, real image/PDF thumbnails, drag-and-drop both
                     from the OS (import) and within the app (move),
                     multi-file open, version history dialog, change
                     password, regenerate recovery key, 10-min auto-lock
  app.py             Entry point
  test_core.py        33 automated tests
  smoke_test_gui.py   Headless GUI test — drives MainWindow's real code
                     paths without a display (see note below)
```

## Run it

```bash
pip install -r requirements.txt
python app.py
```

First run: "New vault" tab, choose a location, set a password. **A
recovery key is generated and shown once** — write it down, it can't be
retrieved again, and it's the only way in if you forget your password.

After that: "Unlock vault" with your password, or "Unlock with recovery
key" if you've forgotten it.

Once unlocked:
- **Double-click a file** → opens in your normal default app. Edit and
  save it there — it syncs back into the vault automatically within
  about a second, and the previous content is kept as a version.
- **Drag files/folders in** from your OS file manager → imported into the
  current vault folder, encrypted on the way in.
- **Drag an item onto a folder** (in the tree, or onto a folder row in the
  file list) → moves it, entirely within the app.
- **Select a file** → text files preview inline; images and PDFs render a
  real thumbnail; other types tell you to double-click.
- **Right-click → Version History** on a file → see up to 5 previous
  versions with timestamps, restore any of them (restoring itself creates
  a new version of what it replaced, so it's non-destructive).
- **Select multiple files → Open** (right-click) opens all of them at
  once, not just the first.
- Toolbar: new folder/file, import, export (single or multiple files),
  rename, delete, search, change password, generate a new recovery key,
  and lock.
- **Lock Vault** (toolbar, or just close the window) flushes pending
  edits, securely wipes the temp workspace, clears the key from memory.

## What's tested and proven

| Claim | Status |
|---|---|
| Filenames/folder structure unreadable on disk while locked | ✅ tested |
| Wrong password / wrong recovery key rejected without exposing content | ✅ tested |
| Recovery key unlocks the vault; changing password doesn't break it | ✅ tested |
| Changing password rotates access without re-encrypting all data | ✅ tested |
| Regenerating the recovery key invalidates the old one | ✅ tested |
| Large files encrypted/decrypted in chunks, never fully loaded into memory | ✅ tested with a 5MB+ file |
| Create/rename/move/delete folders & files, recursive delete removes blobs *and* version history | ✅ tested |
| Import a whole external folder recursively | ✅ tested |
| Search by name / extension | ✅ tested |
| **Open a file → external app edits it → auto re-encrypts, no manual save** | ✅ tested end-to-end — the core "acts like a normal folder" claim |
| Editing a file snapshots the previous content as a version | ✅ tested |
| Restoring a version is non-destructive (current content becomes a version too) | ✅ tested |
| Version history capped at 5, oldest pruned and securely deleted | ✅ tested |
| Moving a folder that has an open/tracked file inside it doesn't crash sync-on-close | ✅ tested (this was a real bug I found via the smoke test and fixed — see below) |
| Lock securely wipes the temp workspace | ✅ tested |
| GUI wiring: tree/list/preview/drag-drop/move/search/version-history/lock all call the right engine methods, including real image thumbnail rendering | ✅ smoke-tested headlessly |
| Actual visual appearance / manual clicking-around | ⚠️ **not verified** — this sandbox has no display, so nothing was ever rendered or clicked by a human. Please open it yourself and tell me if anything looks or feels off. |

### A bug the tests actually caught

Moving a folder that had a file open in the temp workspace used to crash
the app when you locked the vault — the workspace kept trying to sync the
file back to its *old* path, which no longer existed after the move. The
GUI smoke test caught this on the first run. Fixed by having moves remap
any open workspace paths, and by making sync-back fail quietly (skip,
don't crash) if a path is ever orphaned some other way. There's now a
dedicated regression test for both halves of that fix.

## Remaining gaps (honestly, not glossed over)

- **Video thumbnails** — would need `ffmpeg` or similar; not included.
- **Mounting as a real drive letter (V4, WinFsp/Dokan)** — a much bigger,
  platform-specific project, intentionally out of scope here. The
  temp-workspace approach gets close to the same feel with far less
  complexity.
- **No offline-attack rate limiting beyond PBKDF2 cost** — 200,000
  iterations slows down password-guessing against a stolen vault folder,
  but doesn't stop it. A weak password is still a weak password.
- **Rename/move validation is basic** — no protection yet against, e.g.,
  reserved filenames on Windows.

## A security note, stated plainly

This encrypts file contents and hides filenames/folder structure at rest,
and now supports account recovery without weakening that. It does **not**
protect against a keylogger, a compromised OS, or a weak/guessable
password. Treat it as solid protection against "someone finds or steals
the vault folder," not against a compromised computer.
