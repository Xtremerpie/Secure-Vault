"""
core/crypto.py — encryption primitives for SecureVault V2.

- Key derivation: PBKDF2-HMAC-SHA256 from the user's password + a per-vault salt.
- Small data (manifest, verifier): single-shot AES-256-GCM.
- Files: chunked AES-256-GCM so we never hold a whole large file in memory
  either encrypting or decrypting.

Wire format for a chunked-encrypted blob:

    [8 bytes]  magic  b"SVLTCHNK"
    [4 bytes]  chunk_size (uint32, plaintext bytes per chunk before the last)
    [8 bytes]  total_plaintext_size (uint64)
    repeated:
        [12 bytes] nonce (unique per chunk)
        [4 bytes]  ciphertext_len (uint32)
        [ciphertext_len bytes] ciphertext (includes the 16-byte GCM tag)
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

KEY_LEN = 32          # AES-256
NONCE_LEN = 12         # standard GCM nonce size
DEFAULT_ITERATIONS = 200_000
DEFAULT_CHUNK_SIZE = 1024 * 1024   # 1 MiB
MAGIC = b"SVLTCHNK"


def new_salt() -> bytes:
    return os.urandom(16)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Single-shot AES-GCM encrypt. Returns nonce || ciphertext(+tag)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data or None)
    return nonce + ct


def decrypt_bytes(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return aesgcm.decrypt(nonce, ct, associated_data or None)


def encrypt_file_chunked(key: bytes, src_path: str, dest_path: str,
                          chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    """Stream-encrypt src_path into dest_path without loading it all into memory."""
    aesgcm = AESGCM(key)
    total_size = os.path.getsize(src_path)

    with open(src_path, "rb") as fin, open(dest_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack("<I", chunk_size))
        fout.write(struct.pack("<Q", total_size))

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            nonce = os.urandom(NONCE_LEN)
            ct = aesgcm.encrypt(nonce, chunk, None)
            fout.write(nonce)
            fout.write(struct.pack("<I", len(ct)))
            fout.write(ct)


def decrypt_file_chunked(key: bytes, src_path: str, dest_path: str) -> None:
    """Stream-decrypt src_path (produced by encrypt_file_chunked) into dest_path."""
    aesgcm = AESGCM(key)

    with open(src_path, "rb") as fin, open(dest_path, "wb") as fout:
        magic = fin.read(8)
        if magic != MAGIC:
            raise ValueError("not a valid SecureVault chunked blob")
        (chunk_size,) = struct.unpack("<I", fin.read(4))
        (total_size,) = struct.unpack("<Q", fin.read(8))
        written = 0

        while written < total_size:
            nonce = fin.read(NONCE_LEN)
            if len(nonce) < NONCE_LEN:
                break
            (ct_len,) = struct.unpack("<I", fin.read(4))
            ct = fin.read(ct_len)
            pt = aesgcm.decrypt(nonce, ct, None)
            fout.write(pt)
            written += len(pt)


def decrypt_file_chunked_to_bytes(key: bytes, src_path: str, max_bytes: int | None = None) -> bytes:
    """Decrypt straight to memory — for previews of small/medium files only."""
    aesgcm = AESGCM(key)
    out = bytearray()

    with open(src_path, "rb") as fin:
        magic = fin.read(8)
        if magic != MAGIC:
            raise ValueError("not a valid SecureVault chunked blob")
        (_chunk_size,) = struct.unpack("<I", fin.read(4))
        (total_size,) = struct.unpack("<Q", fin.read(8))

        written = 0
        while written < total_size:
            nonce = fin.read(NONCE_LEN)
            if len(nonce) < NONCE_LEN:
                break
            (ct_len,) = struct.unpack("<I", fin.read(4))
            ct = fin.read(ct_len)
            pt = aesgcm.decrypt(nonce, ct, None)
            out.extend(pt)
            written += len(pt)
            if max_bytes is not None and len(out) >= max_bytes:
                return bytes(out[:max_bytes])
    return bytes(out)


@dataclass
class KdfParams:
    salt: bytes
    iterations: int = DEFAULT_ITERATIONS

    def to_dict(self) -> dict:
        return {"salt": self.salt.hex(), "iterations": self.iterations}

    @staticmethod
    def from_dict(d: dict) -> "KdfParams":
        return KdfParams(salt=bytes.fromhex(d["salt"]), iterations=d["iterations"])
