"""Chunked AES-256-GCM file encryption for backups (needs the `cryptography` package).

Format:  MAGIC(8) | salt(16) | nonce_prefix(4) | { len(4, big-endian) | ciphertext+tag }*
Each chunk's nonce is prefix||counter and its AAD binds MAGIC, the counter and a "final" flag, so
reordering, dropping, truncating or appending chunks all fail authentication. The per-file key is
HKDF(master_key, salt). The master key is 32 random bytes, base64-encoded, supplied via the
BACKUP_ENCRYPTION_KEY environment variable (or *_FILE) and NEVER stored beside the backups.
"""
from __future__ import annotations

import base64
import os
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"NFSUBK01"
CHUNK = 1 << 20
KEY_ENV = "BACKUP_ENCRYPTION_KEY"


class BackupCryptoError(Exception):
    pass


def generate_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def load_key(env: Mapping[str, str] = os.environ) -> bytes:
    raw = env.get(KEY_ENV)
    if raw is None and env.get(KEY_ENV + "_FILE"):
        with open(env[KEY_ENV + "_FILE"], "r", encoding="ascii") as fh:
            raw = fh.read().strip()
    if not raw:
        raise BackupCryptoError(f"{KEY_ENV} is not set")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise BackupCryptoError(f"{KEY_ENV} is not valid base64") from exc
    if len(key) != 32:
        raise BackupCryptoError(f"{KEY_ENV} must decode to exactly 32 bytes")
    return key


def _file_key(master: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"nfsu-backup-v1").derive(master)


def _aad(counter: int, final: bool) -> bytes:
    return MAGIC + counter.to_bytes(8, "big") + (b"\x01" if final else b"\x00")


def open_private(path: str, mode: str = "wb"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, mode)


def encrypt_file(src: str, dst: str, master_key: bytes) -> None:
    salt, prefix = os.urandom(16), os.urandom(4)
    aes = AESGCM(_file_key(master_key, salt))
    with open(src, "rb") as fi, open_private(dst) as fo:
        fo.write(MAGIC + salt + prefix)
        counter, buf = 0, fi.read(CHUNK)
        while True:
            nxt = fi.read(CHUNK)
            final = not nxt
            ct = aes.encrypt(prefix + counter.to_bytes(8, "big"), buf, _aad(counter, final))
            fo.write(len(ct).to_bytes(4, "big") + ct)
            if final:
                break
            buf, counter = nxt, counter + 1
        fo.flush()
        os.fsync(fo.fileno())


def decrypt_file(src: str, dst: str, master_key: bytes) -> None:
    size = os.path.getsize(src)
    try:
        with open(src, "rb") as fi, open_private(dst) as fo:
            header = fi.read(28)
            if len(header) != 28 or header[:8] != MAGIC:
                raise BackupCryptoError("not an NFSU backup file (bad header)")
            salt, prefix = header[8:24], header[24:28]
            aes = AESGCM(_file_key(master_key, salt))
            counter = 0
            while True:
                raw_len = fi.read(4)
                if len(raw_len) != 4:
                    raise BackupCryptoError("backup is truncated")
                n = int.from_bytes(raw_len, "big")
                if n < 16 or n > CHUNK + 16:
                    raise BackupCryptoError("corrupt chunk length")
                ct = fi.read(n)
                if len(ct) != n:
                    raise BackupCryptoError("backup is truncated")
                final = fi.tell() == size
                try:
                    fo.write(aes.decrypt(prefix + counter.to_bytes(8, "big"), ct, _aad(counter, final)))
                except InvalidTag as exc:
                    raise BackupCryptoError("authentication failed: wrong key, or the backup was "
                                            "modified, truncated or extended") from exc
                if final:
                    break
                counter += 1
            fo.flush()
            os.fsync(fo.fileno())
    except BaseException:
        if os.path.exists(dst):
            os.remove(dst)
        raise
