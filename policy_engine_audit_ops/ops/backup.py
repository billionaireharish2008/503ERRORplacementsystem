"""Create and restore encrypted backups.   python -m ops.backup --help

  create :  python -m ops.backup create --out /secure/backups --db-kind sqlite --db-path db.sqlite3 \
                --include audit_logs=/var/log/nfsu/audit --include media=/srv/nfsu/media
            python -m ops.backup create --out /secure/backups --db-kind postgres      (uses libpq env: PGHOST,
                PGUSER, PGDATABASE, PGPASSFILE ... -- no password is ever passed on a command line)
  restore:  python -m ops.backup restore --file X.bak.enc --target /tmp/restore-test
            (add --pg-restore-db NAME to load a PostgreSQL dump into a *scratch* database)

The key comes from BACKUP_ENCRYPTION_KEY (never from an argument). `python -m ops.backup genkey` makes one.
Plaintext only ever exists in a private temp directory (mode 0700) that is deleted afterwards; point
TMPDIR at an encrypted volume or tmpfs. Restores refuse to run when NFSU_ENV=production unless
--allow-production is given.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .crypto_stream import BackupCryptoError, decrypt_file, encrypt_file, generate_key, load_key, open_private

TOOL_VERSION = "1"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _private_tmp() -> str:
    d = tempfile.mkdtemp(prefix="nfsu-bk-")
    os.chmod(d, 0o700)
    return d


def _dump_sqlite(src: str, dst: str) -> None:
    # The online-backup API gives a consistent snapshot even while the app is writing.
    with sqlite3.connect(src) as source, sqlite3.connect(dst) as target:
        source.backup(target)


def _dump_postgres(dst: str, timeout: int = 3600) -> None:
    subprocess.run(["pg_dump", "--format=custom", "--no-owner", "--file", dst], check=True, timeout=timeout)


def create_backup(*, out_dir: str, key: bytes, db_kind: str, db_path: Optional[str] = None,
                  includes: Sequence[Tuple[str, str]] = (), label: str = "") -> Dict:
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tmp = _private_tmp()
    t0 = time.monotonic()
    try:
        contents: List[Dict] = []
        tar_path = os.path.join(tmp, "payload.tar.gz")
        if db_kind == "sqlite":
            if not db_path or not os.path.isfile(db_path):
                raise SystemExit("--db-path must point to an existing SQLite file")
            db_member = "db.sqlite3"
            _dump_sqlite(db_path, os.path.join(tmp, db_member))
        elif db_kind == "postgres":
            db_member = "db.dump"
            _dump_postgres(os.path.join(tmp, db_member))
        else:
            raise SystemExit("--db-kind must be sqlite or postgres")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(os.path.join(tmp, db_member), arcname=db_member)
            contents.append({"name": db_member, "kind": "database"})
            for name, path in includes:
                if os.path.exists(path):
                    tar.add(path, arcname=name)
                    contents.append({"name": name, "kind": "files"})
        enc_path = os.path.join(out_dir, f"nfsu-{stamp}{('-' + label) if label else ''}.bak.enc")
        encrypt_file(tar_path, enc_path, key)
        manifest = {"format": "NFSUBK01", "tool_version": TOOL_VERSION, "created_utc": stamp,
                    "db_kind": db_kind, "db_member": db_member, "contents": contents,
                    "bytes": os.path.getsize(enc_path), "sha256": sha256_file(enc_path),
                    "backup_seconds": round(time.monotonic() - t0, 3)}
        with open_private(enc_path + ".manifest.json", "w") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        return {**manifest, "path": enc_path}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _safe_members(tar: tarfile.TarFile):
    for m in tar.getmembers():
        parts = m.name.replace("\\", "/").split("/")
        if m.name.startswith(("/", "\\")) or ".." in parts or m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
            raise BackupCryptoError(f"unsafe archive member rejected: {m.name!r}")
        yield m


def restore_backup(*, enc_path: str, key: bytes, target_dir: str, manifest_path: Optional[str] = None,
                   pg_restore_db: Optional[str] = None, allow_production: bool = False,
                   force: bool = False) -> Dict:
    if os.environ.get("NFSU_ENV", "").lower() in ("production", "prod") and not allow_production:
        raise SystemExit("refusing to restore while NFSU_ENV=production (use a scratch host, or --allow-production)")
    manifest_path = manifest_path or enc_path + ".manifest.json"
    manifest = None
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        if sha256_file(enc_path) != manifest["sha256"]:
            raise BackupCryptoError("checksum mismatch: the backup file differs from its manifest")
    if os.path.isdir(target_dir) and os.listdir(target_dir) and not force:
        raise SystemExit(f"target {target_dir} is not empty (use --force to overwrite)")
    os.makedirs(target_dir, mode=0o700, exist_ok=True)

    tmp = _private_tmp()
    t0 = time.monotonic()
    try:
        tar_path = os.path.join(tmp, "payload.tar.gz")
        decrypt_file(enc_path, tar_path, key)
        with tarfile.open(tar_path, "r:gz") as tar:
            members = list(_safe_members(tar))
            kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extractall(target_dir, members=members, **kwargs)
        result: Dict = {"target": target_dir, "restore_seconds": 0.0, "manifest_checked": manifest is not None}
        sqlite_path = os.path.join(target_dir, "db.sqlite3")
        if os.path.exists(sqlite_path):
            with sqlite3.connect(sqlite_path) as conn:
                result["sqlite_integrity_check"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
        dump = os.path.join(target_dir, "db.dump")
        if os.path.exists(dump) and pg_restore_db:
            subprocess.run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--dbname", pg_restore_db, dump],
                           check=True, timeout=3600)
            result["pg_restored_into"] = pg_restore_db
        result["restore_seconds"] = round(time.monotonic() - t0, 3)
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def prune(out_dir: str, keep: int) -> List[str]:
    files = sorted(f for f in os.listdir(out_dir) if f.endswith(".bak.enc"))
    removed = []
    for f in files[:-keep] if keep > 0 else []:
        for suffix in ("", ".manifest.json"):
            p = os.path.join(out_dir, f + suffix)
            if os.path.exists(p):
                os.remove(p)
        removed.append(f)
    return removed


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="ops.backup")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey", help="print a new random backup key (store it in your secret manager)")
    c = sub.add_parser("create")
    c.add_argument("--out", required=True)
    c.add_argument("--db-kind", choices=["sqlite", "postgres"], required=True)
    c.add_argument("--db-path")
    c.add_argument("--include", action="append", default=[], metavar="NAME=PATH")
    c.add_argument("--label", default="")
    c.add_argument("--keep", type=int, default=0, help="after backing up, keep only the newest N (0 = keep all)")
    r = sub.add_parser("restore")
    r.add_argument("--file", required=True)
    r.add_argument("--target", required=True)
    r.add_argument("--pg-restore-db")
    r.add_argument("--allow-production", action="store_true")
    r.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "genkey":
        print(generate_key())
        return 0
    key = load_key()
    if a.cmd == "create":
        incs = [tuple(i.split("=", 1)) for i in a.include]
        info = create_backup(out_dir=a.out, key=key, db_kind=a.db_kind, db_path=a.db_path, includes=incs, label=a.label)
        print(json.dumps({k: info[k] for k in ("path", "bytes", "sha256", "backup_seconds")}, indent=2))
        if a.keep:
            prune(a.out, a.keep)
        return 0
    print(json.dumps(restore_backup(enc_path=a.file, key=key, target_dir=a.target, pg_restore_db=a.pg_restore_db,
                                    allow_production=a.allow_production, force=a.force), indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BackupCryptoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
