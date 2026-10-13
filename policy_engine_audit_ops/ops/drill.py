"""Restore drill: proves a backup can actually be recovered, and writes an evidence report.

    python -m ops.drill --report-dir drill_reports                 # synthetic data, ephemeral key
    python -m ops.drill --sqlite-path copy_of_test.sqlite3 --report-dir drill_reports   # a COPY of real data

Steps: snapshot -> encrypted backup -> simulate disaster (delete DB) -> restore to a fresh directory ->
compare row counts and audit-chain head -> re-verify the audit hash chain -> confirm that a tampered
backup and a wrong key are both rejected. Exit code 0 only if every check passes. Run it against a
PostgreSQL test instance with `ops.backup` + pg_restore for the production-like rehearsal (see the runbook).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from audit_ops.chain import GENESIS, compute_hash, verify_chain
from audit_ops.events import PAYLOAD_FIELDS, Action, Outcome, payload_from_row, prepare_event

from .backup import create_backup, restore_backup
from .crypto_stream import BackupCryptoError, generate_key, load_key
import base64

AUDIT_TABLE = "audit_ops_auditevent"
_SCHEMA = f"""CREATE TABLE {AUDIT_TABLE} (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, timestamp TEXT, actor_id TEXT, action TEXT,
  target_type TEXT, target_id TEXT, outcome TEXT, request_id TEXT, source_ip TEXT,
  before TEXT, after TEXT, metadata TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE placement_records (id INTEGER PRIMARY KEY, placement_id TEXT, status TEXT);"""


def make_synthetic_db(path: str, key: Optional[bytes], rows: int = 300) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    prev, t0 = GENESIS, datetime(2026, 10, 1, tzinfo=timezone.utc)
    actions = [Action.POLICY_DECISION, Action.OFFER_CHANGE, Action.EXCEPTION_APPROVE, Action.LOGIN_SUCCESS]
    for i in range(rows):
        f = prepare_event(action=actions[i % 4], target_type="drive_application", target_id=f"P{i:04d}:D1",
                          outcome=Outcome.SUCCESS, actor_id=str(i % 7 + 1), request_id=f"req-{i:08d}",
                          timestamp=t0 + timedelta(seconds=i), before={"status": "OPEN"}, after={"status": "DONE"})
        h = compute_hash(prev, f, key)
        conn.execute(f"INSERT INTO {AUDIT_TABLE} ({','.join(PAYLOAD_FIELDS)},prev_hash,hash) VALUES "
                     f"({','.join('?' * (len(PAYLOAD_FIELDS) + 2))})",
                     [json.dumps(f[c]) if c in ("before", "after", "metadata") else f[c] for c in PAYLOAD_FIELDS]
                     + [prev, h])
        conn.execute("INSERT INTO placement_records (placement_id,status) VALUES (?,?)", (f"P{i:04d}", "ACTIVE"))
        prev = h
    conn.commit()
    conn.close()


def snapshot(path: str, hmac_key: Optional[bytes]) -> Dict:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    counts = {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
    chain = None
    if AUDIT_TABLE in tables:
        recs = ({"seq": r["seq"], "prev_hash": r["prev_hash"], "hash": r["hash"],
                 "payload": payload_from_row(dict(r))}
                for r in conn.execute(f"SELECT * FROM {AUDIT_TABLE} ORDER BY seq"))
        v = verify_chain(recs, hmac_key)
        chain = {"ok": v.ok, "checked": v.checked, "head": v.head_hash, "reason": v.reason}
    conn.close()
    return {"row_counts": counts, "audit_chain": chain}


def run_drill(workdir: str, sqlite_path: Optional[str] = None, hmac_key: Optional[bytes] = None) -> Dict:
    checks: List[Dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(ok), "detail": detail})

    master = load_key() if os.environ.get("BACKUP_ENCRYPTION_KEY") else base64.b64decode(generate_key())
    src = sqlite_path or os.path.join(workdir, "source.sqlite3")
    if not sqlite_path:
        make_synthetic_db(src, hmac_key)
    before = snapshot(src, hmac_key)
    check("source audit chain verifies before backup", before["audit_chain"] is None or before["audit_chain"]["ok"])

    backups = os.path.join(workdir, "backups")
    info = create_backup(out_dir=backups, key=master, db_kind="sqlite", db_path=src, label="drill")
    check("encrypted backup written", os.path.getsize(info["path"]) > 0, f"{info['bytes']} bytes")
    with open(info["path"], "rb") as fh:
        check("backup is not plaintext SQLite", b"SQLite format 3" not in fh.read(1 << 20))

    scratch = os.path.join(workdir, "restored")        # the "disaster": we restore without using src at all
    t0 = time.monotonic()
    res = restore_backup(enc_path=info["path"], key=master, target_dir=scratch)
    restore_s = round(time.monotonic() - t0, 3)
    after = snapshot(os.path.join(scratch, "db.sqlite3"), hmac_key)
    check("restored database passes integrity_check", res.get("sqlite_integrity_check") == "ok")
    check("row counts identical after restore", before["row_counts"] == after["row_counts"],
          json.dumps(after["row_counts"], sort_keys=True))
    if before["audit_chain"]:
        check("audit chain verifies after restore", after["audit_chain"]["ok"], after["audit_chain"]["reason"])
        check("audit head hash identical", before["audit_chain"]["head"] == after["audit_chain"]["head"])

    tampered = os.path.join(workdir, "tampered.bak.enc")
    shutil.copy(info["path"], tampered)
    shutil.copy(info["path"] + ".manifest.json", tampered + ".manifest.json")
    with open(tampered, "r+b") as fh:
        fh.seek(60)
        b = fh.read(1)
        fh.seek(60)
        fh.write(bytes([b[0] ^ 0xFF]))
    try:
        restore_backup(enc_path=tampered, key=master, target_dir=os.path.join(workdir, "t1"))
        check("tampered backup rejected", False)
    except BackupCryptoError:
        check("tampered backup rejected", True)
    try:
        restore_backup(enc_path=info["path"], key=os.urandom(32), target_dir=os.path.join(workdir, "t2"))
        check("wrong key rejected", False)
    except BackupCryptoError:
        check("wrong key rejected", True)

    return {"drill_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": "real-copy" if sqlite_path else "synthetic",
            "backup_seconds": info["backup_seconds"], "restore_seconds": restore_s,
            "backup_bytes": info["bytes"], "checks": checks, "passed": all(c["passed"] for c in checks),
            "note": "Measured on this host with this data size. Compare restore_seconds with the agreed RTO; "
                    "RPO equals the interval between scheduled backups."}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ops.drill")
    ap.add_argument("--sqlite-path", help="a COPY of a test database (never the live one)")
    ap.add_argument("--report-dir", default="drill_reports")
    ap.add_argument("--hmac-key-env", default="AUDIT_HMAC_KEY", help="env var holding the audit HMAC key, if any")
    a = ap.parse_args(argv)
    hk = os.environ.get(a.hmac_key_env)
    work = tempfile.mkdtemp(prefix="nfsu-drill-")
    os.chmod(work, 0o700)
    try:
        report = run_drill(work, a.sqlite_path, hk.encode() if hk else None)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    os.makedirs(a.report_dir, exist_ok=True)
    out = os.path.join(a.report_dir, f"restore_drill_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    for c in report["checks"]:
        print(("PASS  " if c["passed"] else "FAIL  ") + c["check"])
    print(f"\nbackup {report['backup_seconds']}s, restore {report['restore_seconds']}s -> {out}")
    print("DRILL PASSED" if report["passed"] else "DRILL FAILED")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
