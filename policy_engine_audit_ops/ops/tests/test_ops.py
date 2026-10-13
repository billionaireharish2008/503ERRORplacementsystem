import base64
import io
import os
import shutil
import sqlite3
import tarfile
import tempfile
import unittest

from ops import dep_check, drill, secret_scan
from ops.backup import create_backup, restore_backup
from ops.crypto_stream import BackupCryptoError, decrypt_file, encrypt_file, generate_key

FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
RANDOMISH = "Zk9" + "qL2vT8xW4pR7sN1mC6bY3hD5fG0jA9eU"  # secret-scan: allow
PW = "Tr0ub4dor" + "AndTh3"


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.key = base64.b64decode(generate_key())

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _enc(self, data: bytes):
        src, enc, out = (os.path.join(self.d, n) for n in ("p", "e", "o"))
        with open(src, "wb") as fh:
            fh.write(data)
        encrypt_file(src, enc, self.key)
        return enc, out

    def test_round_trip_multi_chunk_and_empty(self):
        for data in (b"", b"hello", os.urandom((1 << 20) * 2 + 123)):
            enc, out = self._enc(data)
            decrypt_file(enc, out, self.key)
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), data)
            os.remove(out)

    def test_file_modes_private(self):
        enc, _ = self._enc(b"x")
        self.assertEqual(os.stat(enc).st_mode & 0o077, 0)

    def test_wrong_key_flip_truncate_extend_all_fail(self):
        data = os.urandom((1 << 20) * 2 + 5)
        enc, out = self._enc(data)
        with self.assertRaises(BackupCryptoError):
            decrypt_file(enc, out, os.urandom(32))
        with open(enc, "rb") as fh:
            raw = fh.read()
        variants = {"flip": raw[:100] + bytes([raw[100] ^ 1]) + raw[101:],
                    "truncate_at_chunk": raw[:28 + 4 + (1 << 20) + 16],
                    "truncate_tail": raw[:-5],
                    "extend": raw + b"\x00\x00\x00\x20" + os.urandom(32)}
        for name, blob in variants.items():
            p = os.path.join(self.d, name)
            with open(p, "wb") as fh:
                fh.write(blob)
            with self.assertRaises(BackupCryptoError, msg=name):
                decrypt_file(p, out, self.key)
            self.assertFalse(os.path.exists(out), "partial plaintext must be removed")


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.key = base64.b64decode(generate_key())
        self.db = os.path.join(self.d, "src.sqlite3")
        c = sqlite3.connect(self.db)
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        c.executemany("INSERT INTO t (v) VALUES (?)", [(f"row{i}",) for i in range(50)])
        c.commit()
        c.close()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_end_to_end(self):
        os.makedirs(os.path.join(self.d, "media"))
        with open(os.path.join(self.d, "media", "a.txt"), "w") as fh:
            fh.write("hi")
        info = create_backup(out_dir=os.path.join(self.d, "b"), key=self.key, db_kind="sqlite", db_path=self.db,
                             includes=[("media", os.path.join(self.d, "media"))])
        res = restore_backup(enc_path=info["path"], key=self.key, target_dir=os.path.join(self.d, "r"))
        self.assertEqual(res["sqlite_integrity_check"], "ok")
        self.assertTrue(os.path.exists(os.path.join(self.d, "r", "media", "a.txt")))
        n = sqlite3.connect(os.path.join(self.d, "r", "db.sqlite3")).execute("SELECT COUNT(*) FROM t").fetchone()[0]
        self.assertEqual(n, 50)

    def test_manifest_checksum_mismatch_and_non_empty_target(self):
        info = create_backup(out_dir=os.path.join(self.d, "b"), key=self.key, db_kind="sqlite", db_path=self.db)
        with open(info["path"], "ab") as fh:
            fh.write(b"x")
        with self.assertRaises(BackupCryptoError):
            restore_backup(enc_path=info["path"], key=self.key, target_dir=os.path.join(self.d, "r"))

    def test_refuses_production_without_flag(self):
        info = create_backup(out_dir=os.path.join(self.d, "b"), key=self.key, db_kind="sqlite", db_path=self.db)
        os.environ["NFSU_ENV"] = "production"
        try:
            with self.assertRaises(SystemExit):
                restore_backup(enc_path=info["path"], key=self.key, target_dir=os.path.join(self.d, "r"))
        finally:
            del os.environ["NFSU_ENV"]

    def test_path_traversal_archive_rejected(self):
        evil = os.path.join(self.d, "evil.tar.gz")
        with tarfile.open(evil, "w:gz") as tar:
            ti = tarfile.TarInfo("../escape.txt")
            ti.size = 3
            tar.addfile(ti, io.BytesIO(b"bad"))
        enc = os.path.join(self.d, "evil.bak.enc")
        encrypt_file(evil, enc, self.key)
        with self.assertRaises(BackupCryptoError):
            restore_backup(enc_path=enc, key=self.key, target_dir=os.path.join(self.d, "r"))
        self.assertFalse(os.path.exists(os.path.join(self.d, "escape.txt")))

    def test_full_drill_passes(self):
        report = drill.run_drill(self.d, hmac_key=b"h" * 32)
        failed = [c for c in report["checks"] if not c["passed"]]
        self.assertEqual(failed, [])
        self.assertTrue(report["passed"])


class SecretScanTests(unittest.TestCase):
    def test_detects_without_printing_secret(self):
        found = secret_scan.scan_text("a.py", f'KEY = "{FAKE_AWS}"\npassword = "{PW}"\n')  # secret-scan: allow
        self.assertEqual({f.rule for f in found}, {"aws-access-key-id", "assigned-secret"})
        for f in found:
            self.assertNotIn(FAKE_AWS, f.render())
            self.assertNotIn(PW, f.render())

    def test_high_entropy_string(self):
        self.assertTrue(secret_scan.scan_text("a.py", f'x = "{RANDOMISH}"'))

    def test_benign_values_ignored(self):
        text = 'password = os.environ["PW"]\nSECRET_KEY = "<generate>"\ntoken = request.GET["t"]\n'
        self.assertEqual(secret_scan.scan_text("a.py", text), [])

    def test_allow_marker(self):
        self.assertEqual(secret_scan.scan_text("a.py", f'k = "{FAKE_AWS}"  # secret-scan: allow'), [])

    def test_forbidden_files(self):
        self.assertIsNotNone(secret_scan.forbidden_file("config/.env"))
        self.assertIsNotNone(secret_scan.forbidden_file("db.sqlite3"))
        self.assertIsNone(secret_scan.forbidden_file(".env.example"))

    def test_tree_scan_and_baseline(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "x.py"), "w") as fh:
                fh.write(f'k = "{FAKE_AWS}"\n')
            self.assertEqual(secret_scan.main(["--root", d]), 1)
            self.assertEqual(secret_scan.main(["--root", d, "--update-baseline"]), 0)
            self.assertEqual(secret_scan.main(["--root", d]), 0)
            with open(os.path.join(d, "y.py"), "w") as fh:
                fh.write(f'k2 = "{FAKE_AWS}"\n')
            self.assertEqual(secret_scan.main(["--root", d]), 1)       # new file => new fingerprint
        finally:
            shutil.rmtree(d, ignore_errors=True)


class DepCheckTests(unittest.TestCase):
    def test_pinned_ok(self):
        self.assertEqual(dep_check.check_requirements("Django==5.1.4\ncryptography==44.0.0 ; python_version>'3'\n# c\n"), [])

    def test_unpinned_and_vcs_flagged(self):
        p = dep_check.check_requirements("Django\nrequests>=2\ngit+https://x/y.git\nflask==3.0.0\n")
        self.assertEqual(len(p), 3)

    def test_hashes_required(self):
        h = "a" * 64
        self.assertEqual(dep_check.check_requirements(f"django==5.1.4 \\\n    --hash=sha256:{h}\n", True), [])
        self.assertEqual(len(dep_check.check_requirements("django==5.1.4\n", True)), 1)


if __name__ == "__main__":
    unittest.main()
