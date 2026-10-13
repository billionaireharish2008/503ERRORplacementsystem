import json
import logging
import unittest
from datetime import datetime, timezone

from audit_ops import chain
from audit_ops.events import Action, Outcome, changed_only, payload_from_row, prepare_event
from audit_ops.logging_config import JsonFormatter, RedactingFilter
from audit_ops.sanitize import (REDACTED, clean_text, clean_value, csv_safe, mask_pii_text,
                                redact_text, sanitize_log_value)

# Built at run time so this file itself never contains a scannable secret literal.
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "abcDEF123456ghiJKL"])
PW = "s3cr3t" + "Pa55w0rd"


class SanitizeTests(unittest.TestCase):
    def test_log_injection_newlines_and_ansi(self):
        out = sanitize_log_value("ok\nFAKE 2026 LOGIN admin SUCCESS\r\x1b[31mred")
        self.assertNotIn("\n", out)
        self.assertNotIn("\r", out)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\n", out)

    def test_bidi_and_unicode_line_separators_escaped_but_zwj_kept(self):
        out = sanitize_log_value("a\u202eb\u2028c\u200dd")
        self.assertNotIn("\u202e", out)
        self.assertNotIn("\u2028", out)
        self.assertIn("\u200d", out)

    def test_truncation(self):
        self.assertIn("truncated", sanitize_log_value("x" * 5000, max_len=100))

    def test_secrets_redacted_in_text(self):
        for raw in (f"password={PW}", f"key {FAKE_AWS}", f"Authorization: Bearer {FAKE_JWT}",  # secret-scan: allow
                    f"Cookie: sessionid={PW}abcdef", "GET /reset/MQ/5ab-" + "a1b2c3d4e5f6a7b8c9d0/",  # secret-scan: allow
                    f"postgres://app:{PW}@db:5432/x", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"):  # secret-scan: allow
            out = redact_text(raw)
            self.assertIn(REDACTED, out, raw)
            for needle in (PW, FAKE_AWS, FAKE_JWT, "a1b2c3d4e5f6a7b8c9d0", "AAAA"):
                self.assertNotIn(needle, out)

    def test_password_key_kept_value_removed(self):
        self.assertEqual(redact_text(f"password={PW}"), "password=" + REDACTED)  # secret-scan: allow

    def test_clean_value_redacts_by_key_and_masks_pii(self):
        out = clean_value({"username": "u1", "password": PW, "API_KEY": "abc", "email": "ravi@example.org",
                           "mobile": "9876543210", "nested": {"session_id": "zzz", "note": "hi\nthere"},
                           "name": "Ravi Kumar"})
        self.assertEqual(out["password"], REDACTED)
        self.assertEqual(out["API_KEY"], REDACTED)
        self.assertEqual(out["nested"]["session_id"], REDACTED)
        self.assertEqual(out["email"], "r***@example.org")
        self.assertTrue(out["mobile"].endswith("10") and "98765" not in out["mobile"])
        self.assertEqual(out["name"], "R***")
        self.assertNotIn("\n", out["nested"]["note"])

    def test_mask_pii_text(self):
        out = mask_pii_text("call 9876543210 or mail a.b@x.in id 1234 5678 9012")
        self.assertNotIn("9876543210", out)
        self.assertNotIn("a.b@", out)
        self.assertNotIn("1234 5678 9012", out)

    def test_csv_formula_injection(self):
        for bad in ("=cmd()", "+1", "-1", "@SUM(A1)"):
            self.assertTrue(csv_safe(bad).startswith("'"))
        self.assertEqual(csv_safe("plain"), "plain")


class EventTests(unittest.TestCase):
    def test_event_has_required_fields_and_masks(self):
        ev = prepare_event(action=Action.RECORD_UPDATE, target_type="student", target_id="P001",
                           actor_id="7", request_id="req-12345678", source_ip="10.0.0.5",
                           before={"email": "a@b.co", "status": "OPEN", "same": 1},
                           after={"email": "c@d.co", "status": "DONE", "same": 1})
        for f in ("event_id", "timestamp", "actor_id", "action", "target_type", "target_id", "outcome",
                  "request_id", "before", "after"):
            self.assertIn(f, ev)
        self.assertNotIn("same", ev["before"])                    # unchanged field not stored
        self.assertEqual(ev["before"]["email"], "a***@b.co")
        self.assertEqual(ev["request_id"], "req-12345678")

    def test_unknown_action_rejected_and_bad_request_id_neutralised(self):
        with self.assertRaises(ValueError):
            prepare_event(action="FREE TEXT\nINJECT", target_type="t", target_id="1")
        ev = prepare_event(action=Action.LOGOUT, target_type="t", target_id="1", request_id="bad id\n")
        self.assertEqual(ev["request_id"], "-")

    def test_huge_payload_bounded(self):
        ev = prepare_event(action=Action.DATA_EXPORT, target_type="t", target_id="1",
                           metadata={"rows": ["x" * 100] * 1000})
        self.assertTrue(ev["metadata"].get("_truncated"))

    def test_password_never_in_event(self):
        ev = prepare_event(action=Action.PASSWORD_CHANGE, target_type="user", target_id="1",
                           before={"password": "pbkdf2$old"}, after={"password": "pbkdf2$new"})  # secret-scan: allow
        self.assertNotIn("pbkdf2", json.dumps(ev))

    def test_changed_only(self):
        b, a = changed_only({"x": 1, "y": 2}, {"x": 1, "y": 3})
        self.assertEqual((b, a), ({"y": 2}, {"y": 3}))

    def test_payload_round_trip_from_row(self):
        ev = prepare_event(action=Action.OFFER_CHANGE, target_type="offer", target_id="O1",
                           outcome=Outcome.SUCCESS, timestamp=datetime(2026, 10, 1, 5, 6, 7, 8, tzinfo=timezone.utc),
                           before={"ctc": "10"}, after={"ctc": "12"})
        row = dict(ev, event_id=ev["event_id"].replace("-", ""), timestamp="2026-10-01 05:06:07.000008",
                   before=json.dumps(ev["before"]), after=json.dumps(ev["after"]),
                   metadata=json.dumps(ev["metadata"]))
        self.assertEqual(payload_from_row(row), ev)


class ChainTests(unittest.TestCase):
    KEY = b"k" * 32

    def build(self, n=5, key=KEY):
        recs, prev = [], chain.GENESIS
        for i in range(1, n + 1):
            p = {"i": i, "v": f"event-{i}"}
            h = chain.compute_hash(prev, p, key)
            recs.append({"seq": i * 2, "prev_hash": prev, "hash": h, "payload": p})   # gaps are fine
            prev = h
        return recs

    def test_valid_chain(self):
        r = chain.verify_chain(self.build(), self.KEY)
        self.assertTrue(r.ok)
        self.assertEqual(r.checked, 5)

    def test_edit_detected(self):
        recs = self.build()
        recs[2]["payload"]["v"] = "changed"
        r = chain.verify_chain(recs, self.KEY)
        self.assertFalse(r.ok)
        self.assertEqual(r.first_bad_seq, recs[2]["seq"])

    def test_delete_middle_detected(self):
        recs = self.build()
        del recs[2]
        self.assertFalse(chain.verify_chain(recs, self.KEY).ok)

    def test_reorder_detected(self):
        recs = self.build()
        recs[1], recs[2] = recs[2], recs[1]
        self.assertFalse(chain.verify_chain(recs, self.KEY).ok)

    def test_wrong_key_detected(self):
        self.assertFalse(chain.verify_chain(self.build(), b"x" * 32).ok)

    def test_attacker_without_key_cannot_forge(self):
        recs = self.build()
        recs[-1]["payload"]["v"] = "forged"
        recs[-1]["hash"] = chain.compute_hash(recs[-1]["prev_hash"], recs[-1]["payload"], None)   # plain sha256
        self.assertFalse(chain.verify_chain(recs, self.KEY).ok)


class LoggingTests(unittest.TestCase):
    def test_filter_and_formatter(self):
        rec = logging.LogRecord("t", logging.INFO, __file__, 1, "login password=%s from %s\nFORGED", (PW, "x"), None)
        RedactingFilter().filter(rec)
        line = JsonFormatter().format(rec)
        self.assertNotIn(PW, line)
        self.assertNotIn("\n", line)
        self.assertEqual(len(line.splitlines()), 1)

    def test_exception_text_redacted(self):
        try:
            raise ValueError(f"bad token={PW}")  # secret-scan: allow
        except ValueError:
            import sys
            rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
        self.assertNotIn(PW, JsonFormatter().format(rec))


if __name__ == "__main__":
    unittest.main()
