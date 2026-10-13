"""Tamper-evident hash chain for audit events (no Django).

Each event stores prev_hash and hash = HMAC-SHA256(key, prev_hash + "\\n" + canonical_json(payload)).
Editing or deleting a row in the middle breaks the link to the next row. With a secret HMAC key
that the database role does not have, someone with only DB write access cannot recompute a
valid chain. Deleting the NEWEST rows is not detectable from the table alone, so export the
head hash (see verify_audit_chain) to separate storage on a schedule.

Sequence numbers are NOT required to be contiguous: PostgreSQL sequences skip values when a
transaction rolls back, so gaps are normal. The prev_hash link is what proves continuity.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

GENESIS = "0" * 64


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def compute_hash(prev_hash: str, payload: Mapping[str, Any], key: Optional[bytes] = None) -> str:
    msg = prev_hash.encode("ascii") + b"\n" + canonical_json(payload)
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    checked: int
    head_hash: str
    first_bad_seq: Optional[int] = None
    reason: str = ""


def verify_chain(records: Iterable[Mapping[str, Any]], key: Optional[bytes] = None, *,
                 start_prev: str = GENESIS) -> ChainVerification:
    """records: iterable ordered by seq, each with keys seq, prev_hash, hash, payload."""
    prev = start_prev
    checked = 0
    last_seq = None
    for rec in records:
        seq = rec["seq"]
        if last_seq is not None and seq <= last_seq:
            return ChainVerification(False, checked, prev, seq, "sequence not increasing")
        if not hmac.compare_digest(str(rec["prev_hash"]), prev):
            return ChainVerification(False, checked, prev, seq,
                                     "prev_hash does not match previous record (row removed, inserted or reordered)")
        expected = compute_hash(prev, rec["payload"], key)
        if not hmac.compare_digest(str(rec["hash"]), expected):
            return ChainVerification(False, checked, prev, seq,
                                     "hash mismatch (row content altered or wrong HMAC key)")
        prev = rec["hash"]
        last_seq = seq
        checked += 1
    return ChainVerification(True, checked, prev)
