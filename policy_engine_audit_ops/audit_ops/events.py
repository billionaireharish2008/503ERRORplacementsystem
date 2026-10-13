"""Audit event vocabulary and the single place where an event is cleaned and shaped. No Django.

prepare_event() output is exactly what gets hashed AND stored, so the chain can be re-verified
later from table columns (payload_from_row) without keeping a second copy of the data.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional

from .context import valid_request_id
from .sanitize import clean_value, sanitize_log_value

MAX_JSON_BYTES = 16_384     # per before/after/metadata; stops log flooding / giant PII dumps


class Action(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST"
    RECORD_CREATE = "RECORD_CREATE"
    RECORD_UPDATE = "RECORD_UPDATE"
    RECORD_DELETE = "RECORD_DELETE"
    OFFER_CHANGE = "OFFER_CHANGE"
    PACKAGE_CHANGE = "PACKAGE_CHANGE"
    POLICY_DECISION = "POLICY_DECISION"
    EXCEPTION_REQUEST = "EXCEPTION_REQUEST"
    EXCEPTION_APPROVE = "EXCEPTION_APPROVE"
    EXCEPTION_REJECT = "EXCEPTION_REJECT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    DATA_EXPORT = "DATA_EXPORT"
    AUDIT_VIEW = "AUDIT_VIEW"
    AUDIT_EXPORT = "AUDIT_EXPORT"
    AUDIT_VERIFY = "AUDIT_VERIFY"
    BACKUP_CREATED = "BACKUP_CREATED"
    BACKUP_RESTORED = "BACKUP_RESTORED"
    CONFIG_CHANGE = "CONFIG_CHANGE"


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"      # attempted, did not work (bad credentials, validation error)
    DENIED = "DENIED"        # refused by permission or policy
    REVIEW = "REVIEW"        # routed to a human
    ERROR = "ERROR"          # system fault


PAYLOAD_FIELDS = ("event_id", "timestamp", "actor_id", "action", "target_type", "target_id",
                  "outcome", "request_id", "source_ip", "before", "after", "metadata")
_JSON_FIELDS = ("before", "after", "metadata")


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace(" ", "T").replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)      # DB stores naive UTC


def changed_only(before: Optional[Mapping], after: Optional[Mapping]):
    """Keep only fields that differ. Less data stored = less PII exposed."""
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return before, after
    keys = [k for k in set(before) | set(after) if before.get(k) != after.get(k)]
    return ({k: before.get(k) for k in sorted(keys, key=str) if k in before},
            {k: after.get(k) for k in sorted(keys, key=str) if k in after})


def _bounded(value: Any):
    if value is None:
        return None
    if len(json.dumps(value, sort_keys=True, default=str)) > MAX_JSON_BYTES:
        keys = sorted(value.keys(), key=str)[:50] if isinstance(value, Mapping) else None
        return {"_truncated": True, "_keys": [sanitize_log_value(k, 100) for k in keys or []]}
    return value


def prepare_event(*, action, target_type: str, target_id: Any, outcome=Outcome.SUCCESS,
                  actor_id: Any = "system", request_id: str = "-", source_ip: str = "",
                  before: Any = None, after: Any = None, metadata: Optional[Mapping] = None,
                  timestamp: Optional[datetime] = None, event_id: Optional[str] = None,
                  minimise: bool = True) -> Dict[str, Any]:
    """Validate vocabulary, drop unchanged fields, redact secrets, mask PII, bound size."""
    action = Action(action)                     # ValueError on unknown action: no free-text actions
    outcome = Outcome(outcome)
    timestamp = timestamp or datetime.now(timezone.utc)
    # before/after are always JSON objects (or None) so they round-trip through any DB unchanged
    before = {"value": before} if before is not None and not isinstance(before, Mapping) else before
    after = {"value": after} if after is not None and not isinstance(after, Mapping) else after
    if minimise:
        before, after = changed_only(before, after)
    return {
        "event_id": str(uuid.UUID(event_id)) if event_id else str(uuid.uuid4()),
        "timestamp": iso_utc(timestamp),
        "actor_id": sanitize_log_value(actor_id, 128),
        "action": action.value,
        "target_type": sanitize_log_value(target_type, 64),
        "target_id": sanitize_log_value(target_id, 128),
        "outcome": outcome.value,
        "request_id": request_id if valid_request_id(request_id) else "-",
        "source_ip": sanitize_log_value(source_ip, 45),
        "before": _bounded(clean_value(before)),
        "after": _bounded(clean_value(after)),
        "metadata": _bounded(clean_value(metadata or {})) or {},
    }


def payload_from_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Rebuild the hashed payload from stored column values (Django model or raw SQLite row)."""
    ts = row["timestamp"]
    ts = parse_ts(ts) if isinstance(ts, str) else ts
    out: Dict[str, Any] = {f: row[f] for f in PAYLOAD_FIELDS}
    out["event_id"] = str(uuid.UUID(str(row["event_id"])))
    out["timestamp"] = iso_utc(ts)
    for f in _JSON_FIELDS:
        v = out[f]
        out[f] = json.loads(v) if isinstance(v, (str, bytes)) else v
    out["source_ip"] = out["source_ip"] or ""
    return out
