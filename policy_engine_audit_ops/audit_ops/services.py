"""record_event(): the one function every sensitive code path calls. Needs Django."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from functools import lru_cache
from typing import Any, Mapping, Optional

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction

from .chain import GENESIS, ChainVerification, compute_hash, verify_chain
from .context import actor_id_var, client_ip, request_id_var, source_ip_var
from .events import Action, Outcome, parse_ts, prepare_event
from .models import AuditEvent
from .sinks import sink_from_config

log = logging.getLogger("nfsu.audit")


class AuditWriteError(RuntimeError):
    """Raised when a sensitive action could not be recorded; the caller must not proceed."""


def _hmac_key() -> Optional[bytes]:
    key = getattr(settings, "AUDIT_HMAC_KEY", None)
    if not key:
        if settings.DEBUG:
            return None
        raise ImproperlyConfigured("AUDIT_HMAC_KEY must be set outside DEBUG")
    return key.encode("utf-8")


@lru_cache(maxsize=1)
def _sink():
    return sink_from_config(getattr(settings, "AUDIT_LOG_PATH", None),
                            getattr(settings, "AUDIT_SYSLOG_HOST", None),
                            getattr(settings, "AUDIT_SYSLOG_PORT", 514))


def _actor_id(actor: Any) -> str:
    if actor is None:
        return actor_id_var.get() if actor_id_var.get() != "-" else "system"
    if isinstance(actor, str):
        return actor
    return str(actor.pk) if getattr(actor, "is_authenticated", False) else "anonymous"


def record_event(*, action, target_type: str, target_id: Any, outcome=Outcome.SUCCESS,
                 actor: Any = None, request=None, before: Any = None, after: Any = None,
                 metadata: Optional[Mapping] = None, fail_closed: bool = True,
                 minimise: bool = True) -> Optional[AuditEvent]:
    """Write one audit event (database row in the hash chain + JSONL/syslog copy).

    Call it INSIDE the same transaction as the business change so both commit or neither does.
    fail_closed=True (default): if the event cannot be stored, raise AuditWriteError so the caller
    aborts. Use False only for high-volume, low-risk events such as failed logins (the event is still
    written to the file sink and logged).
    """
    if request is not None:
        request_id = getattr(request, "request_id", request_id_var.get())
        ip = client_ip(request.META, getattr(settings, "AUDIT_TRUSTED_PROXY_COUNT", 0))
        if actor is None:
            actor = getattr(request, "user", None)
    else:
        request_id, ip = request_id_var.get(), source_ip_var.get()

    fields = prepare_event(action=action, target_type=target_type, target_id=target_id, outcome=outcome,
                           actor_id=_actor_id(actor), request_id=request_id, source_ip=ip,
                           before=before, after=after, metadata=metadata, minimise=minimise)
    try:
        with transaction.atomic():
            # Lock the newest row so concurrent writers extend the chain one at a time (PostgreSQL).
            last = AuditEvent.objects.select_for_update().order_by("-seq").only("seq", "hash").first()
            prev = last.hash if last else GENESIS
            digest = compute_hash(prev, fields, _hmac_key())
            event = AuditEvent.objects.create(
                event_id=uuid.UUID(fields["event_id"]), timestamp=parse_ts(fields["timestamp"]),
                actor_id=fields["actor_id"], action=fields["action"], target_type=fields["target_type"],
                target_id=fields["target_id"], outcome=fields["outcome"], request_id=fields["request_id"],
                source_ip=fields["source_ip"], before=fields["before"], after=fields["after"],
                metadata=fields["metadata"], prev_hash=prev, hash=digest)
    except Exception as exc:
        log.error("audit write failed action=%s error=%s", fields["action"], type(exc).__name__)
        sink = _sink()
        if sink:
            sink.write({**fields, "chain": "unlinked", "db_write": "failed"})
        if fail_closed:
            raise AuditWriteError("audit event could not be recorded") from exc
        return None

    sink = _sink()
    if sink:      # after commit, so a rolled-back business action leaves no phantom "success" line
        record = {**fields, "seq": event.seq, "prev_hash": prev, "hash": digest}
        transaction.on_commit(lambda: sink.write(record))
    return event


def iter_chain_records(batch: int = 2000):
    for ev in AuditEvent.objects.order_by("seq").iterator(chunk_size=batch):
        yield {"seq": ev.seq, "prev_hash": ev.prev_hash, "hash": ev.hash, "payload": ev.payload()}


def verify_db_chain() -> ChainVerification:
    return verify_chain(iter_chain_records(), _hmac_key())
