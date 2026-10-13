"""Per-request context (request/correlation ID, actor, source IP) via contextvars. No Django."""
from __future__ import annotations

import ipaddress
import re
import uuid
from contextvars import ContextVar
from typing import Mapping

request_id_var: ContextVar[str] = ContextVar("audit_request_id", default="-")
actor_id_var: ContextVar[str] = ContextVar("audit_actor_id", default="-")
source_ip_var: ContextVar[str] = ContextVar("audit_source_ip", default="")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def new_request_id() -> str:
    return uuid.uuid4().hex


def valid_request_id(value: str) -> bool:
    return bool(value) and bool(_REQUEST_ID_RE.match(value))


def client_ip(meta: Mapping[str, str], trusted_proxies: int = 0) -> str:
    """REMOTE_ADDR unless exactly `trusted_proxies` proxies you control append to X-Forwarded-For.
    Never trust the left-most X-Forwarded-For entry: the client can set it to anything."""
    remote = meta.get("REMOTE_ADDR", "")
    candidate = remote
    if trusted_proxies > 0:
        parts = [p.strip() for p in meta.get("HTTP_X_FORWARDED_FOR", "").split(",") if p.strip()]
        if len(parts) >= trusted_proxies:
            candidate = parts[-trusted_proxies]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "invalid"
