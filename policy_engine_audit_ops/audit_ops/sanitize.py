"""Log-injection defence, secret redaction and PII masking. Standard library only (no Django).

Order matters: redact secrets FIRST (a private-key block spans lines), then escape control
characters, then truncate (so a secret is never cut in half and left partly visible).
"""
from __future__ import annotations

import re
import unicodedata
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Callable, Mapping, Optional

REDACTED = "[REDACTED]"
MASKED = "[MASKED]"
MAX_LOG_VALUE = 2000
MAX_INPUT_CHARS = 20_000      # hard cap before regex work, so huge inputs cannot burn CPU
MAX_DEPTH = 8

# --------------------------------------------------------------------------------------
# Secret patterns. If a pattern has a group named "secret", only that group is replaced
# (a password assignment keeps its key and loses its value); otherwise the whole match goes.
# Shared with ops/secret_scan.py so logs and the repository scanner use the same rules.
# --------------------------------------------------------------------------------------
SECRET_PATTERNS = (
    ("private-key-block", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{8,}=*)")),
    ("url-credentials", re.compile(
        r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<secret>[^\s/@]+)@")),
    ("cookie-value", re.compile(r"(?i)\b(?:sessionid|csrftoken|session|sid)=(?P<secret>[^;\s,]+)")),
    ("reset-link-token", re.compile(
        r"(?i)/(?:password[_-]?)?reset/[A-Za-z0-9_-]+/(?P<secret>[A-Za-z0-9_-]{8,})")),
    ("assigned-secret", re.compile(
        r"(?i)\b[\w-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b[\"']?"
        r"\s*[:=]\s*[\"']?(?P<secret>[^\s\"',;&]{4,})")),
)

_SECRET_KEY_TOKENS = ("password", "passwd", "passphrase", "secret", "token", "apikey",
                      "authorization", "cookie", "sessionid", "sessionkey", "csrf",
                      "resetlink", "reseturl", "privatekey", "credential", "accesskey")
_SECRET_KEY_EXACT = {"pwd", "otp", "pin", "sid"}


def _norm_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def is_secret_key(key: Any) -> bool:
    k = _norm_key(key)
    return k in _SECRET_KEY_EXACT or any(t in k for t in _SECRET_KEY_TOKENS)


def redact_text(text: str) -> str:
    """Replace anything that looks like a secret with [REDACTED]."""
    text = text[:MAX_INPUT_CHARS]
    for _name, rx in SECRET_PATTERNS:
        if "secret" in rx.groupindex:
            def _sub(m, _rx=rx):
                s = m.start()
                return m.group(0)[:m.start("secret") - s] + REDACTED + m.group(0)[m.end("secret") - s:]
            text = rx.sub(_sub, text)
        else:
            text = rx.sub(REDACTED, text)
    return text


# --------------------------------------------------------------------------------------
# Log injection
# --------------------------------------------------------------------------------------
_SIMPLE_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
_KEEP_FORMAT_CHARS = {"\u200c", "\u200d"}     # ZWNJ/ZWJ are legitimate in Gujarati/Hindi text
_ESCAPE_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"}


def sanitize_log_value(value: Any, max_len: int = MAX_LOG_VALUE) -> str:
    """One physical line, no control/bidi characters, bounded length. Does NOT redact secrets."""
    s = value if isinstance(value, str) else str(value)
    out = []
    for ch in s[:MAX_INPUT_CHARS]:
        if ch in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[ch])
        elif ch not in _KEEP_FORMAT_CHARS and unicodedata.category(ch) in _ESCAPE_CATEGORIES:
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
        else:
            out.append(ch)
    clean = "".join(out)
    if len(clean) > max_len:
        clean = clean[:max_len] + f"...[truncated {len(clean) - max_len} chars]"
    return clean


def clean_text(value: Any, max_len: int = MAX_LOG_VALUE) -> str:
    """Redact secrets, then neutralise control characters, then truncate."""
    s = value if isinstance(value, str) else str(value)
    return sanitize_log_value(redact_text(s), max_len)


# --------------------------------------------------------------------------------------
# PII masking
# --------------------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_AADHAAR_RE = re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")


def mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    return f"{local[:1]}***@{domain}" if domain else mask_generic(v)


def mask_digits(v: str, keep: int = 2) -> str:
    digits = re.sub(r"\D", "", v)
    return ("*" * max(len(digits) - keep, 0)) + digits[-keep:] if digits else mask_generic(v)


def mask_generic(v: str) -> str:
    return (v[:1] + "***") if v else v


def mask_pii_text(text: str, *, phones_and_ids: bool = True) -> str:
    """Mask e-mail addresses (always) and Indian mobile / 12-digit ID numbers (optional) in free text.
    Turn phones_and_ids off where a legitimate numeric ID could be mistaken for a phone number."""
    text = _EMAIL_RE.sub(lambda m: mask_email(m.group(0)), text)
    if phones_and_ids:
        text = _AADHAAR_RE.sub(lambda m: mask_digits(m.group(0), 4), text)
        text = _PHONE_RE.sub(lambda m: mask_digits(m.group(0), 2), text)
    return text


_PII_KEY_CONTAINS: tuple = (
    ("email", mask_email), ("phone", lambda v: mask_digits(v, 2)), ("mobile", lambda v: mask_digits(v, 2)),
    ("aadhaar", lambda v: mask_digits(v, 4)), ("aadhar", lambda v: mask_digits(v, 4)),
    ("passport", lambda v: mask_generic(v)), ("address", lambda v: mask_generic(v)),
)
_PII_KEY_EXACT = {"name", "fullname", "firstname", "lastname", "studentname", "dob", "dateofbirth", "pan"}


def pii_masker(key: Any) -> Optional[Callable[[str], str]]:
    k = _norm_key(key)
    if k in _PII_KEY_EXACT:
        return mask_generic
    for token, fn in _PII_KEY_CONTAINS:
        if token in k:
            return fn
    return None


# --------------------------------------------------------------------------------------
# Whole-structure cleaning (used for audit before/after/metadata and structured log extras)
# --------------------------------------------------------------------------------------
def clean_value(obj: Any, key: Any = None, depth: int = 0, *, mask_text_pii: bool = False) -> Any:
    """Return a JSON-safe copy with secrets redacted, PII masked and strings sanitised."""
    if depth > MAX_DEPTH:
        return "[MAX_DEPTH]"
    if key is not None:
        if is_secret_key(key):
            return REDACTED
        masker = pii_masker(key)
        if masker is not None:
            if obj is None or obj == "":
                return obj
            if isinstance(obj, (str, int)) and not isinstance(obj, bool):
                return masker(str(obj))
            return MASKED                      # a structure under a PII key: hide it whole
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        return obj if obj == obj and obj not in (float("inf"), float("-inf")) else str(obj)
    if isinstance(obj, Mapping):
        return {sanitize_log_value(k, 200): clean_value(v, k, depth + 1, mask_text_pii=mask_text_pii)
                for k, v in obj.items()}
    if isinstance(obj, (set, frozenset)):
        obj = sorted(obj, key=str)
    if isinstance(obj, (list, tuple)):
        return [clean_value(v, None, depth + 1, mask_text_pii=mask_text_pii) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return f"[BYTES {len(obj)}]"
    if isinstance(obj, Decimal):
        obj = str(obj)
    elif isinstance(obj, (datetime, date)):
        obj = obj.isoformat()
    elif isinstance(obj, Enum):
        obj = obj.value
    text = clean_text(obj)
    return mask_pii_text(text, phones_and_ids=mask_text_pii) if mask_text_pii else mask_pii_text(
        text, phones_and_ids=False)


# --------------------------------------------------------------------------------------
# CSV / spreadsheet formula injection
# --------------------------------------------------------------------------------------
def csv_safe(value: Any) -> str:
    """Neutralise cells that Excel/Sheets would execute as formulas (=, +, -, @, tab, CR)."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
