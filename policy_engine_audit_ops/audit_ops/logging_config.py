"""Safe application logging: secrets redacted, one JSON object per line, files created 0600. No Django.

Use in settings.py:  LOGGING = build_logging_config(debug=DEBUG, log_dir=env.get("APP_LOG_DIR"))
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
from typing import Any, Dict, Optional

from .context import actor_id_var, request_id_var
from .sanitize import clean_text, mask_pii_text, sanitize_log_value


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.actor_id = actor_id_var.get()
        return True


class RedactingFilter(logging.Filter):
    """Resolve the message, strip secrets, mask PII, neutralise control characters."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        record.msg = mask_pii_text(clean_text(msg), phones_and_ids=True)
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: Dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": sanitize_log_value(record.getMessage()),
            "request_id": getattr(record, "request_id", "-"),
            "actor_id": getattr(record, "actor_id", "-"),
        }
        if record.exc_info:
            entry["exc"] = clean_text(self.formatException(record.exc_info), 4000)
        return json.dumps(entry, ensure_ascii=True, separators=(",", ":"))


class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Creates the log file with mode 0600 regardless of the process umask."""

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)


def build_logging_config(*, debug: bool = False, log_dir: Optional[str] = None) -> Dict[str, Any]:
    handlers: Dict[str, Any] = {
        "console": {"class": "logging.StreamHandler", "formatter": "json",
                    "filters": ["context", "redact"]},
    }
    if log_dir:
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        handlers["file"] = {
            "()": "audit_ops.logging_config.SecureRotatingFileHandler",
            "filename": os.path.join(log_dir, "app.log"), "maxBytes": 10_000_000,
            "backupCount": 10, "encoding": "utf-8", "formatter": "json",
            "filters": ["context", "redact"]}
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {"context": {"()": "audit_ops.logging_config.RequestContextFilter"},
                    "redact": {"()": "audit_ops.logging_config.RedactingFilter"}},
        "formatters": {"json": {"()": "audit_ops.logging_config.JsonFormatter"}},
        "handlers": handlers,
        "root": {"handlers": list(handlers), "level": "INFO"},
        "loggers": {
            # SQL logging prints query parameters (passwords, PII). Never below WARNING.
            "django.db.backends": {"level": "WARNING", "propagate": True},
            "django.request": {"level": "WARNING", "propagate": True},
        },
    }
