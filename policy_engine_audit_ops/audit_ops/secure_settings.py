"""Environment-driven, fail-safe Django settings. No Django import; returns plain dicts.

In settings.py:
    import os
    from audit_ops.secure_settings import build_security_settings, build_database_settings
    globals().update(build_security_settings(os.environ))
    DATABASES = build_database_settings(os.environ)

Defaults are the SAFE ones: NFSU_ENV unset means production, DEBUG is off, secrets must come from the
environment (or a *_FILE path, as Docker/Kubernetes/systemd credentials provide) and the app refuses
to start without them. Nothing here is a secret; real values live outside the repository.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, Mapping, Optional


class ConfigError(RuntimeError):
    pass


def env_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    return default if raw is None else raw.strip().lower() in ("1", "true", "yes", "on")


def get_secret(env: Mapping[str, str], name: str, *, required: bool = True, min_len: int = 0) -> Optional[str]:
    """Read NAME, or the file named by NAME_FILE (trailing newline stripped)."""
    value = env.get(name)
    file_path = env.get(name + "_FILE")
    if value is None and file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                value = fh.read().rstrip("\r\n")
        except OSError as exc:
            raise ConfigError(f"cannot read {name}_FILE") from exc
    if not value:
        if required:
            raise ConfigError(f"{name} is not set (use the environment or {name}_FILE)")
        return None
    if len(value) < min_len:
        raise ConfigError(f"{name} is too short (need at least {min_len} characters)")
    return value


def build_security_settings(env: Mapping[str, str]) -> Dict[str, Any]:
    environment = env.get("NFSU_ENV", "production").strip().lower()
    if environment not in ("development", "test", "staging", "production"):
        raise ConfigError("NFSU_ENV must be development, test, staging or production")
    is_prod = environment in ("staging", "production")
    debug = env_bool(env, "DJANGO_DEBUG", False)
    if is_prod and debug:
        raise ConfigError("DJANGO_DEBUG must be off in staging/production")

    if is_prod:
        secret_key = get_secret(env, "DJANGO_SECRET_KEY", min_len=50)
        audit_key = get_secret(env, "AUDIT_HMAC_KEY", min_len=32)
        hosts = [h.strip() for h in env.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h.strip()]
        if not hosts or "*" in hosts:
            raise ConfigError("DJANGO_ALLOWED_HOSTS must list explicit host names (no '*')")
    else:   # development/test: random per-process keys, nothing to leak, sessions reset on restart
        secret_key = get_secret(env, "DJANGO_SECRET_KEY", required=False) or secrets.token_urlsafe(64)
        audit_key = get_secret(env, "AUDIT_HMAC_KEY", required=False) or secrets.token_urlsafe(32)
        hosts = [h.strip() for h in env.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]

    cfg: Dict[str, Any] = {
        "DEBUG": debug,
        "SECRET_KEY": secret_key,
        "ALLOWED_HOSTS": hosts,
        "NFSU_ENV": environment,
        # cookies / transport
        "SESSION_COOKIE_SECURE": is_prod,
        "CSRF_COOKIE_SECURE": is_prod,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "CSRF_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_AGE": int(env.get("SESSION_COOKIE_AGE", 8 * 3600)),
        "SESSION_EXPIRE_AT_BROWSER_CLOSE": True,
        "SECURE_SSL_REDIRECT": is_prod and env_bool(env, "DJANGO_SSL_REDIRECT", True),
        "SECURE_HSTS_SECONDS": int(env.get("DJANGO_HSTS_SECONDS", 31536000 if is_prod else 0)),
        "SECURE_HSTS_INCLUDE_SUBDOMAINS": env_bool(env, "DJANGO_HSTS_SUBDOMAINS", False),
        "SECURE_CONTENT_TYPE_NOSNIFF": True,
        "SECURE_REFERRER_POLICY": "same-origin",
        "X_FRAME_OPTIONS": "DENY",
        # request limits (Django-level; nginx/gunicorn enforce their own, see deploy/)
        "DATA_UPLOAD_MAX_MEMORY_SIZE": int(env.get("DATA_UPLOAD_MAX_MEMORY_SIZE", 5 * 1024 * 1024)),
        "FILE_UPLOAD_MAX_MEMORY_SIZE": int(env.get("FILE_UPLOAD_MAX_MEMORY_SIZE", 2 * 1024 * 1024)),
        "DATA_UPLOAD_MAX_NUMBER_FIELDS": 1000,
        "DATA_UPLOAD_MAX_NUMBER_FILES": 20,
        "FILE_UPLOAD_PERMISSIONS": 0o640,
        "FILE_UPLOAD_DIRECTORY_PERMISSIONS": 0o750,
        # audit_ops
        "AUDIT_HMAC_KEY": audit_key,
        "AUDIT_LOG_PATH": env.get("AUDIT_LOG_PATH") or None,
        "AUDIT_SYSLOG_HOST": env.get("AUDIT_SYSLOG_HOST") or None,
        "AUDIT_SYSLOG_PORT": int(env.get("AUDIT_SYSLOG_PORT", 514)),
        "AUDIT_TRUSTED_PROXY_COUNT": int(env.get("AUDIT_TRUSTED_PROXY_COUNT", 0)),
        "AUDIT_EXPORT_MAX_ROWS": int(env.get("AUDIT_EXPORT_MAX_ROWS", 50_000)),
    }
    if env_bool(env, "DJANGO_BEHIND_PROXY", False):
        cfg["SECURE_PROXY_SSL_HEADER"] = ("HTTP_X_FORWARDED_PROTO", "https")
    return cfg


def build_database_settings(env: Mapping[str, str]) -> Dict[str, Any]:
    """PostgreSQL with connect/statement/idle timeouts, TLS in production. SQLite only for dev/test."""
    environment = env.get("NFSU_ENV", "production").strip().lower()
    is_prod = environment in ("staging", "production")
    if env.get("DB_ENGINE", "postgres" if is_prod else "sqlite") == "sqlite":
        if is_prod:
            raise ConfigError("SQLite is not allowed in staging/production")
        return {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": env.get("DB_NAME", "dev.sqlite3")}}
    return {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env.get("DB_NAME") or _missing("DB_NAME"),
        "USER": env.get("DB_USER") or _missing("DB_USER"),
        "PASSWORD": get_secret(env, "DB_PASSWORD"),
        "HOST": env.get("DB_HOST", "127.0.0.1"),
        "PORT": env.get("DB_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {
            "connect_timeout": 5,
            "sslmode": env.get("DB_SSLMODE", "require" if is_prod else "prefer"),
            "options": "-c statement_timeout=15000 -c idle_in_transaction_session_timeout=30000",
        },
    }}


def _missing(name: str):
    raise ConfigError(f"{name} is not set")
