"""Where audit events are written besides the database. No Django.

The JSONL file is the local copy; ship it off-box (rsyslog/Vector/Filebeat -> a write-only
collector that the application server cannot modify) for real tamper resistance. SyslogSink
forwards directly if you have a collector. A sink must never raise into business code.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import socket
import threading
from typing import Any, List, Mapping, Optional, Protocol


class Sink(Protocol):
    def write(self, record: Mapping[str, Any]) -> None: ...


def to_line(record: Mapping[str, Any]) -> str:
    # ensure_ascii=True => newlines/control chars in any value are escaped; one event = one line
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


class JsonlFileSink:
    """Append-only JSON-lines file, mode 0600, parent dir 0700. On Linux also consider `chattr +a`."""

    def __init__(self, path: str, fsync: bool = True):
        self.path, self.fsync = path, fsync
        self._lock = threading.Lock()
        self._fd: Optional[int] = None

    def _open(self) -> int:
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        return os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    def write(self, record: Mapping[str, Any]) -> None:
        data = (to_line(record) + "\n").encode("ascii")
        with self._lock:
            if self._fd is None:
                self._fd = self._open()
            os.write(self._fd, data)
            if self.fsync:
                os.fsync(self._fd)

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None


class SyslogSink:
    """Forward to a remote syslog collector. Prefer a local agent that adds TLS and buffering."""

    def __init__(self, host: str, port: int = 514, tcp: bool = True):
        handler = logging.handlers.SysLogHandler(
            address=(host, port), facility=logging.handlers.SysLogHandler.LOG_AUTH,
            socktype=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        self._log = logging.getLogger("nfsu.audit.forward")
        self._log.propagate = False
        self._log.setLevel(logging.INFO)
        self._log.addHandler(handler)

    def write(self, record: Mapping[str, Any]) -> None:
        self._log.info("nfsu-audit %s", to_line(record))


class MultiSink:
    def __init__(self, sinks: List[Sink]):
        self.sinks = sinks

    def write(self, record: Mapping[str, Any]) -> None:
        for s in self.sinks:
            try:
                s.write(record)
            except Exception:                       # one failing sink must not block the others
                logging.getLogger("nfsu.audit").error("audit sink %s failed", type(s).__name__)


def sink_from_config(path: Optional[str], syslog_host: Optional[str] = None,
                     syslog_port: int = 514) -> Optional[Sink]:
    sinks: List[Sink] = []
    if path:
        sinks.append(JsonlFileSink(path))
    if syslog_host:
        try:
            sinks.append(SyslogSink(syslog_host, syslog_port))
        except OSError:
            logging.getLogger("nfsu.audit").error("cannot reach audit syslog collector")
    return MultiSink(sinks) if sinks else None
