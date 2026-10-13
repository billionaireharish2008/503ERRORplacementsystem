"""Repository secret scanner (standard library only).

    python -m ops.secret_scan                 # scan tracked files (git) or the whole tree
    python -m ops.secret_scan --staged        # only staged changes (pre-commit hook)
    python -m ops.secret_scan --history       # every line ever added in git history
    python -m ops.secret_scan --update-baseline   # accept the CURRENT findings after human review

Findings print file, line, rule and a fingerprint, never the secret. Exit 1 = new findings, 2 = error.
Suppress a reviewed false positive with a trailing comment `# secret-scan: allow` or via the baseline
file (which stores only fingerprints). If a real secret is found: rotate it FIRST (see the runbook).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Sequence, Set

from audit_ops.sanitize import SECRET_PATTERNS, is_secret_key

BASELINE = ".secret-scan-baseline.json"
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", "drill_reports"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".pyc", ".woff", ".woff2"}
FORBIDDEN_FILES = ("*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_rsa.*", "id_ed25519", "*.sqlite3",
                   "*.db", "*.bak", "*.dump", "*.enc", "credentials.json", ".env", ".env.*", "*.kdbx")
FORBIDDEN_OK = (".env.example", ".env.sample", ".env.template")
ALLOW_MARK = "secret-scan: allow"
MAX_LINE = 2000
_BENIGN_PREFIX = ("/", "%", "os.", "env", "settings.", "request.", "getenv", "config", "self.", "<", "${", "{{", "$(", "%(")
_BENIGN_WORDS = ("changeme", "change-me", "placeholder", "example", "your_", "your-", "xxxx", "redacted",
                 "dummy", "fake", "test", "none", "null", "true", "false")
_HIGH_ENTROPY_RE = re.compile(r"""["']([A-Za-z0-9+/=_\-]{32,})["']""")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    fingerprint: str

    def render(self) -> str:
        return f"{self.path}:{self.line}  {self.rule}  [{self.fingerprint}]"


def entropy(s: str) -> float:
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def _benign(value: str) -> bool:
    v = value.lower()
    return v.startswith(_BENIGN_PREFIX) or any(w in v for w in _BENIGN_WORDS) or "(" in v or ")" in v or "[" in v


def _fp(rule: str, path: str, secret: str) -> str:
    return hashlib.sha256(f"{rule}\0{path}\0{secret}".encode()).hexdigest()[:16]


def scan_text(path: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        line = line[:MAX_LINE]
        for rule, rx in SECRET_PATTERNS:
            for m in rx.finditer(line):
                secret = m.group("secret") if "secret" in rx.groupindex else m.group(0)
                if rule == "assigned-secret" and _benign(secret):
                    continue
                if rule == "private-key-block" and "END" not in m.group(0) and "BEGIN" not in m.group(0):
                    continue
                out.append(Finding(path, n, rule, _fp(rule, path, secret)))
        for m in _HIGH_ENTROPY_RE.finditer(line):
            tok = m.group(1)
            if not re.fullmatch(r"[0-9a-fA-F]+", tok) and entropy(tok) >= 4.5 and not _benign(tok):
                out.append(Finding(path, n, "high-entropy-string", _fp("hes", path, tok)))
    return out


def forbidden_file(path: str) -> Optional[Finding]:
    base = os.path.basename(path)
    if base in FORBIDDEN_OK:
        return None
    if any(fnmatch.fnmatch(base, pat) for pat in FORBIDDEN_FILES):
        return Finding(path, 0, "forbidden-file-type", _fp("ff", path, base))
    return None


def _git(args: Sequence[str], root: str) -> Optional[str]:
    try:
        r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=120)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def iter_paths(root: str, staged: bool = False) -> Iterator[str]:
    listing = _git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"] if staged
                   else ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root)
    if listing is not None:
        for p in filter(None, listing.split("\0")):
            yield p
        return
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in files:
            yield os.path.relpath(os.path.join(dirpath, f), root)


def scan_tree(root: str, staged: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    for rel in iter_paths(root, staged):
        if rel == BASELINE or os.path.splitext(rel)[1].lower() in BINARY_EXT:
            continue
        if any(part in SKIP_DIRS for part in rel.replace("\\", "/").split("/")):
            continue
        ff = forbidden_file(rel)
        if ff:
            findings.append(ff)
            continue
        full = os.path.join(root, rel)
        try:
            if os.path.getsize(full) > 2_000_000:
                continue
            with open(full, "r", encoding="utf-8", errors="strict") as fh:
                findings.extend(scan_text(rel, fh.read()))
        except (OSError, UnicodeDecodeError):
            continue
    return findings


def scan_history(root: str) -> List[Finding]:
    log = _git(["log", "-p", "--all", "-U0", "--no-color"], root)
    if log is None:
        raise RuntimeError("not a git repository (or git unavailable)")
    findings: List[Finding] = []
    commit, path = "?", "?"
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line[7:15]
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for f in scan_text(f"{path}@{commit}", line[1:]):
                findings.append(Finding(f.path, 0, f.rule, f.fingerprint))
    return findings


def load_baseline(root: str) -> Set[str]:
    p = os.path.join(root, BASELINE)
    if not os.path.exists(p):
        return set()
    with open(p, "r", encoding="utf-8") as fh:
        return {e["fingerprint"] for e in json.load(fh).get("accepted", [])}


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="ops.secret_scan")
    ap.add_argument("--root", default=".")
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--history", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    a = ap.parse_args(argv)
    try:
        findings = scan_history(a.root) if a.history else scan_tree(a.root, a.staged)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if a.update_baseline:
        data = {"note": "Fingerprints of findings a human reviewed and accepted. No secret values.",
                "accepted": [{"fingerprint": f.fingerprint, "path": f.path, "rule": f.rule} for f in findings]}
        with open(os.path.join(a.root, BASELINE), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"baseline updated with {len(findings)} accepted finding(s)")
        return 0
    accepted = load_baseline(a.root)
    new = [f for f in findings if f.fingerprint not in accepted]
    for f in new:
        print(f.render())
    print(f"{len(new)} new finding(s), {len(findings) - len(new)} baselined")
    if new:
        print("If any finding is a real credential, ROTATE IT FIRST, then remove it (and purge history if it was committed).")
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
