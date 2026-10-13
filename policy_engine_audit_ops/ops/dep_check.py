"""Dependency hygiene gate.   python -m ops.dep_check [--strict] [--require-hashes] [--django-check]

1. requirements.txt must pin every package exactly (==), with no VCS/URL installs.
   (--require-hashes also demands --hash=sha256 entries: build the file with `pip-compile --generate-hashes`.)
2. Runs pip-audit (known vulnerabilities) and bandit (insecure code patterns) when installed.
   --strict turns a missing tool into a failure so CI cannot silently skip the scan.
3. --django-check runs `manage.py check --deploy` (DEBUG, HSTS, cookie flags ...).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

_REQ = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==[A-Za-z0-9][A-Za-z0-9.!+_-]*(\s*;[^#]*)?")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def check_requirements(text: str, require_hashes: bool = False) -> List[str]:
    problems: List[str] = []
    logical, buf, start = [], "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append((start, (buf + line).strip()))
        buf = ""
    for n, line in logical:
        line = re.sub(r"\s+#.*$", "", line)
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-c", "--index-url", "--extra-index-url", "--require-hashes")):
            continue
        if re.search(r"(git\+|https?://|\.whl|\.tar\.gz|^-e\s)", line):
            problems.append(f"line {n}: VCS/URL/editable requirement is not allowed: {line[:60]}")
        elif not _REQ.match(line):
            problems.append(f"line {n}: not pinned with '==': {line[:60]}")
        elif require_hashes and not _HASH.search(line):
            problems.append(f"line {n}: missing --hash=sha256: entry: {line[:60]}")
    return problems


def _run(cmd: Sequence[str], timeout: int = 600) -> Tuple[int, str]:
    try:
        r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)[-1500:]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 99, str(exc)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="ops.dep_check")
    ap.add_argument("--requirements", default="requirements.txt")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--require-hashes", action="store_true")
    ap.add_argument("--django-check", action="store_true")
    ap.add_argument("--skip-tools", action="store_true", help="only validate pinning (offline use)")
    a = ap.parse_args(argv)

    failed = False
    try:
        with open(a.requirements, "r", encoding="utf-8") as fh:
            problems = check_requirements(fh.read(), a.require_hashes)
    except OSError:
        print(f"FAIL  cannot read {a.requirements}")
        return 2
    if problems:
        failed = True
        print("FAIL  dependency pinning")
        for p in problems:
            print("      " + p)
    else:
        print("PASS  dependency pinning")

    if not a.skip_tools:
        steps = [("pip-audit", ["pip-audit", "-r", a.requirements, "--disable-pip"] if a.require_hashes
                  else ["pip-audit", "-r", a.requirements]),
                 ("bandit", ["bandit", "-q", "-r", ".", "-x", "./.venv,./venv,./tests_ops,./policy_engine/tests,"
                             "./audit_ops/tests", "-ll"])]
        for name, cmd in steps:
            if not shutil.which(cmd[0]):
                print(f"{'FAIL' if a.strict else 'SKIP'}  {name} is not installed")
                failed = failed or a.strict
                continue
            code, out = _run(cmd)
            print(f"{'PASS' if code == 0 else 'FAIL'}  {name}")
            if code != 0:
                failed = True
                print(out)
    if a.django_check:
        code, out = _run([sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"])
        print(f"{'PASS' if code == 0 else 'FAIL'}  manage.py check --deploy")
        if code != 0:
            failed = True
            print(out)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
