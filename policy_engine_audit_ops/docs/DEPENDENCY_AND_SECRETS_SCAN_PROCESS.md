# Dependency and Secrets Scan Process

## 1. Where secrets live
| Never in the repo | Where instead |
|---|---|
| `DJANGO_SECRET_KEY`, `AUDIT_HMAC_KEY`, DB password, `BACKUP_ENCRYPTION_KEY`, SMTP/API credentials | Environment variables or root-owned credential files read via `*_FILE` (see `deploy/nfsu-placement.service`), ideally from the institution's approved secret store **[DECIDE which]** |
| Development values | `.env` (git-ignored; copy from `.env.example`, which holds placeholders only) |

Development, test and production use **different** values and different configuration (`NFSU_ENV`). The app refuses to start in production without secrets, with `DEBUG` on, with `*` in `ALLOWED_HOSTS`, or with SQLite (`audit_ops/secure_settings.py`).

## 2. Secrets scan
| When | Command | Blocks |
|---|---|---|
| Every commit (pre-commit hook) | `python -m ops.secret_scan --staged` | the commit |
| Every pull request and weekly (CI) | `python -m ops.secret_scan` and `--history` | the merge |
| Before first push of a new repo | `python -m ops.secret_scan --history` | the push |

The scanner reports file, line, rule and a fingerprint, never the secret. It also flags files that should not be committed (`.env`, keys, databases, dumps, encrypted backups). A reviewed false positive is suppressed with `# secret-scan: allow` or by running `--update-baseline` and committing the fingerprint-only baseline (needs a second reviewer).

### If a secret is found or exposed
1. **Rotate first** (new value in the secret store, restart services, revoke the old one). Removing it from git does not make it safe.
2. Check logs for use of the old credential between exposure and rotation.
3. If it was committed: purge history (`git filter-repo`), force-push, ask collaborators to re-clone, and invalidate forks/caches.
4. Record a CONFIG_CHANGE event and a short note (what, when, who rotated). If the credential protected personal data and misuse is possible, follow the Incident Response Runbook.

## 3. Dependencies
- `requirements.in` lists direct dependencies; `pip-compile --generate-hashes` produces `requirements.txt` with exact versions and hashes. CI installs with `--require-hashes`.
- No VCS/URL/editable installs in production requirements.
- **Update cadence:** weekly CI scan (`pip-audit`); monthly planned upgrade; security patches within **7 days** (critical: 48 hours) **[DECIDE SLAs]**. Read the changelog, run the full test suite and the restore drill, then merge.
- New dependency checklist: maintained? license acceptable? needed (could the standard library do it)? pinned with hashes?

## 4. Scans in CI (`.github/workflows/security.yml`)
`python -m ops.dep_check --strict --require-hashes` runs pinning validation, `pip-audit` (known vulnerabilities) and `bandit` (insecure code patterns). `--strict` fails the build if a scanner is missing, so a scan cannot be silently skipped. Before each release also run `python manage.py check --deploy` (`--django-check`).

## 5. Server hardening checklist
- Service runs as an unprivileged account; hardened systemd unit in `deploy/`; secrets files `0600/0640`, directories `0700/0750`.
- Gunicorn and nginx request-size, header and time limits (`deploy/`); login rate limit.
- OS security updates applied automatically or within the SLA above; unused services and ports closed; database not reachable from the internet; TLS enforced with HSTS.
- Database roles: app (no DDL, no UPDATE/DELETE on audit tables), backup (read-only), auditor (audit read-only).

## 6. Gate checklist
- [ ] `ops.secret_scan` and `--history` clean (or baselined with reviewer sign-off)
- [ ] `requirements.txt` generated with hashes; `ops.dep_check --strict --require-hashes` passes
- [ ] No secret in logs (sample reviewed after login, failed login, password reset, export)
- [ ] `check --deploy` clean in the production configuration
