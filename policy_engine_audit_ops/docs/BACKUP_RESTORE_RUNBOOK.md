# Backup and Restore Runbook

Status: DRAFT. Objectives below are **proposals to agree with the institution [DECIDE]**; the drill measures what is actually achievable.

## 1. Recovery objectives
| | Proposed | Meaning | How it is met |
|---|---|---|---|
| RPO (max data loss) | 24 h (1 h in placement season) **[DECIDE]** | time between backups | scheduled `ops.backup create`; PostgreSQL WAL archiving if < 1 h is required |
| RTO (max downtime) | 4 h **[DECIDE]** | time to restore service | measured `restore_seconds` in every drill + provisioning time of a replacement host |

## 2. What is backed up
PostgreSQL database (`pg_dump --format=custom`), uploaded media, the audit JSONL directory. **Not** in backups: secrets, `.env`, the backup key. Each backup is a single AES-256-GCM encrypted file (`*.bak.enc`) plus a manifest (SHA-256, size, contents).

## 3. Key handling
- `python -m ops.backup genkey` creates a 32-byte key. Store it in the secret store and in **one sealed offline copy held by a second person**. Without the key, backups are unrecoverable; with it, anyone with a backup can read all data.
- The key is never kept on the backup storage and never passed on a command line. Rotate yearly or after suspected exposure (new backups use the new key; keep the old key until old backups expire).
- Backup storage: separate host/bucket from the database server, write-only for the backup job, read access for 2 named people, MFA on the account. Keep copies in two locations, one offline or object-locked **[DECIDE]**.

## 4. Taking backups (schedule: daily 02:00 + before every release)
```bash
export BACKUP_ENCRYPTION_KEY_FILE=/etc/nfsu/secrets/backup_key      # or the environment variable
export PGHOST=... PGUSER=nfsu_backup PGDATABASE=nfsu PGPASSFILE=/etc/nfsu/secrets/.pgpass
python -m ops.backup create --out /secure/backups --db-kind postgres \
    --include audit_logs=/var/log/nfsu/audit --include media=/srv/nfsu/media --keep 30
```
Then copy `*.bak.enc` and its `.manifest.json` off the host. Alert if no new backup in 26 h. Record a BACKUP_CREATED event.

## 5. Restoring (always to a scratch environment first)
1. Declare the incident (or drill) and name an owner; note the start time (this is your measured RTO).
2. Provision a clean host/database. **Never restore over production without incident-commander approval**; the tool refuses when `NFSU_ENV=production` unless `--allow-production` is passed.
3. Fetch the latest good backup + manifest; the tool verifies the checksum, then the encryption authenticates every chunk (wrong key, edit, truncation and appended data all fail).
```bash
python -m ops.backup restore --file nfsu-<stamp>.bak.enc --target /srv/restore --pg-restore-db nfsu_restored
```
4. Verify: `python manage.py verify_audit_chain` (chain intact, head hash matches the last off-box anchor), row counts vs. the last known figures, application smoke test (login, one drive application, one policy decision).
5. Cut over (point the app at the restored DB / replace the host), rotate any credentials the incident exposed, record BACKUP_RESTORED, write down end time and data-loss window (RPO actually achieved).
6. Replay: events after the backup exist in the off-box JSONL copy; keep them for reconciliation.

## 6. Restore drill (the completion gate)
Run **before go-live, then quarterly and after any change to the backup tooling**:
```bash
python -m ops.drill --report-dir drill_reports                              # synthetic data, runs anywhere
python -m ops.drill --sqlite-path copy_of_test.sqlite3 --report-dir drill_reports   # a COPY of test data
```
It takes a backup, deletes the source, restores into a fresh directory, compares row counts, re-verifies the audit hash chain and head hash, and confirms a tampered backup and a wrong key are rejected. It writes a timestamped JSON report. For the PostgreSQL rehearsal: restore a real backup onto a **test** server with the commands in section 5 and attach (a) the tool output, (b) `verify_audit_chain` output, (c) start/end times to the drill report.
The gate is met only when a drill report with `"passed": true` from the **institution's test environment** is filed, with measured restore time compared to the RTO. The synthetic drill proves the tooling; it does not replace the PostgreSQL rehearsal.

## 7. Backup retention **[DECIDE]**
Proposed: 30 daily, 12 monthly, 3 yearly; deleted by `--keep` plus a monthly archive job; backups of personal data are deleted with the same schedule as the source data.
