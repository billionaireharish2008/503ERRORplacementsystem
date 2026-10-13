# Audit Trail and Log-Access Policy

Status: DRAFT for approval by the policy owner / security officer. Items marked **[DECIDE]** need an institutional decision.

## 1. Purpose
Detect misuse, keep every sensitive action attributable, and make tampering evident.

## 2. What is recorded
Every event is created through `audit_ops.services.record_event()` and stored in `audit_ops_auditevent` (database, hash-chained) and in an append-only JSONL file (and optionally a remote syslog collector).

| Area | Actions (`audit_ops.events.Action`) | Emitted by |
|---|---|---|
| Login / security | LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, PASSWORD_CHANGE, PASSWORD_RESET_REQUEST | `signals.py` (automatic; add a call in your reset view) |
| Record changes | RECORD_CREATE / UPDATE / DELETE | call `record_event` in the service that changes the record |
| Offers and packages | OFFER_CHANGE, PACKAGE_CHANGE | same |
| Policy decisions | POLICY_DECISION | `policy_engine.services.apply_to_drive` (done) |
| Exceptions | EXCEPTION_REQUEST, EXCEPTION_APPROVE, EXCEPTION_REJECT | exception workflow (Layer 3) |
| Permissions | PERMISSION_CHANGE | `signals.py` (user flags, groups, user and group permissions) |
| Exports | DATA_EXPORT, AUDIT_EXPORT | call `record_event` BEFORE returning the file |
| Audit access | AUDIT_VIEW, AUDIT_EXPORT, AUDIT_VERIFY | admin viewer, export view, verify command |
| Operations | BACKUP_CREATED, BACKUP_RESTORED, CONFIG_CHANGE | backup job / deployment tooling |

### Required fields on every event
actor ID, timestamp (UTC, microseconds), action, target type + target ID, outcome (SUCCESS / FAILURE / DENIED / REVIEW / ERROR), request/correlation ID (`X-Request-ID`, also echoed in the response and in application logs), source IP, before/after values (changed fields only), metadata, `prev_hash`, `hash`.

### Example call (offer change)
```python
from audit_ops.events import Action
from audit_ops.services import record_event

with transaction.atomic():
    offer.annual_fte_ctc_lpa = new_ctc
    offer.save()
    record_event(action=Action.OFFER_CHANGE, target_type="offer", target_id=offer.offer_id,
                 actor=request.user, request=request,
                 before={"annual_fte_ctc_lpa": old_ctc}, after={"annual_fte_ctc_lpa": new_ctc})
```
Call it inside the same transaction as the change. By default it is **fail-closed**: if the event cannot be stored, `AuditWriteError` is raised and the change rolls back. Only low-risk, high-volume events (logins) use `fail_closed=False`.

## 3. What is never recorded
Passwords, password hashes, session cookies, CSRF tokens, reset links or tokens, API keys, private keys, full secrets. `sanitize.py` removes them by field name and by pattern, in audit events and in application logs. Typed usernames on failed logins are stored only as a hash (users sometimes type their password into the username box). Names, e-mail addresses, phone and ID numbers are masked; only fields that changed are stored. Student placement IDs are used instead of names.

## 4. Log-injection defence
Every string is stripped of CR/LF, control, bidi and Unicode line-separator characters, bounded in length, and written as JSON (one object per line). Actions come from a fixed vocabulary; free text cannot become an action. CSV exports neutralise cells starting with `= + - @`.

## 5. Integrity and tamper resistance
1. **Application level:** the model refuses UPDATE/DELETE; no add/change/delete permissions exist for it.
2. **Database level:** `sql/postgres_append_only.sql` revokes UPDATE/DELETE/TRUNCATE from the app role and adds triggers.
3. **Hash chain:** each event's HMAC covers the previous event's hash, keyed with `AUDIT_HMAC_KEY` (not available to the database role). `python manage.py verify_audit_chain` runs **daily** and alerts on failure. Truncation of the newest rows is only detectable against an external anchor, so the command's printed *head hash and count* must be copied weekly to storage the application cannot write **[DECIDE: where]**.
4. **Off-box copy:** ship the JSONL file (`AUDIT_LOG_PATH`) with a log shipper to a separate, access-controlled host/bucket where the application account has write-only access. Optionally `chattr +a` the local file.

## 6. Who can access logs
| Role | Access | Notes |
|---|---|---|
| Ordinary users, placement officers, faculty | none | cannot see or alter audit data |
| Security officer / auditor | `audit_ops.view_auditevent` (read-only admin viewer) | every view is itself an AUDIT_VIEW event |
| Named exporters (max 2) **[DECIDE]** | `audit_ops.export_auditevent` | CSV capped at `AUDIT_EXPORT_MAX_ROWS`, filters recorded |
| Superusers / DBAs | database access via break-glass procedure | use of a privileged account is reported to the security officer |
| Application server account | append only | cannot read back, edit or delete the off-box copy |

Access is granted by the security officer, reviewed **quarterly**, and revoked on role change. Grants and revocations are PERMISSION_CHANGE events. The application log directory is `0700`, files `0600`, owned by the service account.

## 7. Retention **[DECIDE with the institution / legal]**
Proposed: audit events 3 years online (then archived, encrypted); application logs 90 days; failed-login events 1 year. Backups of audit data follow the backup runbook. Personal data in logs is already minimised (section 3).

## 8. Review routine
Daily: chain verification result. Weekly: review of LOGIN_FAILURE bursts, DENIED outcomes, EXCEPTION_APPROVE, PERMISSION_CHANGE, DATA_EXPORT and AUDIT_EXPORT. Any unexplained privileged action starts the Incident Response Runbook.

## 9. Gate checklist
- [ ] Each action in section 2 produces an event (tests or manual check with request ID shown)
- [ ] `verify_audit_chain` passes; tampering test fails as expected
- [ ] `ops.secret_scan` clean; log samples contain no secrets
- [ ] SQL hardening applied and tested: `UPDATE`/`DELETE` as the app role is rejected
