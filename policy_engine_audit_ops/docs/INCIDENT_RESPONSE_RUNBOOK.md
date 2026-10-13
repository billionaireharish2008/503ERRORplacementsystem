# Incident Response Runbook

Status: DRAFT. Fill every **[DECIDE]** (names, phone numbers, deadlines) before go-live and keep a printed copy; the system may be down when you need it.

## 1. Roles **[DECIDE names and deputies]**
| Role | Does |
|---|---|
| Incident commander | owns decisions, keeps the timeline, approves containment and restore |
| Technical lead | investigates, contains, recovers |
| Security officer | evidence, reporting, access review |
| Placement office / data owner | business impact, communication with students and companies |
| Institution management / legal / DPO | external reporting decisions |

## 2. What counts as an incident
Suspected or confirmed: unauthorised access; leaked credential or key; unexplained changes to offers, packages, policy decisions or permissions; audit chain verification failure; unexpected exports; malware; data loss or a failed backup; service outage caused by an attack. If unsure, treat it as an incident and downgrade later.

| Severity | Examples | Respond within |
|---|---|---|
| SEV1 | confirmed data breach, audit chain broken, production credentials exposed and used | immediately |
| SEV2 | credential exposed (no known use), suspicious privileged activity | 1 hour |
| SEV3 | single compromised student account, blocked attack | next working day |

## 3. Procedure
**Detect and triage (first 30 min).** Record the time, who reported it, what was seen. Open an incident log (append-only document). Assign roles and severity. Do not discuss details on channels that include people outside the response team.

**Contain (stop the damage, keep the evidence).**
- Compromised account: disable it (`is_active=False`; never delete), end its sessions, reset its password through the normal flow.
- Exposed credential or key: **rotate it now** (DJANGO_SECRET_KEY invalidates sessions; AUDIT_HMAC_KEY rotation must be recorded and the old key kept offline to verify old events; DB password; backup key).
- Suspected server compromise: isolate from the network (firewall rule or security group), do **not** power off or reboot (volatile memory), do not "clean up".
- Active abuse of one feature: switch that feature off (e.g. exports) rather than the whole system if possible.

**Preserve evidence (before anything is changed more than necessary).**
1. Snapshot the VM/disk, or copy `/var/log/nfsu/`, the off-box audit copy, web server and auth logs, `journalctl -u nfsu-placement`, and a database backup taken **now** (`ops.backup create --label incident`).
2. Compute SHA-256 of each artefact; store hashes in the incident log; keep copies read-only on separate storage; write who handled what and when (chain of custody).
3. Run `python manage.py verify_audit_chain` and note the result and head hash. If it fails, keep the broken table as it is: do not repair it.
4. Query the audit trail by actor, IP, target and `request_id` to reconstruct the timeline (admin viewer or `export.csv`; these accesses are audited too).

**Eradicate.** Find the entry point (credential, vulnerable dependency, misconfiguration), remove access paths and persistence, patch, run `ops.secret_scan --history` and `ops.dep_check --strict`.

**Recover.** Prefer rebuilding from a known-good image and restoring data with the Backup/Restore Runbook to a **clean** host. Verify the audit chain and application behaviour. Re-enable access gradually; watch logs closely for 72 h. Review every record changed during the exposure window against the audit trail and reverse unauthorised changes through normal, audited operations.

**Report and notify.** The incident commander decides, with management/legal/DPO, **[DECIDE who and by when]**:
- notification to the institution's authorities and, where required, to regulators. In India this may include CERT-In (its 2022 directions set a short reporting window for specified cyber incidents, commonly cited as 6 hours) and obligations under the Digital Personal Data Protection Act where personal data is involved. **Check the current text and deadlines with legal/DPO; do not rely on this summary.**
- affected students, companies or staff: what happened, what data, what to do, a contact point.
Record every notification with time, recipient and content.

**Post-incident (within 5 working days).** Blameless review: timeline, root cause, what detected it, what slowed us down, decisions needed. Create tracked actions (fixes, new alerts, training), update this runbook and the policies, and file the report with the incident log.

## 4. Quick commands
```bash
python manage.py verify_audit_chain                  # integrity of the audit trail
python -m ops.secret_scan --history                  # secrets ever committed
python -m ops.dep_check --strict --require-hashes    # vulnerable or unpinned dependencies
python -m ops.backup create --out /secure/incident --db-kind postgres --label incident
```

## 5. Exercises
Run a tabletop exercise before go-live and every 6 months (scenarios: leaked key in a commit; staff account abuses exports; database lost). Log gaps found. Combine the restore leg with the quarterly restore drill.

## 6. Gate checklist
- [ ] Roles, contacts and reporting deadlines filled in and approved
- [ ] Tabletop exercise held; findings logged
- [ ] Evidence-collection steps tried once on a test host
