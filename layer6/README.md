# Placement Statistics & Secure Reporting System

Production-grade, permission-aware placement reporting and analytics module engineered to prevent data leakage, eliminate CSV formula injection, and enforce read-only reporting guarantees.

---

## 1. Architecture & Security Invariants

### 1.1 Read-Only Reporting Guarantee
Reporting views, dashboards, and export generation must never mutate underlying operational database records.
- Enforced at the engine level via SQLite `PRAGMA query_only = ON` on all connections spawned by the analytics layer.
- Mutation attempts (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`) are physically blocked by the database engine and raise `sqlite3.OperationalError`.

### 1.2 Isolation of Annual FTE CTC vs Internship Stipend
- **Strict Invariant**: Internship stipends are **never** combined with, added to, or averaged into Annual Full-Time Equivalent (FTE) CTC.
- FTE CTC is calculated solely on valid accepted FTE offers (`FTE_ONLY` or `FTE_PLUS_INTERNSHIP`) where `annual_fte_ctc > 0`.
- Internship Stipends are calculated separately by billing period (e.g., `MONTHLY`, `WEEKLY`, `LUMP_SUM`).
- Offers with pure internships have `annual_fte_ctc = NULL` and contribute $0$ to FTE averages.

### 1.3 Unique Placed Students vs Offer Volume
- A student is classified as **Placed** if and only if they hold at least one active offer with `status = 'ACCEPTED'` where `is_latest_correction = 1`.
- Students receiving multiple offers (e.g., dream tier + core tier) are counted **once** in unique placed metrics, but all issued offers are reflected in offer volume.
- **Declined Offers (`DECLINED`)**: Do not confer placed status. If a student declines an offer and holds no other accepted offer, they remain **Unplaced**.
- **Expired Offers (`EXPIRED`)**: Do not confer placed status.
- **Offer Corrections (`SUPERSEDED`)**: Superseded clerical corrections (`is_latest_correction = 0`) are excluded from active statistics to prevent double counting.

### 1.4 Mathematical Invariants & Reconciliation
$$\text{Total Registered} = \text{Total Eligible} + \text{Total Ineligible}$$
$$\text{Total Eligible} = \text{Total Placed (Unique)} + \text{Total Unplaced}$$
$$\text{Total Active Offers} = \text{Accepted} + \text{Declined} + \text{Expired} + \text{Revoked}$$

### 1.5 Role-Based Access Control (RBAC) & Tenancy Scope Boundaries
| Role | Programme Scope | Batch Scope | Company Scope | PII (Phone/Email) | Restricted Views (Policy / Future Drives) |
|---|---|---|---|---|---|
| `ADMIN` | All | All | All | Opt-in / Masked | Full Access |
| `PLACEMENT_OFFICER` | All | All | All | Opt-in / Masked | Full Access |
| `DEPARTMENT_COORDINATOR`| Assigned Dept only | Assigned | All | Masked | Scoped to Department |
| `STUDENT_REPRESENTATIVE`| Assigned Dept only | Assigned | None | Redacted | **Blocked** |
| `COMPANY_RECRUITER` | Applied candidates | Active Drives| Assigned Company only | Redacted | **Blocked** |
| `AUDITOR` | All | All | All | Redacted | Policy View Only |

### 1.6 Export Protection & Formula Injection Defense (CWE-1236)
- CSV/Excel injection attacks (payloads starting with `=`, `+`, `-`, `@`, `\t`, `\r`, `%`) are automatically prefixed with a single quote `'`.
- PII (Phone and Email) are excluded by default from export files.
- Every export is cryptographically hashed (`SHA-256`) and recorded in `export_audit_log` with timestamp, user ID, role, and filter scope.

---

## 2. Directory Structure

```
placement_reporting/
├── database.py              # Schema, read-only connection manager, deterministic synthetic seeder
├── models.py                # Dataclasses & Enums (Roles, OfferStatus, StipendPeriod)
├── policy.py                # Formal business rules, placed definition, reconciliation logic
├── security.py              # ScopeEnforcer, PIISanitizer, FormulaInjectionSanitizer
├── service.py               # PlacementAnalyticsService: aggregate metrics & restricted views
├── export_engine.py         # Secure CSV & Excel XML export generator + audit logger
├── api.py                   # REST API gateway & request dispatch router
├── test_reconciliation.py   # Complete test suite validating all completion gates
├── demo_runner.py           # End-to-end interactive CLI demo
└── README.md                # System documentation
```

---

## 3. Quick Start & Execution

### Run Reconciliation & Security Tests
```powershell
python test_reconciliation.py
```

### Run Interactive Demonstration
```powershell
python demo_runner.py
```

---

## 4. API Endpoints

- `GET /api/v1/dashboard`: Aggregate student & offer metrics, FTE CTC, and stipend analytics.
- `GET /api/v1/reports/detailed`: Drill-down student records with PII redaction.
- `GET /api/v1/reports/export/csv`: Download secure CSV report with formula sanitization.
- `GET /api/v1/reports/export/excel`: Download formatted Excel XML spreadsheet.
- `GET /api/v1/restricted/future-drives`: Eligible student candidates for upcoming drives.
- `GET /api/v1/restricted/pending-acceptances`: Offers awaiting student decision (`OFFERED`).
- `GET /api/v1/restricted/joining-updates`: Post-placement joining statuses.
- `GET /api/v1/restricted/policy-reviews`: Sensitive cases awaiting disciplinary or policy review.
