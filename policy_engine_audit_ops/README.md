# NFSU Placement System — Layer 4: Policy Engine

## Quick start (no installs)
```bash
python run_demo.py               # prints decisions for sample students
python -m unittest discover -v   # 13 tests
```
In VS Code: open this folder, press F5 and pick **Run demo** or **Run unit tests**.

## Full setup

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (macOS/Linux: source .venv/bin/activate)
pip install django pytest
pip freeze > requirements.txt     # the plan wants pinned dependencies
python -m unittest discover -v    # or: pytest
```
The engine (`types, config, rules, evaluator`) has **no Django dependency** and runs/tests on its own.
`models.py`, `services.py`, `apps.py` are for the shared Django project:
add `"policy_engine"` to `INSTALLED_APPS`, then `python manage.py makemigrations policy_engine`
(review the migration before applying).

## Layer 5: audit, secrets, backup and incident response
New in this folder: `audit_ops/` (Django app + pure-Python core), `ops/` (scanners, backup/restore, restore drill),
`docs/` (4 policies/runbooks), `deploy/`, `sql/`, `.github/workflows/security.yml`.

```bash
python -m unittest discover -v          # 59 tests (13 engine + 46 audit/ops), standard library + cryptography
python -m ops.secret_scan               # secrets in the repo           (--staged / --history)
python -m ops.dep_check --skip-tools    # pinning check (fails until you compile requirements.txt)
python -m ops.drill                     # backup -> disaster -> restore -> verify, writes drill_reports/*.json
```
Wire-up in your shared Django project:
1. `INSTALLED_APPS += ["audit_ops", "policy_engine"]`; `MIDDLEWARE += ["audit_ops.middleware.RequestContextMiddleware"]`
   (after `AuthenticationMiddleware`); `path("audit/", include("audit_ops.urls"))`.
2. In settings.py: `globals().update(build_security_settings(os.environ))`, `DATABASES = build_database_settings(os.environ)`,
   `LOGGING = build_logging_config(debug=DEBUG, log_dir=os.environ.get("APP_LOG_DIR"))` (see `audit_ops/secure_settings.py`).
3. `python manage.py makemigrations audit_ops policy_engine`, review, `migrate`, then run `sql/postgres_append_only.sql` as the DB owner.
4. Schedule: `verify_audit_chain` daily, `ops.backup create` daily, `ops.drill` quarterly.
5. Add `record_event(...)` calls where offers, packages, exceptions, permissions and exports change (see docs/AUDIT_TRAIL_AND_LOG_ACCESS_POLICY.md).

NOT verified here: the Django-dependent files (`models, services, signals, middleware, admin, views`) were written without Django
installed, so they are syntax-checked only. Run `makemigrations`, the app, and a PostgreSQL concurrency test before relying on them.

## What is real vs placeholder
The official NFSU 2026-27 placement guideline was not publicly available. All numbers in
`config.py` marked PLACEHOLDER are typical values from other institutes. `approved=False`, so in
normal mode the engine returns REVIEW (rule R-POLICY-00) until the policy owner signs off a real
version. Replace values, set `approved=True` and `approved_by`, bump `version`, keep the old version
in `POLICIES`.

## Hardening still to do outside this folder
- DB-level append-only for `policy_engine_policydecision`: REVOKE UPDATE, DELETE from the app's DB role.
- Layer 2 permission check in the view before calling `apply_to_drive`.
- Concurrency test against PostgreSQL (SQLite does not really honour `select_for_update`).
- Run dependency + secrets scans before merging.
