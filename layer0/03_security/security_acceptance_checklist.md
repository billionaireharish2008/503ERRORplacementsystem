# Security acceptance checklist
Tick only with evidence (test name, screenshot or report). Items are grouped by the layer that proves them.

## Layer 0 (this pack)
- [ ] SEC-00a Policy rules include boundary and exception examples
- [ ] SEC-00b No ambiguous rule is coded as an assumed ALLOW
- [ ] SEC-00c Every High threat has a control, a test and a named owner
- [ ] SEC-00d A person is nominated to review policy changes and security-sensitive releases

## Layer 1 - Data
- [ ] SEC-01a Duplicate Placement ID and broken foreign keys rejected by the database
- [ ] SEC-01b Offer history preserved (no silent overwrite)
- [ ] SEC-01c App uses a least-privilege DB account; DB not internet-exposed
- [ ] SEC-01d No raw SQL built from user input; only synthetic data in development

## Layer 2 - Access
- [ ] SEC-02a Students cannot change protected status/package fields
- [ ] SEC-02b Recruiters cannot see other companies' data (even with a known URL/ID)
- [ ] SEC-02c Direct URL/API attempts denied server-side
- [ ] SEC-02d Login throttling; secure/HttpOnly/SameSite cookies; CSRF protection on forms
- [ ] SEC-02e No shared admin account

## Layer 3 - Workflow
- [ ] SEC-03a Modified browser request cannot bypass a rule or permission
- [ ] SEC-03b Concurrent actions do not create contradictory offers
- [ ] SEC-03c Import: type/size limits, safe parsing, no stack traces in errors
- [ ] SEC-03d Export: permission check per request, formula-safe, minimal columns, logged

## Layer 4 - Policy engine
- [ ] SEC-04a All approved scenarios match expected outcomes (table-driven tests)
- [ ] SEC-04b Missing/contradictory input -> REVIEW or safe error
- [ ] SEC-04c Decisions reproducible from saved rule version + facts

## Layer 5 - Operations
- [ ] SEC-05a Sensitive actions produce audit events (actor, time, action, target, outcome)
- [ ] SEC-05b No secrets in repo or logs; DEBUG off in deployment
- [ ] SEC-05c Backup restore demonstrated in a test environment

## Layer 6 - Reporting
- [ ] SEC-06a Counts reconcile with test data; unique placed students differ from offer count
- [ ] SEC-06b Stipends never combined with annual CTC
- [ ] SEC-06c Users see only metrics within their scope
