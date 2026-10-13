# NFSU Placement System - Layer 0 Pack
**Policy definition, requirements and threat modelling (before any code)**

Built from: the problem statement (Sections 1-3.1 seen), and *Secure Layer-Wise Development Plan v2.0* (Layer 0).

## Honest status
This pack is a **pre-filled working draft, not an approved baseline**.
We have NOT yet seen the official 2026-27 Student Placement Guidelines, so every policy
rule is marked `NEEDS_GUIDELINE` and defaults to `REVIEW` (never ALLOW) until someone fills it
in from the guideline and the policy owner approves it.

## Folder map
| Path | What it is | Layer 0 deliverable |
|---|---|---|
| `00_requirements/requirements_summary.md` | What the problem statement says, what we have not seen yet | input |
| `01_policy/rule_catalogue.csv` | One row per rule: ID, condition, inputs, decision, reason, exception path, owner, date, tests | Policy decision table |
| `01_policy/boundary_and_failsafe_tests.csv` | Boundary (10 / 16 LPA) and missing-data examples | Rule test examples |
| `01_policy/exception_authority_matrix.csv` | Who may request / review / approve each exception | Exception authority matrix |
| `01_policy/open_questions.md` | Questions to put to the Placement Cell | unblocks the above |
| `02_data/data_classification.csv` | Every field: class, who sees it, export default, retention | Data classification |
| `02_data/retention_notes.md` | Retention and archive approach + open decisions | Retention notes |
| `03_security/threat_model.csv` | Assets, abuse cases, impact, control, test, owner | Threat list |
| `03_security/role_access_matrix.csv` | Roles x actions (initial proposal) | feeds Layer 2 |
| `03_security/security_acceptance_checklist.md` | Acceptance criteria per layer | Security checklist |
| `04_governance/roles_and_owners.md` | Name the policy owner and security reviewer | Gate requirement |
| `04_governance/decision_log.md` | Decisions made and pending | traceability |
| `tools/check_layer0.py` | Automatic gate check for this pack | completion gate |

## How to use it (in this order)
1. Read `01_policy/open_questions.md` and send it to the Placement Cell / event mentors. Biggest blocker: the guideline document itself.
2. Fill `rule_catalogue.csv` from the guideline: replace each `TBD`, set `status` to `DRAFT`, then `APPROVED` once the policy owner agrees.
3. Fill names in `04_governance/roles_and_owners.md` and the `owner` columns.
4. Run the gate check:  `python tools/check_layer0.py`   (needs only Python 3)
5. Move to Layer 1 when the check says READY. Hackathon shortcut: you may start Layer 1 (schema) while rules are being confirmed, but do not code a rule into the engine until it is `APPROVED`.

## How Layer 0 feeds later layers
- `rule_catalogue.csv` -> Layer 4 policy engine (rule IDs, reasons, tests)
- `data_classification.csv` -> Layer 1 models, Layer 2 field-level permissions, Layer 6 export columns
- `role_access_matrix.csv` -> Layer 2 permissions and negative tests
- `threat_model.csv` + `security_acceptance_checklist.md` -> test cases in every layer

## Golden rule
**An unclear rule is never an assumed ALLOW.** Unknown, missing or contradictory input => `REVIEW`.
