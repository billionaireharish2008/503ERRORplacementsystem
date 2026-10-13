#!/usr/bin/env python3
"""Layer 0 gate check. Run from the pack root:  python tools/check_layer0.py
Exit code 0 = READY for Layer 1+, 1 = NOT READY."""
import csv, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def rows(p):
    with open(os.path.join(ROOT, p), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))
tbd = lambda v: (v or "").strip() == "" or "TBD" in v
problems, notes = [], []

rules = rows("01_policy/rule_catalogue.csv")
need = [r["rule_id"] for r in rules if r["status"] in ("NEEDS_GUIDELINE", "NEEDS_DECISION")]
if need: problems.append(f"{len(need)} rule(s) not yet defined/approved: {', '.join(need)}")
for r in rules:
    # an ALLOW may only exist on an approved rule
    if "ALLOW" in r["decision_if_condition_met"] and r["status"] not in ("APPROVED", "ACCEPTED_DESIGN"):
        problems.append(f"{r['rule_id']}: ALLOW on a rule that is not APPROVED")
    if r["status"] == "APPROVED":
        for col in ("condition", "owner", "effective_date", "test_examples", "reason_template"):
            if tbd(r[col]): problems.append(f"{r['rule_id']}: APPROVED but '{col}' is empty/TBD")

th = rows("03_security/threat_model.csv")
for t in th:
    if t["risk"] == "High":
        for col in ("control", "test", "owner"):
            if tbd(t[col]): problems.append(f"{t['threat_id']} (High): '{col}' is empty/TBD")

ex = rows("01_policy/exception_authority_matrix.csv")
open_ex = [e["exception_id"] for e in ex if tbd(e["final_approver"])]
if open_ex: problems.append(f"Final approver not named for: {', '.join(open_ex)}")

gov = open(os.path.join(ROOT, "04_governance/roles_and_owners.md"), encoding="utf-8").read()
first3 = [l for l in gov.splitlines() if l.startswith("| Policy owner") or l.startswith("| Policy-catalogue") or l.startswith("| Security reviewer")]
if any("| TBD |" in l for l in first3): problems.append("Policy owner / maintainer / security reviewer not named")

bt = rows("01_policy/boundary_and_failsafe_tests.csv")
for b in bt:
    if b["test_id"] in ("BT-01", "BT-02") and b["expected_decision_now"] != "REVIEW":
        problems.append(f"{b['test_id']}: boundary must be REVIEW until resolved")

dc = rows("02_data/data_classification.csv")
und = [d["field"] for d in dc if tbd(d["classification"])]
if und: problems.append(f"Unclassified fields: {', '.join(und)}")
notes.append(f"{len(rules)} rules, {len(th)} threats, {len(dc)} data fields, {len(ex)} exception types, {len(bt)} boundary/fail-safe tests")

print("LAYER 0 GATE CHECK"); print("-" * 18)
for n in notes: print(n)
if problems:
    print(f"\nNOT READY - {len(problems)} open item(s):")
    for p in problems: print(" -", p)
    sys.exit(1)
print("\nREADY - Layer 0 gate satisfied. Proceed to Layer 1."); sys.exit(0)
