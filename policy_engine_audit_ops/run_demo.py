"""Runs the policy engine on sample students. No installs needed: python run_demo.py"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from dataclasses import replace

from policy_engine import (DRAFT_2026_27, ApprovedException, DriveFacts, OfferFact,
                           OfferStatus, OfferType, StudentFacts, evaluate)

NOW = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
PROG = "M.Sc. Cyber Security"


def student(pid, **kw):
    base = dict(placement_id=pid, programme=PROG, is_registered=True, is_deregistered=False,
                unexcused_absences=0, offers=(), approved_exceptions=())
    base.update(kw)
    return StudentFacts(**base)


def drive(ctc="12", **kw):
    base = dict(drive_id="D1", company_id="ACME", offer_type=OfferType.F,
                annual_fte_ctc_lpa=D(ctc), eligible_programmes=frozenset({PROG}),
                application_deadline=NOW + timedelta(days=2))
    base.update(kw)
    return DriveFacts(**base)


held10 = (OfferFact("O1", OfferType.F, OfferStatus.ACCEPTED, D("10")),)
scenarios = [
    ("Clean application",                    student("S01"), drive()),
    ("Not registered",                       student("S02", is_registered=False), drive()),
    ("Wrong programme",                      student("S03", programme="B.Tech"), drive()),
    ("Deadline passed",                      student("S04"), drive(application_deadline=NOW - timedelta(hours=1))),
    ("Deadline passed + approved exception", student("S05", approved_exceptions=(
        ApprovedException("R-DEADLINE-01", "EX-1", "Placement Officer"),)),
        drive(application_deadline=NOW - timedelta(hours=1))),
    ("Holds 10 LPA, new 12 LPA",             student("S06", offers=held10), drive("12")),
    ("Holds 10 LPA, new 15 LPA (boundary)",  student("S07", offers=held10), drive("15")),
    ("Holds 10 LPA, new 20 LPA",             student("S08", offers=held10), drive("20")),
    ("Drive CTC exactly 16 LPA",             student("S09"), drive("16")),
    ("Attendance record missing",            student("S10", unexcused_absences=None), drive()),
]


def show(title, policy, allow_draft):
    print(f"\n=== {title} ===")
    print(f"{'Scenario':<40} {'Decision':<8} Rules / reasons")
    for name, s, d in scenarios:
        r = evaluate(s, d, policy, NOW, allow_draft=allow_draft)
        why = "; ".join(f"{i}: {t}" for i, t in zip(r.rule_ids, r.reasons)) or "all rules passed"
        if r.exceptions_applied:
            why += f"  [exceptions: {', '.join(r.exceptions_applied)}]"
        print(f"{name:<40} {r.decision.value:<8} {why}")


if __name__ == "__main__":
    show("DRAFT policy, development mode (rules visible)", DRAFT_2026_27, True)
    show("DRAFT policy, NORMAL mode (unapproved => REVIEW)", DRAFT_2026_27, False)
    approved = replace(DRAFT_2026_27, version="DEMO-APPROVED", approved=True, approved_by="demo")
    show("Pretend-approved policy (demo only)", approved, False)
