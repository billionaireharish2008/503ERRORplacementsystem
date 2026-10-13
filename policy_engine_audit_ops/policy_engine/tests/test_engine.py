import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from unittest import mock

from policy_engine import (DRAFT_2026_27, ApprovedException, Decision, DriveFacts, OfferFact,
                           OfferStatus, OfferType, StudentFacts, evaluate, evaluate_by_version)
from policy_engine import evaluator

NOW = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
DEADLINE = NOW + timedelta(days=2)
P = DRAFT_2026_27
A, B, R = Decision.ALLOW, Decision.BLOCK, Decision.REVIEW


def student(**kw):
    base = dict(placement_id="P001", programme="M.Sc. Cyber Security", is_registered=True,
                is_deregistered=False, unexcused_absences=0, offers=(), approved_exceptions=())
    base.update(kw)
    return StudentFacts(**base)


def drive(**kw):
    base = dict(drive_id="D1", company_id="C1", offer_type=OfferType.F,
                annual_fte_ctc_lpa=D("12"), eligible_programmes=frozenset({"M.Sc. Cyber Security"}),
                application_deadline=DEADLINE)
    base.update(kw)
    return DriveFacts(**base)


def offer(oid="O1", t=OfferType.F, status=OfferStatus.ACCEPTED, ctc="10", **kw):
    return OfferFact(oid, t, status, D(ctc) if ctc is not None else None, **kw)


def run(s, d, now=NOW, policy=P):
    return evaluate(s, d, policy, now, allow_draft=True)


class RuleTable(unittest.TestCase):
    def test_table(self):
        past = NOW - timedelta(seconds=1)
        cases = [
            ("baseline ok",              student(), drive(), A, None),
            ("not registered",           student(is_registered=False), drive(), B, "R-REG-01"),
            ("registration missing",     student(is_registered=None), drive(), R, "R-REG-01"),
            ("deregistered",             student(is_deregistered=True), drive(), B, "R-REG-02"),
            ("programme not eligible",   student(programme="B.Tech"), drive(), B, "R-ELIG-01"),
            ("no eligibility defined",   student(), drive(eligible_programmes=frozenset()), R, "R-ELIG-01"),
            ("after deadline",           student(), drive(application_deadline=past), B, "R-DEADLINE-01"),
            ("exactly at deadline",      student(), drive(application_deadline=NOW), A, None),
            ("deadline missing",         student(), drive(application_deadline=None), R, "R-DEADLINE-01"),
            ("naive deadline",           student(), drive(application_deadline=datetime(2026, 12, 1)), R, "R-DEADLINE-01"),
            ("absence over limit",       student(unexcused_absences=1), drive(), B, "R-ATT-01"),
            ("attendance missing",       student(unexcused_absences=None), drive(), R, "R-ATT-01"),
            ("I held, F drive",          student(offers=(offer(t=OfferType.I, ctc=None),)), drive(), A, None),
            ("I held, I drive",          student(offers=(offer(t=OfferType.I, ctc=None),)),
                                         drive(offer_type=OfferType.I, annual_fte_ctc_lpa=None), R, "R-OFFER-02"),
            ("F held 10, new 12",        student(offers=(offer(ctc="10"),)), drive(annual_fte_ctc_lpa=D("12")), B, "R-OFFER-03"),
            ("F held 10, new 15 (==1.5x)", student(offers=(offer(ctc="10"),)), drive(annual_fte_ctc_lpa=D("15")), R, "R-OFFER-03"),
            ("F held 10, new 20",        student(offers=(offer(ctc="10"),)), drive(annual_fte_ctc_lpa=D("20")), A, None),
            ("declined offer ignored",   student(offers=(offer(status=OfferStatus.DECLINED),)), drive(), A, None),
            ("pending offer",            student(offers=(offer(status=OfferStatus.PENDING),)), drive(), R, "R-OFFER-01"),
            ("accepted PPO",             student(offers=(offer(t=OfferType.I, ctc=None, is_ppo=True),)), drive(), R, "R-OFFER-05"),
            ("duplicate offer ids",      student(offers=(offer("X", status=OfferStatus.DECLINED), offer("X", status=OfferStatus.DECLINED))), drive(), R, "R-OFFER-01"),
            ("accepted F, no CTC",       student(offers=(offer(ctc=None),)), drive(), R, "R-OFFER-01"),
            ("drive CTC on boundary 10", student(), drive(annual_fte_ctc_lpa=D("10")), R, "R-CAT-01"),
            ("drive CTC on boundary 16", student(), drive(annual_fte_ctc_lpa=D("16")), R, "R-CAT-01"),
            ("F drive, CTC missing",     student(), drive(annual_fte_ctc_lpa=None), R, "R-CAT-01"),
            ("BLOCK beats REVIEW",       student(is_registered=False), drive(application_deadline=None), B, "R-REG-01"),
        ]
        for name, s, d, want, rule_id in cases:
            with self.subTest(name):
                res = run(s, d)
                self.assertEqual(res.decision, want, res.reasons)
                if rule_id:
                    self.assertIn(rule_id, res.rule_ids)
                self.assertTrue(res.policy_version)
                self.assertTrue(res.next_action)


class Exceptions(unittest.TestCase):
    late = dict(application_deadline=NOW - timedelta(hours=1))

    def ex(self, rule="R-DEADLINE-01", until=None):
        return ApprovedException(rule, "EX-77", "Placement Officer", until)

    def test_valid_exception_lifts_overridable_block(self):
        res = run(student(approved_exceptions=(self.ex(),)), drive(**self.late))
        self.assertEqual(res.decision, A)
        self.assertEqual(res.exceptions_applied, ("R-DEADLINE-01:EX-77",))

    def test_expired_exception_ignored(self):
        res = run(student(approved_exceptions=(self.ex(until=NOW - timedelta(minutes=1)),)), drive(**self.late))
        self.assertEqual(res.decision, B)

    def test_non_overridable_rule_cannot_be_lifted(self):
        res = run(student(is_registered=False, approved_exceptions=(self.ex("R-REG-01"),)), drive())
        self.assertEqual(res.decision, B)

    def test_exception_for_other_rule_does_not_help(self):
        res = run(student(approved_exceptions=(self.ex("R-ATT-01"),)), drive(**self.late))
        self.assertEqual(res.decision, B)


class FailSafe(unittest.TestCase):
    def test_unapproved_policy_never_final_in_normal_mode(self):
        res = evaluate(student(), drive(), P, NOW)            # allow_draft defaults to False
        self.assertEqual(res.decision, R)
        self.assertIn("R-POLICY-00", res.rule_ids)
        res = evaluate(student(is_registered=False), drive(), P, NOW)
        self.assertEqual(res.decision, R)

    def test_approved_policy_allows(self):
        approved = replace(P, version="T-1", approved=True, approved_by="Test Owner")
        self.assertEqual(evaluate(student(), drive(), approved, NOW).decision, A)

    def test_unknown_policy_version(self):
        res = evaluate_by_version(student(), drive(), "does-not-exist", NOW)
        self.assertEqual(res.decision, R)
        self.assertIn("R-POLICY-01", res.rule_ids)

    def test_rule_crash_becomes_review_without_leaking_message(self):
        def boom(*a):
            raise ValueError("secret-student-data")
        with mock.patch.object(evaluator, "RULES", (boom,)):
            res = run(student(), drive())
        self.assertEqual(res.decision, R)
        self.assertIn("R-SYS-01", res.rule_ids)
        self.assertNotIn("secret-student-data", " ".join(res.reasons))

    def test_missing_matrix_pair_is_review(self):
        pol = replace(P, offer_type_matrix={})
        res = run(student(offers=(offer(t=OfferType.I, ctc=None),)), drive(), policy=pol)
        self.assertEqual(res.decision, R)


class Reproducibility(unittest.TestCase):
    def test_deterministic(self):
        s, d = student(offers=(offer(ctc="10"),)), drive(annual_fte_ctc_lpa=D("20"))
        r1, r2 = run(s, d), run(s, d)
        self.assertEqual(r1, r2)
        self.assertEqual(r1.facts_hash, r2.facts_hash)

    def test_hash_changes_when_facts_change(self):
        self.assertNotEqual(run(student(), drive()).facts_hash,
                            run(student(unexcused_absences=2), drive()).facts_hash)

    def test_audit_dict_is_json_and_pii_light(self):
        audit = run(student(), drive()).to_audit_dict()
        blob = json.dumps(audit)
        self.assertNotIn("P001", blob)           # not even the placement ID is inside
        self.assertEqual(set(audit), {"decision", "policy_version", "evaluated_at", "rule_ids",
                                      "reasons", "exceptions_applied", "facts_hash"})


if __name__ == "__main__":
    unittest.main()
