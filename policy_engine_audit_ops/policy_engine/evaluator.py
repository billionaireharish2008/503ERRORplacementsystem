"""Deterministic decision interface. Pure function: same inputs => same output."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from .config import POLICIES, PolicyConfig
from .rules import (rule_attendance, rule_deadline, rule_deregistered,
                    rule_offer_conflicts, rule_offer_state, rule_package_category,
                    rule_programme_eligibility, rule_registration)
from .types import (Decision, DecisionResult, DriveFacts, RuleOutcome, StudentFacts,
                    facts_fingerprint)

RULES = (rule_registration, rule_deregistered, rule_programme_eligibility, rule_deadline,
         rule_attendance, rule_offer_state, rule_offer_conflicts, rule_package_category)


def _apply_exceptions(outcomes, student, policy, now):
    """A BLOCK from an overridable rule is lifted only by a recorded, unexpired exception."""
    final: List[RuleOutcome] = []
    applied: List[str] = []
    for o in outcomes:
        if o.decision is Decision.BLOCK and o.rule_id in policy.overridable_rule_ids:
            for ex in student.approved_exceptions:
                if ex.rule_id != o.rule_id:
                    continue
                if ex.valid_until is not None:
                    if (now.tzinfo is None) != (ex.valid_until.tzinfo is None) or now > ex.valid_until:
                        continue
                applied.append(f"{ex.rule_id}:{ex.reference}")
                o = RuleOutcome(o.rule_id, Decision.ALLOW,
                                f"BLOCK lifted by approved exception {ex.reference} "
                                f"(approved by {ex.approved_by})")
                break
        final.append(o)
    return final, tuple(applied)


def _next_action(decision, outcomes, policy):
    if decision is Decision.ALLOW:
        return "Proceed. The decision will be re-evaluated again when the action is committed."
    if decision is Decision.REVIEW:
        return "Refer to the placement officer / policy owner for a manual decision."
    if any(o.decision is Decision.BLOCK and o.rule_id in policy.overridable_rule_ids
           for o in outcomes):
        return "Not permitted. The student may request an exception from the authorised person."
    return "Not permitted by placement policy."


def evaluate(student: StudentFacts, drive: DriveFacts, policy: PolicyConfig,
             now: datetime, *, allow_draft: bool = False) -> DecisionResult:
    """`now` is passed in (never read from the clock) so results are reproducible."""
    outcomes: List[RuleOutcome] = []
    for rule in RULES:
        try:
            outcomes.extend(rule(student, drive, policy, now))
        except Exception as exc:  # fail safe; never leak exception text (may hold data)
            outcomes.append(RuleOutcome("R-SYS-01", Decision.REVIEW,
                                        f"Rule {rule.__name__} failed ({type(exc).__name__})"))

    outcomes, applied = _apply_exceptions(outcomes, student, policy, now)

    if not policy.approved and not allow_draft:
        outcomes.append(RuleOutcome("R-POLICY-00", Decision.REVIEW,
                                    "Policy version is not approved by the policy owner"))

    if any(o.decision is Decision.BLOCK for o in outcomes) and (policy.approved or allow_draft):
        decision = Decision.BLOCK
    elif any(o.decision is not Decision.ALLOW for o in outcomes):
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW
    # An unapproved policy can never produce a final BLOCK or ALLOW in normal mode.
    if not policy.approved and not allow_draft:
        decision = Decision.REVIEW

    return DecisionResult(
        decision=decision, policy_version=policy.version, evaluated_at=now,
        outcomes=tuple(outcomes), next_action=_next_action(decision, outcomes, policy),
        facts_hash=facts_fingerprint(student, drive, now), exceptions_applied=applied)


def evaluate_by_version(student: StudentFacts, drive: DriveFacts, version: str,
                        now: datetime, *, registry: Optional[Dict[str, PolicyConfig]] = None,
                        allow_draft: bool = False) -> DecisionResult:
    """Use this in services: an unknown policy version fails safe into REVIEW."""
    policy = (registry if registry is not None else POLICIES).get(version)
    if policy is None:
        return DecisionResult(
            decision=Decision.REVIEW, policy_version=version, evaluated_at=now,
            outcomes=(RuleOutcome("R-POLICY-01", Decision.REVIEW, "Unknown policy version"),),
            next_action="Refer to the policy owner; the policy version is not recognised.",
            facts_hash=facts_fingerprint(student, drive, now))
    return evaluate(student, drive, policy, now, allow_draft=allow_draft)
