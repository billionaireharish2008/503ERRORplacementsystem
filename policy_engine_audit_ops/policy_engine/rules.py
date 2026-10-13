"""One function per rule. Each takes (student, drive, policy, now) and returns a list of
RuleOutcome. Missing / contradictory input => REVIEW. Nothing here ever assumes ALLOW."""
from __future__ import annotations

from datetime import datetime
from typing import List

from .config import Conflict, PolicyConfig
from .types import (Decision, DriveFacts, OfferStatus, OfferType, RuleOutcome,
                    StudentFacts)

A, B, R = Decision.ALLOW, Decision.BLOCK, Decision.REVIEW
_CTC_TYPES = (OfferType.F, OfferType.IF)


def _o(rule_id: str, decision: Decision, reason: str) -> List[RuleOutcome]:
    return [RuleOutcome(rule_id, decision, reason)]


def rule_registration(s: StudentFacts, d: DriveFacts, p: PolicyConfig, now: datetime):
    if s.is_registered is None:
        return _o("R-REG-01", R, "Registration status is missing")
    if not s.is_registered:
        return _o("R-REG-01", B, "Student is not registered for placements")
    return _o("R-REG-01", A, "Student is registered")


def rule_deregistered(s, d, p, now):
    if s.is_deregistered is None:
        return _o("R-REG-02", R, "Deregistration status is missing")
    if s.is_deregistered:
        return _o("R-REG-02", B, "Student has been deregistered from placements")
    return _o("R-REG-02", A, "Student is not deregistered")


def rule_programme_eligibility(s, d, p, now):
    if not s.programme:
        return _o("R-ELIG-01", R, "Student programme is missing")
    if not d.eligible_programmes:
        return _o("R-ELIG-01", R, "Drive has no eligibility criteria defined")
    if s.programme not in d.eligible_programmes:
        return _o("R-ELIG-01", B, "Programme is not eligible for this drive")
    return _o("R-ELIG-01", A, "Programme is eligible")


def rule_deadline(s, d, p, now):
    if d.application_deadline is None:
        return _o("R-DEADLINE-01", R, "Drive application deadline is missing")
    if (now.tzinfo is None) != (d.application_deadline.tzinfo is None):
        return _o("R-DEADLINE-01", R, "Naive/aware datetime mismatch; cannot compare deadline")
    if now > d.application_deadline:
        return _o("R-DEADLINE-01", B, "Application deadline has passed")
    return _o("R-DEADLINE-01", A, "Within application deadline")


def rule_attendance(s, d, p, now):
    if s.unexcused_absences is None:
        return _o("R-ATT-01", R, "Attendance record is missing")
    if p.max_unexcused_absences is None:
        return _o("R-ATT-01", R, "Attendance threshold not defined in policy")
    if s.unexcused_absences > p.max_unexcused_absences:
        return _o("R-ATT-01", B, "Unexcused absences exceed the permitted limit")
    return _o("R-ATT-01", A, "Attendance within limit")


def rule_offer_state(s, d, p, now):
    """Detect contradictory / unresolved offer data before any offer logic runs."""
    out: List[RuleOutcome] = []
    ids = [o.offer_id for o in s.offers]
    if len(ids) != len(set(ids)):
        out += _o("R-OFFER-01", R, "Duplicate offer IDs in history (contradictory data)")
    if any(o.status is OfferStatus.PENDING for o in s.offers):
        out += _o("R-OFFER-01", R, "An earlier offer is still pending a decision")
    for o in s.offers:
        if (o.status is OfferStatus.ACCEPTED and o.offer_type in _CTC_TYPES
                and o.annual_fte_ctc_lpa is None):
            out += _o("R-OFFER-01", R, "Accepted full-time offer has no CTC recorded")
    return out or _o("R-OFFER-01", A, "Offer history is consistent")


def rule_offer_conflicts(s, d, p, now):
    held = [o for o in s.offers if o.status is OfferStatus.ACCEPTED]
    if not held:
        return _o("R-OFFER-02", A, "No accepted offers held")
    out: List[RuleOutcome] = []
    for o in held:
        if o.is_ppo:
            out += _o("R-OFFER-05", R, "Student holds an accepted PPO; policy owner must decide")
        verdict = p.offer_type_matrix.get((o.offer_type, d.offer_type), Conflict.REVIEW)
        pair = f"{o.offer_type.value} held, {d.offer_type.value} drive"
        if verdict is Conflict.ALLOW:
            out += _o("R-OFFER-02", A, f"Offer-type combination permitted ({pair})")
        elif verdict is Conflict.BLOCK:
            out += _o("R-OFFER-02", B, f"Offer-type combination not permitted ({pair})")
        elif verdict is Conflict.REVIEW:
            out += _o("R-OFFER-02", R, f"Offer-type combination needs a decision ({pair})")
        else:  # CTC_CHECK
            out += _second_offer_ctc(o, d, p, pair)
    return out


def _second_offer_ctc(held, d, p, pair):
    m = p.second_offer_ctc_multiple
    if m is None or held.annual_fte_ctc_lpa is None or d.annual_fte_ctc_lpa is None:
        return _o("R-OFFER-03", R, f"Cannot compare CTC for second offer ({pair})")
    needed = m * held.annual_fte_ctc_lpa
    new = d.annual_fte_ctc_lpa
    if new > needed:
        return _o("R-OFFER-03", A, f"New CTC clears {m}x the CTC already held")
    if new == needed:
        if p.second_offer_boundary_inclusive is None:
            return _o("R-OFFER-03", R, "New CTC is exactly on the second-offer threshold; "
                                       "policy does not say if equal passes")
        ok = p.second_offer_boundary_inclusive
        return _o("R-OFFER-03", A if ok else B, "New CTC equals the second-offer threshold")
    return _o("R-OFFER-03", B, f"New CTC is below {m}x the CTC already held")


def rule_package_category(s, d, p, now):
    if d.offer_type not in _CTC_TYPES:
        return _o("R-CAT-01", A, "Internship drive: stipend is never compared with CTC")
    if d.annual_fte_ctc_lpa is None:
        return _o("R-CAT-01", R, "Drive CTC missing; cannot classify package category")
    if d.annual_fte_ctc_lpa in p.category_boundaries_lpa and not p.boundary_semantics_approved:
        return _o("R-CAT-01", R, "CTC sits exactly on a category boundary; boundary rule "
                                 "not yet approved")
    return _o("R-CAT-01", A, "Package category is unambiguous")


def package_category(ctc_lpa, p: PolicyConfig) -> int:
    """Index of the category (0 = below first boundary). Use after boundary rule is approved."""
    return sum(1 for b in p.category_boundaries_lpa if ctc_lpa >= b)
