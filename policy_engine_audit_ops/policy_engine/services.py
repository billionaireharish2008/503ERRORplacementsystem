"""Glue between Layer 1/3 models and the pure engine.

!! TEMPLATE !! The Student / Drive / Offer / Participation field names below are ASSUMED.
Adapt `_load_models`, `build_student_facts`, `build_drive_facts` to your teammates' Layer 1
schema (agree the names with them first). Authorisation (is this user allowed to act on this
student?) belongs to Layer 2 and must run in the view BEFORE this function.
"""
from decimal import Decimal

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from audit_ops.events import Action, Outcome
from audit_ops.services import record_event

from .config import DRAFT_2026_27
from .evaluator import evaluate_by_version
from .models import PolicyDecision
from .types import (ApprovedException, Decision, DriveFacts, OfferFact, OfferStatus,
                    OfferType, StudentFacts)

ACTIVE_POLICY_VERSION = DRAFT_2026_27.version      # later: read from deployment settings

_AUDIT_OUTCOME = {Decision.ALLOW: Outcome.SUCCESS, Decision.BLOCK: Outcome.DENIED,
                  Decision.REVIEW: Outcome.REVIEW}


def _load_models():
    from students.models import Student            # TODO adjust app labels
    from drives.models import Drive, Participation  # TODO adjust app labels
    return Student, Drive, Participation


def build_student_facts(student) -> StudentFacts:
    offers = tuple(
        OfferFact(o.offer_id, OfferType(o.offer_type), OfferStatus(o.status),
                  o.annual_fte_ctc_lpa, o.monthly_stipend_inr, o.is_ppo)
        for o in student.offers.all())                              # TODO related_name
    excs = tuple(
        ApprovedException(e.rule_id, e.reference, e.approved_by_role, e.valid_until)
        for e in student.exception_requests.filter(status="APPROVED"))  # TODO model/field names
    return StudentFacts(student.placement_id, student.programme.name,
                        student.is_registered, student.is_deregistered,
                        student.unexcused_absences(), offers, excs)    # TODO derive from Attendance


def build_drive_facts(drive) -> DriveFacts:
    return DriveFacts(str(drive.pk), str(drive.company_id), OfferType(drive.offer_type),
                      drive.annual_fte_ctc_lpa,
                      frozenset(drive.eligible_programmes.values_list("name", flat=True)),
                      drive.application_deadline)


@transaction.atomic
def apply_to_drive(*, user, student_pk, drive_pk, now=None):
    """Re-evaluates at commit time inside a transaction. The student row is locked so two
    simultaneous requests for the same student cannot both pass on stale offer data.
    Never trusts a decision shown earlier in the browser."""
    if not user.is_authenticated:
        raise PermissionDenied
    Student, Drive, Participation = _load_models()
    now = now or timezone.now()

    student = Student.objects.select_for_update().get(pk=student_pk)
    drive = Drive.objects.get(pk=drive_pk)

    result = evaluate_by_version(build_student_facts(student), build_drive_facts(drive),
                                 ACTIVE_POLICY_VERSION, now)

    audit = result.to_audit_dict()
    PolicyDecision.objects.create(
        placement_id=student.placement_id, drive_id=str(drive.pk),
        decision=audit["decision"], policy_version=audit["policy_version"],
        rule_ids=audit["rule_ids"], reasons=audit["reasons"],
        exceptions_applied=audit["exceptions_applied"], facts_hash=audit["facts_hash"],
        evaluated_at=now, requested_by=user)

    # Audit inside the same transaction: if the trail cannot be written (AuditWriteError) the whole
    # application attempt rolls back, so there is never an unrecorded policy decision or participation.
    record_event(action=Action.POLICY_DECISION, target_type="drive_application",
                 target_id=f"{student.placement_id}:{drive.pk}", outcome=_AUDIT_OUTCOME[result.decision],
                 actor=user,
                 metadata={"policy_version": audit["policy_version"], "rule_ids": audit["rule_ids"],
                           "exceptions_applied": audit["exceptions_applied"], "facts_hash": audit["facts_hash"],
                           "participation_created": result.decision is Decision.ALLOW})

    if result.decision is Decision.ALLOW:
        Participation.objects.create(student=student, drive=drive)  # TODO real fields
    return result
