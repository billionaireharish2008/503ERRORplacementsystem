"""Plain-Python data types for the placement policy engine (no Django imports)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Optional, Tuple, FrozenSet


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class OfferType(str, Enum):
    I = "I"        # internship
    F = "F"        # full-time
    IF = "I+F"     # internship leading to full-time


class OfferStatus(str, Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    DECLINED = "DECLINED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class OfferFact:
    offer_id: str
    offer_type: OfferType
    status: OfferStatus
    # Annual FTE CTC in LPA. None for pure internships. NEVER put a stipend here.
    annual_fte_ctc_lpa: Optional[Decimal] = None
    # Internship stipend is kept separate from CTC on purpose.
    monthly_stipend_inr: Optional[Decimal] = None
    is_ppo: bool = False


@dataclass(frozen=True)
class ApprovedException:
    """A human-approved exception, recorded elsewhere (ExceptionRequest model).
    The engine only READS these; it never creates or approves them."""
    rule_id: str
    reference: str                     # e.g. exception request number
    approved_by: str                   # authorised person/role
    valid_until: Optional[datetime] = None


@dataclass(frozen=True)
class StudentFacts:
    placement_id: str
    programme: Optional[str]
    is_registered: Optional[bool]
    is_deregistered: Optional[bool]
    unexcused_absences: Optional[int]
    offers: Tuple[OfferFact, ...] = ()
    approved_exceptions: Tuple[ApprovedException, ...] = ()


@dataclass(frozen=True)
class DriveFacts:
    drive_id: str
    company_id: str
    offer_type: OfferType
    annual_fte_ctc_lpa: Optional[Decimal]      # required for F / I+F drives
    eligible_programmes: FrozenSet[str]
    application_deadline: Optional[datetime]


@dataclass(frozen=True)
class RuleOutcome:
    rule_id: str
    decision: Decision
    reason: str


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    policy_version: str
    evaluated_at: datetime
    outcomes: Tuple[RuleOutcome, ...]
    next_action: str
    facts_hash: str
    exceptions_applied: Tuple[str, ...] = ()

    @property
    def rule_ids(self) -> Tuple[str, ...]:
        return tuple(o.rule_id for o in self.outcomes if o.decision is not Decision.ALLOW)

    @property
    def reasons(self) -> Tuple[str, ...]:
        return tuple(o.reason for o in self.outcomes if o.decision is not Decision.ALLOW)

    def to_audit_dict(self) -> dict:
        """Minimal, PII-light record: IDs, rule IDs, version, hash. No names/contacts."""
        return {
            "decision": self.decision.value,
            "policy_version": self.policy_version,
            "evaluated_at": self.evaluated_at.isoformat(),
            "rule_ids": list(self.rule_ids),
            "reasons": list(self.reasons),
            "exceptions_applied": list(self.exceptions_applied),
            "facts_hash": self.facts_hash,
        }


def _json_default(o):
    if isinstance(o, Decimal):
        return str(o)
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, (set, frozenset)):
        return sorted(str(x) for x in o)
    raise TypeError(f"Cannot serialise {type(o).__name__}")


def facts_fingerprint(student: StudentFacts, drive: DriveFacts, now: datetime) -> str:
    """SHA-256 over canonical JSON of every input. Lets you prove later that a saved
    decision was produced from specific facts without storing extra personal data.
    (To REPLAY a decision you still need the facts: rebuild them from the history tables.)"""
    payload = {"student": asdict(student), "drive": asdict(drive), "now": now}
    blob = json.dumps(payload, default=_json_default, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
