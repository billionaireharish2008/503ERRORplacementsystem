"""Versioned policy configuration.

!! IMPORTANT !!
The official NFSU 2026-27 placement guideline text was NOT available publicly when this was
generated. Every number below marked PLACEHOLDER is a typical value seen at other Indian
institutes, NOT an NFSU rule. `approved=False` makes the engine return REVIEW in normal mode
until the policy owner signs off a real version (see evaluator.evaluate).
Rules live in code / version control only; ordinary users can never edit them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Tuple

from .types import OfferType


class Conflict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    CTC_CHECK = "CTC_CHECK"      # allowed only if the new CTC clears the multiple rule


@dataclass(frozen=True)
class PolicyConfig:
    version: str
    approved: bool
    approved_by: Optional[str]
    # attendance: max unexcused absences from drive stages (talks/tests/interviews)
    max_unexcused_absences: Optional[int]
    # second-offer rule: new CTC must be >= (or >) multiple x CTC already held
    second_offer_ctc_multiple: Optional[Decimal]
    # None = policy owner has NOT said whether exactly-equal passes -> REVIEW at the boundary
    second_offer_boundary_inclusive: Optional[bool]
    # package category cut-offs in LPA (docx notes ranges overlap at 10 and 16 LPA)
    category_boundaries_lpa: Tuple[Decimal, ...]
    boundary_semantics_approved: bool
    # (held offer type, new drive offer type) -> verdict. Missing pair => REVIEW.
    offer_type_matrix: Mapping[Tuple[OfferType, OfferType], Conflict]
    # BLOCKs from these rules may be lifted by a recorded, valid, human-approved exception
    overridable_rule_ids: FrozenSet[str]


I, F, IF = OfferType.I, OfferType.F, OfferType.IF

DRAFT_2026_27 = PolicyConfig(
    version="2026-27-DRAFT-0.1",
    approved=False,                         # flip only after the policy owner signs off
    approved_by=None,
    max_unexcused_absences=0,                              # PLACEHOLDER
    second_offer_ctc_multiple=Decimal("1.5"),              # PLACEHOLDER (common at NITs/DTU)
    second_offer_boundary_inclusive=None,                  # UNDECIDED -> REVIEW when equal
    category_boundaries_lpa=(Decimal("10"), Decimal("16")),  # from your plan; semantics unresolved
    boundary_semantics_approved=False,
    offer_type_matrix={                                    # ALL PLACEHOLDER
        (I, I): Conflict.REVIEW,
        (I, F): Conflict.ALLOW,
        (I, IF): Conflict.REVIEW,
        (F, I): Conflict.REVIEW,
        (F, F): Conflict.CTC_CHECK,
        (F, IF): Conflict.CTC_CHECK,
        (IF, I): Conflict.REVIEW,
        (IF, F): Conflict.CTC_CHECK,
        (IF, IF): Conflict.CTC_CHECK,
    },
    overridable_rule_ids=frozenset({"R-DEADLINE-01", "R-ATT-01"}),
)

# Registry of every version ever used, so old decisions stay explainable.
POLICIES: Dict[str, PolicyConfig] = {DRAFT_2026_27.version: DRAFT_2026_27}
