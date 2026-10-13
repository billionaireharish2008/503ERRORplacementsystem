"""
Data models and Enums for Placement Statistics and Reporting System.
Strict typing and clear domain definitions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, date


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    PLACEMENT_OFFICER = "PLACEMENT_OFFICER"
    DEPARTMENT_COORDINATOR = "DEPARTMENT_COORDINATOR"
    STUDENT_REPRESENTATIVE = "STUDENT_REPRESENTATIVE"
    COMPANY_RECRUITER = "COMPANY_RECRUITER"
    AUDITOR = "AUDITOR"


class OfferStatus(str, Enum):
    OFFERED = "OFFERED"                  # Issued to student, pending decision
    ACCEPTED = "ACCEPTED"                # Formally accepted by student (binding/placed)
    DECLINED = "DECLINED"                # Declined by student
    EXPIRED = "EXPIRED"                  # Lapsed without response
    REVOKED = "REVOKED"                  # Cancelled by company or placement cell
    SUPERSEDED = "SUPERSEDED"            # Replaced by a subsequent corrected record


class OfferType(str, Enum):
    FTE_ONLY = "FTE_ONLY"
    INTERNSHIP_ONLY = "INTERNSHIP_ONLY"
    FTE_PLUS_INTERNSHIP = "FTE_PLUS_INTERNSHIP"


class StipendPeriod(str, Enum):
    MONTHLY = "MONTHLY"
    WEEKLY = "WEEKLY"
    LUMP_SUM = "LUMP_SUM"


class PolicyReviewStatus(str, Enum):
    CLEARED = "CLEARED"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    DEBARRED = "DEBARRED"
    SPECIAL_APPROVAL = "SPECIAL_APPROVAL"


class JoiningStatus(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    JOINING_CONFIRMED = "JOINING_CONFIRMED"
    JOINING_DEFERRED = "JOINING_DEFERRED"
    REVOKED_BY_COMPANY = "REVOKED_BY_COMPANY"
    ABSCONDED = "ABSCONDED"


class DriveStatus(str, Enum):
    UPCOMING = "UPCOMING"
    ONGOING = "ONGOING"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True)
class UserContext:
    user_id: str
    role: UserRole
    # Allowed programmes (None means unrestricted/all programmes)
    allowed_programmes: Optional[List[str]] = None
    # Allowed batches (None means unrestricted/all batches)
    allowed_batches: Optional[List[int]] = None
    # Allowed company ID if recruiter
    company_id: Optional[str] = None
    # Specific permission flags
    can_view_pii: bool = False
    can_view_policy_reviews: bool = False
    can_view_future_drives: bool = False
    can_view_joining_updates: bool = False
    can_export: bool = True


@dataclass
class CompensationStats:
    count: int = 0
    highest: Optional[float] = None
    average: Optional[float] = None
    median: Optional[float] = None
    currency: str = "INR"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "highest": self.highest,
            "average": round(self.average, 2) if self.average is not None else None,
            "median": round(self.median, 2) if self.median is not None else None,
            "currency": self.currency,
        }


@dataclass
class StipendStats:
    count: int = 0
    period: StipendPeriod = StipendPeriod.MONTHLY
    highest_stipend: Optional[float] = None
    average_stipend: Optional[float] = None
    median_stipend: Optional[float] = None
    currency: str = "INR"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "period": self.period.value,
            "highest_stipend": self.highest_stipend,
            "average_stipend": round(self.average_stipend, 2) if self.average_stipend is not None else None,
            "median_stipend": round(self.median_stipend, 2) if self.median_stipend is not None else None,
            "currency": self.currency,
        }


@dataclass
class DashboardMetrics:
    programme_id: Optional[str]
    batch_year: Optional[int]
    company_id: Optional[str]
    
    # Core Student aggregates
    total_registered: int
    total_eligible: int
    total_ineligible: int
    total_placed_unique: int
    total_unplaced: int
    placement_percentage: float  # Placed / Eligible * 100
    
    # Offer aggregates
    total_offers_issued: int
    total_offers_accepted: int
    total_offers_declined: int
    total_offers_expired: int
    total_offers_revoked: int
    students_with_multiple_offers: int
    
    # Compensation aggregates (strictly separated!)
    fte_ctc_stats: CompensationStats
    stipend_stats: StipendStats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": {
                "programme_id": self.programme_id,
                "batch_year": self.batch_year,
                "company_id": self.company_id,
            },
            "student_aggregates": {
                "registered": self.total_registered,
                "eligible": self.total_eligible,
                "ineligible": self.total_ineligible,
                "placed_unique": self.total_placed_unique,
                "unplaced": self.total_unplaced,
                "placement_percentage": round(self.placement_percentage, 2),
            },
            "offer_aggregates": {
                "offers_issued": self.total_offers_issued,
                "offers_accepted": self.total_offers_accepted,
                "offers_declined": self.total_offers_declined,
                "offers_expired": self.total_offers_expired,
                "offers_revoked": self.total_offers_revoked,
                "students_with_multiple_offers": self.students_with_multiple_offers,
            },
            "annual_fte_ctc": self.fte_ctc_stats.to_dict(),
            "internship_stipend": self.stipend_stats.to_dict(),
        }
