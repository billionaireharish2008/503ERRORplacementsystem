"""
Placement Analytics Service.
Executes all queries in strict Read-Only mode, applies RBAC and tenancy scopes,
computes verified placement metrics, and prevents data leaks.
"""

from __future__ import annotations
import sqlite3
import statistics
from typing import Optional, List, Dict, Any

from database import get_read_only_connection
from models import (
    UserContext, UserRole, OfferStatus, OfferType, StipendPeriod,
    PolicyReviewStatus, JoiningStatus, DriveStatus,
    CompensationStats, StipendStats, DashboardMetrics
)
from policy import PlacementPolicy
from security import (
    SecurityViolationError, ScopeEnforcer, PIISanitizer
)


class PlacementAnalyticsService:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path:
            return get_read_only_connection(self.db_path)
        return get_read_only_connection()

    def get_dashboard_metrics(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None,
        company_id: Optional[str] = None,
    ) -> DashboardMetrics:
        """
        Calculates aggregate dashboard metrics for registered, eligible, ineligible,
        placed and unplaced students, filtered strictly within user's authorized scope.
        """
        # 1. Enforce RBAC and Tenancy Boundary
        eff_programme, eff_batch, eff_company = ScopeEnforcer.enforce_scope(
            context, programme_id, batch_year, company_id
        )

        conn = self._get_connection()
        try:
            # Build student query filter
            student_where_clauses = []
            student_params: List[Any] = []

            if eff_programme:
                student_where_clauses.append("s.programme_id = ?")
                student_params.append(eff_programme)
            if eff_batch:
                student_where_clauses.append("s.batch_year = ?")
                student_params.append(eff_batch)

            student_where_sql = f"WHERE {' AND '.join(student_where_clauses)}" if student_where_clauses else ""

            # Core Student Aggregates
            # Registered, Eligible, Ineligible
            cursor = conn.cursor()
            student_counts_query = f"""
                SELECT 
                    SUM(CASE WHEN is_registered = 1 THEN 1 ELSE 0 END) AS registered,
                    SUM(CASE WHEN is_registered = 1 AND is_eligible = 1 THEN 1 ELSE 0 END) AS eligible,
                    SUM(CASE WHEN is_registered = 1 AND is_eligible = 0 THEN 1 ELSE 0 END) AS ineligible
                FROM students s
                {student_where_sql};
            """
            cursor.execute(student_counts_query, student_params)
            student_row = cursor.fetchone()

            total_registered = student_row["registered"] or 0
            total_eligible = student_row["eligible"] or 0
            total_ineligible = student_row["ineligible"] or 0

            # Placed Students (Unique students holding active ACCEPTED offers)
            # Filtered by student scope and optional company scope
            placed_query_clauses = [
                "s.is_registered = 1",
                "s.is_eligible = 1",
                "o.is_latest_correction = 1",
                f"o.status = '{OfferStatus.ACCEPTED.value}'"
            ]
            placed_params: List[Any] = []

            if eff_programme:
                placed_query_clauses.append("s.programme_id = ?")
                placed_params.append(eff_programme)
            if eff_batch:
                placed_query_clauses.append("s.batch_year = ?")
                placed_params.append(eff_batch)
            if eff_company:
                placed_query_clauses.append("o.company_id = ?")
                placed_params.append(eff_company)

            placed_sql = f"""
                SELECT COUNT(DISTINCT s.student_id) AS placed_unique
                FROM students s
                JOIN offers o ON s.student_id = o.student_id
                WHERE {' AND '.join(placed_query_clauses)};
            """
            cursor.execute(placed_sql, placed_params)
            placed_row = cursor.fetchone()
            total_placed_unique = placed_row["placed_unique"] or 0

            # Unplaced = Total Eligible - Total Placed Unique
            # (If company filter is active, unplaced represents eligible students not placed in that company)
            total_unplaced = max(0, total_eligible - total_placed_unique)
            placement_percentage = (
                (total_placed_unique / total_eligible * 100.0) if total_eligible > 0 else 0.0
            )

            # Offer Aggregates (Strictly non-superseded latest corrections)
            offer_where_clauses = ["o.is_latest_correction = 1"]
            offer_params: List[Any] = []

            if eff_programme:
                offer_where_clauses.append("s.programme_id = ?")
                offer_params.append(eff_programme)
            if eff_batch:
                offer_where_clauses.append("s.batch_year = ?")
                offer_params.append(eff_batch)
            if eff_company:
                offer_where_clauses.append("o.company_id = ?")
                offer_params.append(eff_company)

            offer_sql = f"""
                SELECT 
                    COUNT(*) AS total_issued,
                    SUM(CASE WHEN o.status = '{OfferStatus.ACCEPTED.value}' THEN 1 ELSE 0 END) AS total_accepted,
                    SUM(CASE WHEN o.status = '{OfferStatus.DECLINED.value}' THEN 1 ELSE 0 END) AS total_declined,
                    SUM(CASE WHEN o.status = '{OfferStatus.EXPIRED.value}' THEN 1 ELSE 0 END) AS total_expired,
                    SUM(CASE WHEN o.status = '{OfferStatus.REVOKED.value}' THEN 1 ELSE 0 END) AS total_revoked
                FROM offers o
                JOIN students s ON o.student_id = s.student_id
                WHERE {' AND '.join(offer_where_clauses)};
            """
            cursor.execute(offer_sql, offer_params)
            offer_row = cursor.fetchone()

            total_offers_issued = offer_row["total_issued"] or 0
            total_offers_accepted = offer_row["total_accepted"] or 0
            total_offers_declined = offer_row["total_declined"] or 0
            total_offers_expired = offer_row["total_expired"] or 0
            total_offers_revoked = offer_row["total_revoked"] or 0

            # Students with Multiple Offers (Count of distinct students who received > 1 active offers)
            multi_sql = f"""
                SELECT COUNT(*) AS multi_count FROM (
                    SELECT o.student_id
                    FROM offers o
                    JOIN students s ON o.student_id = s.student_id
                    WHERE {' AND '.join(offer_where_clauses)}
                    GROUP BY o.student_id
                    HAVING COUNT(o.offer_id) > 1
                );
            """
            cursor.execute(multi_sql, offer_params)
            students_with_multiple_offers = cursor.fetchone()["multi_count"] or 0

            # Annual FTE CTC Calculations (STRICTLY ISOLATED FROM INTERNSHIP STIPENDS!)
            # Calculated only on ACCEPTED offers with valid annual_fte_ctc > 0
            ctc_where = list(offer_where_clauses)
            ctc_where.append(f"o.status = '{OfferStatus.ACCEPTED.value}'")
            ctc_where.append("o.annual_fte_ctc IS NOT NULL")
            ctc_where.append("o.annual_fte_ctc > 0")

            ctc_sql = f"""
                SELECT o.annual_fte_ctc
                FROM offers o
                JOIN students s ON o.student_id = s.student_id
                WHERE {' AND '.join(ctc_where)}
                ORDER BY o.annual_fte_ctc ASC;
            """
            cursor.execute(ctc_sql, offer_params)
            ctc_values = [r["annual_fte_ctc"] for r in cursor.fetchall()]

            fte_stats = CompensationStats(
                count=len(ctc_values),
                highest=max(ctc_values) if ctc_values else None,
                average=statistics.mean(ctc_values) if ctc_values else None,
                median=statistics.median(ctc_values) if ctc_values else None,
                currency="INR"
            )

            # Internship Stipend Calculations (STRICTLY ISOLATED FROM ANNUAL CTC!)
            stipend_where = list(offer_where_clauses)
            stipend_where.append(f"o.status = '{OfferStatus.ACCEPTED.value}'")
            stipend_where.append("o.internship_stipend_amount IS NOT NULL")
            stipend_where.append("o.internship_stipend_amount > 0")

            stipend_sql = f"""
                SELECT o.internship_stipend_amount, o.stipend_period
                FROM offers o
                JOIN students s ON o.student_id = s.student_id
                WHERE {' AND '.join(stipend_where)}
                ORDER BY o.internship_stipend_amount ASC;
            """
            cursor.execute(stipend_sql, offer_params)
            stipend_rows = cursor.fetchall()
            stipend_values = [r["internship_stipend_amount"] for r in stipend_rows]

            # Invariant assertion check: Verify that stipend values were NEVER blended with FTE CTC
            PlacementPolicy.assert_stipend_ctc_isolation(ctc_values, stipend_values)

            stipend_stats = StipendStats(
                count=len(stipend_values),
                period=StipendPeriod.MONTHLY,
                highest_stipend=max(stipend_values) if stipend_values else None,
                average_stipend=statistics.mean(stipend_values) if stipend_values else None,
                median_stipend=statistics.median(stipend_values) if stipend_values else None,
                currency="INR"
            )

            return DashboardMetrics(
                programme_id=eff_programme,
                batch_year=eff_batch,
                company_id=eff_company,
                total_registered=total_registered,
                total_eligible=total_eligible,
                total_ineligible=total_ineligible,
                total_placed_unique=total_placed_unique,
                total_unplaced=total_unplaced,
                placement_percentage=placement_percentage,
                total_offers_issued=total_offers_issued,
                total_offers_accepted=total_offers_accepted,
                total_offers_declined=total_offers_declined,
                total_offers_expired=total_offers_expired,
                total_offers_revoked=total_offers_revoked,
                students_with_multiple_offers=students_with_multiple_offers,
                fte_ctc_stats=fte_stats,
                stipend_stats=stipend_stats,
            )
        finally:
            conn.close()

    def get_eligible_students_for_future_drives(
        self,
        context: UserContext,
        drive_id: str
    ) -> List[Dict[str, Any]]:
        """
        RESTRICTED VIEW:
        Displays eligible students for an upcoming placement drive.
        Authorized roles only (ADMIN, PLACEMENT_OFFICER, DEPARTMENT_COORDINATOR within dept).
        """
        if not context.can_view_future_drives:
            raise SecurityViolationError(
                f"Unauthorized: Role {context.role.value} does not have clearance to view future drive rosters."
            )

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Retrieve drive specifications
            cursor.execute(
                "SELECT drive_id, company_id, title, min_cgpa, eligible_programmes FROM drives WHERE drive_id = ?",
                (drive_id,)
            )
            drive = cursor.fetchone()
            if not drive:
                raise ValueError(f"Drive {drive_id} not found.")

            eligible_programmes = [p.strip() for p in drive["eligible_programmes"].split(",")]

            # Restrict to coordinator's allowed programmes if applicable
            if context.allowed_programmes is not None:
                eligible_programmes = [p for p in eligible_programmes if p in context.allowed_programmes]
                if not eligible_programmes:
                    return []

            placeholders = ",".join(["?"] * len(eligible_programmes))
            query = f"""
                SELECT 
                    s.student_id, s.name, s.email, s.phone, s.programme_id, s.batch_year, s.cgpa
                FROM students s
                WHERE s.is_registered = 1 
                  AND s.is_eligible = 1
                  AND s.policy_review_status = '{PolicyReviewStatus.CLEARED.value}'
                  AND s.cgpa >= ?
                  AND s.programme_id IN ({placeholders})
                ORDER BY s.cgpa DESC;
            """
            params = [drive["min_cgpa"]] + eligible_programmes
            cursor.execute(query, params)
            rows = [dict(r) for r in cursor.fetchall()]

            # Apply PII sanitization
            return [PIISanitizer.sanitize_student_record(r, context.can_view_pii) for r in rows]
        finally:
            conn.close()

    def get_pending_acceptances(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        RESTRICTED VIEW:
        Returns students holding offers currently awaiting acceptance or decline (status = OFFERED).
        Authorized roles only.
        """
        if context.role not in (UserRole.ADMIN, UserRole.PLACEMENT_OFFICER, UserRole.DEPARTMENT_COORDINATOR):
            raise SecurityViolationError(
                f"Unauthorized: Role {context.role.value} is not permitted to view pending offer acceptances."
            )

        eff_prog, eff_batch, _ = ScopeEnforcer.enforce_scope(context, programme_id, batch_year, None)

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            where_clauses = [
                f"o.status = '{OfferStatus.OFFERED.value}'",
                "o.is_latest_correction = 1"
            ]
            params: List[Any] = []

            if eff_prog:
                where_clauses.append("s.programme_id = ?")
                params.append(eff_prog)
            if eff_batch:
                where_clauses.append("s.batch_year = ?")
                params.append(eff_batch)

            sql = f"""
                SELECT 
                    o.offer_id, s.student_id, s.name, s.email, s.phone, s.programme_id,
                    c.name AS company_name, o.offer_type, o.annual_fte_ctc, 
                    o.internship_stipend_amount, o.stipend_period, o.offer_date
                FROM offers o
                JOIN students s ON o.student_id = s.student_id
                JOIN companies c ON o.company_id = c.company_id
                WHERE {' AND '.join(where_clauses)}
                ORDER BY o.offer_date DESC;
            """
            cursor.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
            return [PIISanitizer.sanitize_student_record(r, context.can_view_pii) for r in rows]
        finally:
            conn.close()

    def get_joining_updates(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        RESTRICTED VIEW:
        Returns post-placement joining status updates (CONFIRMED, DEFERRED, REVOKED, ABSCONDED).
        """
        if not context.can_view_joining_updates:
            raise SecurityViolationError(
                f"Unauthorized: Role {context.role.value} cannot access joining updates."
            )

        eff_prog, eff_batch, eff_comp = ScopeEnforcer.enforce_scope(context, programme_id, batch_year, None)

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            where_clauses = [
                f"o.status = '{OfferStatus.ACCEPTED.value}'",
                "o.is_latest_correction = 1"
            ]
            params: List[Any] = []

            if eff_prog:
                where_clauses.append("s.programme_id = ?")
                params.append(eff_prog)
            if eff_batch:
                where_clauses.append("s.batch_year = ?")
                params.append(eff_batch)
            if eff_comp:
                where_clauses.append("o.company_id = ?")
                params.append(eff_comp)

            sql = f"""
                SELECT 
                    s.student_id, s.name, s.programme_id, s.batch_year,
                    c.name AS company_name, o.annual_fte_ctc, s.joining_status
                FROM offers o
                JOIN students s ON o.student_id = s.student_id
                JOIN companies c ON o.company_id = c.company_id
                WHERE {' AND '.join(where_clauses)}
                ORDER BY s.student_id ASC;
            """
            cursor.execute(sql, params)
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def get_cases_awaiting_policy_review(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        HIGHLY SENSITIVE RESTRICTED VIEW:
        Displays disciplinary cases, debarments, or multi-offer exceptions awaiting policy committee decision.
        Restricted to ADMIN, PLACEMENT_OFFICER, and AUDITOR only.
        """
        if not context.can_view_policy_reviews:
            raise SecurityViolationError(
                f"Access Denied: Role {context.role.value} does not possess security clearance "
                f"for policy review cases."
            )

        eff_prog, eff_batch, _ = ScopeEnforcer.enforce_scope(context, programme_id, batch_year, None)

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            where_clauses = [
                f"s.policy_review_status != '{PolicyReviewStatus.CLEARED.value}'"
            ]
            params: List[Any] = []

            if eff_prog:
                where_clauses.append("s.programme_id = ?")
                params.append(eff_prog)
            if eff_batch:
                where_clauses.append("s.batch_year = ?")
                params.append(eff_batch)

            sql = f"""
                SELECT 
                    s.student_id, s.name, s.programme_id, s.batch_year, s.cgpa,
                    s.policy_review_status, s.policy_notes
                FROM students s
                WHERE {' AND '.join(where_clauses)}
                ORDER BY s.student_id ASC;
            """
            cursor.execute(sql, params)
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def get_detailed_report_data(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None,
        company_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns full row-level reporting data with PII redaction and scope enforcement.
        Used for drill-down views and exports.
        """
        eff_prog, eff_batch, eff_comp = ScopeEnforcer.enforce_scope(
            context, programme_id, batch_year, company_id
        )

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            where_clauses = ["s.is_registered = 1"]
            params: List[Any] = []

            if eff_prog:
                where_clauses.append("s.programme_id = ?")
                params.append(eff_prog)
            if eff_batch:
                where_clauses.append("s.batch_year = ?")
                params.append(eff_batch)
            if eff_comp:
                where_clauses.append("(o.company_id = ? OR o.company_id IS NULL)")
                params.append(eff_comp)

            # Left join to include both placed and unplaced students
            sql = f"""
                SELECT 
                    s.student_id,
                    s.name,
                    s.email,
                    s.phone,
                    s.programme_id,
                    s.batch_year,
                    s.cgpa,
                    s.is_eligible,
                    s.eligibility_reason,
                    o.offer_id,
                    c.name AS company_name,
                    o.offer_type,
                    o.status AS offer_status,
                    o.annual_fte_ctc,
                    o.internship_stipend_amount,
                    o.stipend_period,
                    s.joining_status
                FROM students s
                LEFT JOIN offers o ON s.student_id = o.student_id AND o.is_latest_correction = 1
                LEFT JOIN companies c ON o.company_id = c.company_id
                WHERE {' AND '.join(where_clauses)}
                ORDER BY s.student_id ASC, o.offer_date DESC;
            """
            cursor.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]

            # Apply PII Sanitization
            sanitized_rows = []
            for r in rows:
                sanitized = PIISanitizer.sanitize_student_record(r, context.can_view_pii)
                # Determine placement state flag
                sanitized["is_placed"] = (sanitized.get("offer_status") == OfferStatus.ACCEPTED.value)
                sanitized_rows.append(sanitized)

            return sanitized_rows
        finally:
            conn.close()

    def test_read_only_protection(self) -> bool:
        """
        Security verification test: Proves that reporting connections
        cannot mutate or tamper with source records.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            try:
                cursor.execute("UPDATE students SET cgpa = 10.0 WHERE student_id = 'STU_CSE_01';")
                return False  # Failed: Write succeeded on read-only connection!
            except sqlite3.OperationalError:
                return True   # Success: SQLite rejected write with OperationalError
        finally:
            conn.close()
