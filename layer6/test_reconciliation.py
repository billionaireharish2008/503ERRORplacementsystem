"""
Comprehensive Reconciliation and Security Test Suite.
Validates all requirements and completion gates:
1. All counts match test data (Registered == Eligible + Ineligible, Placed + Unplaced == Eligible).
2. Stipends are never combined with annual CTC.
3. Users see only the metrics and records within their approved scope.
4. Read-only safety prevents data mutation from reporting.
5. Formula injection and PII leakage prevention.
"""

import unittest
import os
import sqlite3
import csv
from typing import Dict, Any

from database import init_database, seed_synthetic_data, get_read_only_connection, get_write_connection, DB_PATH
from models import (
    UserRole, UserContext, OfferStatus, StipendPeriod, PolicyReviewStatus
)
from policy import PlacementPolicy
from security import (
    RolePermissionManager, ScopeEnforcer, FormulaInjectionSanitizer,
    SecurityViolationError, PIISanitizer
)
from service import PlacementAnalyticsService
from export_engine import SecureExportEngine
from api import PlacementApiController


class TestPlacementAnalyticsReconciliation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a fresh temporary test database
        cls.test_db_path = os.path.join(os.path.dirname(__file__), "test_placement_data.db")
        cls.ground_truth = seed_synthetic_data(cls.test_db_path)["btech_cse_2026"]
        cls.service = PlacementAnalyticsService(db_path=cls.test_db_path)
        cls.export_engine = SecureExportEngine(cls.service)
        cls.api = PlacementApiController(cls.service, cls.export_engine)

    @classmethod
    def tearDownClass(cls):
        # Clean up test database if needed
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except Exception:
                pass

    # =========================================================================
    # GATE 1: All counts match test data & mathematical invariants reconcile
    # =========================================================================
    def test_dashboard_metrics_counts_match_ground_truth(self):
        """Verifies all student and offer counts match the known test dataset exactly."""
        admin_context = RolePermissionManager.create_context("admin_01", UserRole.ADMIN)
        metrics = self.service.get_dashboard_metrics(
            context=admin_context,
            programme_id="BTECH_CSE",
            batch_year=2026
        )

        gt = self.ground_truth
        self.assertEqual(metrics.total_registered, gt["registered"], "Registered count mismatch")
        self.assertEqual(metrics.total_eligible, gt["eligible"], "Eligible count mismatch")
        self.assertEqual(metrics.total_ineligible, gt["ineligible"], "Ineligible count mismatch")
        self.assertEqual(metrics.total_placed_unique, gt["placed_unique"], "Placed unique count mismatch")
        self.assertEqual(metrics.total_unplaced, gt["unplaced"], "Unplaced count mismatch")
        self.assertAlmostEqual(metrics.placement_percentage, gt["placement_rate"], places=2)

        # Offer metrics
        self.assertEqual(metrics.total_offers_issued, gt["offers_active_total"], "Total active offers mismatch")
        self.assertEqual(metrics.total_offers_accepted, gt["offers_accepted"], "Accepted offers mismatch")
        self.assertEqual(metrics.total_offers_declined, gt["offers_declined"], "Declined offers mismatch")
        self.assertEqual(metrics.total_offers_expired, gt["offers_expired"], "Expired offers mismatch")
        self.assertEqual(metrics.students_with_multiple_offers, gt["students_with_multiple_offers"], "Multiple offers count mismatch")

    def test_mathematical_invariants(self):
        """Verifies formal mathematical invariants in the policy layer."""
        admin_context = RolePermissionManager.create_context("admin_01", UserRole.ADMIN)
        m = self.service.get_dashboard_metrics(admin_context, "BTECH_CSE", 2026)

        reconciliation = PlacementPolicy.reconcile_metrics(
            registered=m.total_registered,
            eligible=m.total_eligible,
            ineligible=m.total_ineligible,
            placed_unique=m.total_placed_unique,
            unplaced=m.total_unplaced,
            offers_issued=m.total_offers_issued,
            accepted_offers=m.total_offers_accepted,
            declined_offers=m.total_offers_declined,
            expired_offers=m.total_offers_expired,
            revoked_offers=m.total_offers_revoked,
        )

        self.assertTrue(reconciliation["reconciled"], f"Invariant violations: {reconciliation['violations']}")
        self.assertEqual(len(reconciliation["violations"]), 0)
        # Check: Registered == Eligible + Ineligible
        self.assertEqual(m.total_registered, m.total_eligible + m.total_ineligible)
        # Check: Eligible == Placed + Unplaced
        self.assertEqual(m.total_eligible, m.total_placed_unique + m.total_unplaced)

    def test_unique_placed_vs_offer_volume(self):
        """
        Reports unique placed students separately from total offers.
        Verifies that STU_03 (who received 2 offers) does not artificially inflate the placed count.
        """
        admin_context = RolePermissionManager.create_context("admin_01", UserRole.ADMIN)
        metrics = self.service.get_dashboard_metrics(admin_context, "BTECH_CSE", 2026)

        # 8 unique students placed, but 11 total active offers issued (8 accepted, 2 declined, 1 expired)
        self.assertEqual(metrics.total_placed_unique, 8)
        self.assertEqual(metrics.total_offers_issued, 11)
        self.assertNotEqual(metrics.total_placed_unique, metrics.total_offers_issued)

    def test_declined_and_expired_offers_keep_students_unplaced(self):
        """
        Verifies:
        - STU_09 had an offer that was DECLINED -> remains UNPLACED
        - STU_10 had an offer that EXPIRED -> remains UNPLACED
        """
        admin_context = RolePermissionManager.create_context("admin_01", UserRole.ADMIN)
        detailed_data = self.service.get_detailed_report_data(admin_context, "BTECH_CSE", 2026)

        records_by_id = {r["student_id"]: r for r in detailed_data}

        # STU_09 declined Google offer
        stu_09 = records_by_id["STU_CSE_09"]
        self.assertEqual(stu_09["offer_status"], OfferStatus.DECLINED.value)
        self.assertFalse(stu_09["is_placed"], "Student with declined offer must not be placed")

        # STU_10 expired Microsoft offer
        stu_10 = records_by_id["STU_CSE_10"]
        self.assertEqual(stu_10["offer_status"], OfferStatus.EXPIRED.value)
        self.assertFalse(stu_10["is_placed"], "Student with expired offer must not be placed")

    def test_corrections_superseded_records_excluded(self):
        """
        Verifies that when an offer is corrected, the superseded record (is_latest_correction=0)
        is excluded from statistics, preventing double counting and skewed averages.
        """
        admin_context = RolePermissionManager.create_context("admin_01", UserRole.ADMIN)
        metrics = self.service.get_dashboard_metrics(admin_context, "BTECH_CSE", 2026)

        # In raw database, there are 12 offer rows for CSE (including OFF_CSE_06_OLD which was superseded)
        # But total active offers must be exactly 11!
        self.assertEqual(metrics.total_offers_issued, 11)

    # =========================================================================
    # GATE 2: Stipends are never combined with annual CTC
    # =========================================================================
    def test_compensation_isolation_and_values(self):
        """
        Verifies Highest, Average, and Median annual FTE CTC are calculated separately
        from internship stipend, and stipends are never combined with CTC.
        """
        admin_context = RolePermissionManager.create_context("admin_01", UserRole.ADMIN)
        metrics = self.service.get_dashboard_metrics(admin_context, "BTECH_CSE", 2026)

        gt = self.ground_truth
        fte = metrics.fte_ctc_stats
        stipend = metrics.stipend_stats

        # FTE CTC Checks
        self.assertEqual(fte.count, gt["fte_count"])
        self.assertEqual(fte.highest, gt["fte_highest"])
        self.assertAlmostEqual(fte.average, gt["fte_average"], places=2)
        self.assertEqual(fte.median, gt["fte_median"])

        # Stipend Checks
        self.assertEqual(stipend.count, gt["stipend_count"])
        self.assertEqual(stipend.period, StipendPeriod.MONTHLY)
        self.assertEqual(stipend.highest_stipend, gt["stipend_highest"])
        self.assertAlmostEqual(stipend.average_stipend, gt["stipend_average"], places=2)
        self.assertEqual(stipend.median_stipend, gt["stipend_median"])

        # STIPEND ISOLATION PROOF:
        # If stipends (80,000 and 60,000) were accidentally averaged into FTE CTC,
        # the average would plummet from 16,00,000 down to ~12,60,000!
        self.assertGreater(fte.average, 1500000.0)
        self.assertEqual(fte.average, 1600000.0)

        # Check that pure internship offer (STU_08) didn't pollute FTE count
        self.assertEqual(fte.count, 7)  # 7 FTEs, not 8!

    # =========================================================================
    # GATE 3: Users see only the metrics and records within their approved scope
    # =========================================================================
    def test_coordinator_scope_isolation_prevent_data_leaks(self):
        """
        A Department Coordinator for BTECH_CSE must only see BTECH_CSE data.
        Attempting to query BTECH_ECE must be blocked with SecurityViolationError.
        """
        cse_coord = RolePermissionManager.create_context(
            user_id="coord_cse_01",
            role=UserRole.DEPARTMENT_COORDINATOR,
            assigned_programmes=["BTECH_CSE"],
            assigned_batches=[2026]
        )

        # 1. Allowed request: BTECH_CSE
        metrics = self.service.get_dashboard_metrics(cse_coord, programme_id="BTECH_CSE", batch_year=2026)
        self.assertEqual(metrics.total_registered, 15)

        # 2. Blocked request: BTECH_ECE (Attempted Cross-Department Data Leak)
        with self.assertRaises(SecurityViolationError) as cm:
            self.service.get_dashboard_metrics(cse_coord, programme_id="BTECH_ECE", batch_year=2026)
        self.assertIn("cannot access programme BTECH_ECE", str(cm.exception))

    def test_recruiter_scope_isolation(self):
        """
        A Recruiter for Google India must only see Google metrics and cannot query Microsoft.
        """
        google_recruiter = RolePermissionManager.create_context(
            user_id="recruiter_ggl",
            role=UserRole.COMPANY_RECRUITER,
            company_id="CMP_GOOGLE"
        )

        # 1. Allowed request: Own company
        m_google = self.service.get_dashboard_metrics(google_recruiter, company_id="CMP_GOOGLE")
        self.assertEqual(m_google.company_id, "CMP_GOOGLE")

        # 2. Blocked request: Competitor company
        with self.assertRaises(SecurityViolationError) as cm:
            self.service.get_dashboard_metrics(google_recruiter, company_id="CMP_MICROSOFT")
        self.assertIn("cannot query company CMP_MICROSOFT", str(cm.exception))

    def test_restricted_views_authorization(self):
        """
        Ensures restricted endpoints are strictly guarded:
        - Future drives roster
        - Pending acceptances
        - Joining updates
        - Cases awaiting policy review
        """
        admin = RolePermissionManager.create_context("admin", UserRole.ADMIN)
        recruiter = RolePermissionManager.create_context("recruiter", UserRole.COMPANY_RECRUITER, company_id="CMP_GOOGLE")
        student_rep = RolePermissionManager.create_context(
            "student_rep", UserRole.STUDENT_REPRESENTATIVE,
            assigned_programmes=["BTECH_CSE"], assigned_batches=[2026]
        )

        # Policy reviews: Admin can view, Student Rep and Recruiter blocked!
        admin_cases = self.service.get_cases_awaiting_policy_review(admin, "BTECH_CSE", 2026)
        self.assertGreater(len(admin_cases), 0)

        with self.assertRaises(SecurityViolationError):
            self.service.get_cases_awaiting_policy_review(recruiter, "BTECH_CSE", 2026)

        with self.assertRaises(SecurityViolationError):
            self.service.get_cases_awaiting_policy_review(student_rep, "BTECH_CSE", 2026)

        # Future drives: Student Rep and Recruiter blocked!
        with self.assertRaises(SecurityViolationError):
            self.service.get_eligible_students_for_future_drives(student_rep, "DRV_FUTURE_01")

        with self.assertRaises(SecurityViolationError):
            self.service.get_eligible_students_for_future_drives(recruiter, "DRV_FUTURE_01")

    # =========================================================================
    # Read-Only Source Records Protection
    # =========================================================================
    def test_read_only_protection_blocks_mutations(self):
        """
        Proves that reporting queries cannot alter source database records.
        Directly tests SQLite PRAGMA query_only enforcement.
        """
        is_protected = self.service.test_read_only_protection()
        self.assertTrue(is_protected, "Read-only guard failed to block update operation!")

    # =========================================================================
    # Secure Exports & Formula Injection & PII Suppression
    # =========================================================================
    def test_formula_injection_defense_in_csv_export(self):
        """
        Tests CSV formula injection protection (CWE-1236).
        Student name '=cmd|'/C calc'!A0' must be escaped with a single quote.
        """
        admin = RolePermissionManager.create_context("admin", UserRole.ADMIN)
        csv_text, checksum = self.export_engine.export_detailed_report_csv(
            context=admin, programme_id="BTECH_CSE", batch_year=2026
        )

        # Check that dangerous payload was neutralized
        self.assertIn("'=cmd|'/C calc'!A0", csv_text)
        self.assertNotIn("\n=cmd|'/C calc'!A0", csv_text)

    def test_pii_excluded_by_default_in_export(self):
        """
        Phone and email must be excluded by default from exports.
        """
        admin_no_pii = RolePermissionManager.create_context("admin", UserRole.ADMIN, explicit_pii_grant=False)
        csv_text, checksum = self.export_engine.export_detailed_report_csv(
            context=admin_no_pii, programme_id="BTECH_CSE", batch_year=2026
        )

        # Verify headers do not include Email or Phone
        reader = csv.reader(csv_text.splitlines())
        headers = next(reader)
        self.assertNotIn("Email", headers)
        self.assertNotIn("Phone", headers)

    def test_export_audit_logging(self):
        """
        Verifies that every sensitive export is logged into export_audit_log
        with user, role, checksum, and parameters.
        """
        admin = RolePermissionManager.create_context("admin_audit", UserRole.ADMIN)
        csv_text, checksum = self.export_engine.export_detailed_report_csv(
            context=admin, programme_id="BTECH_CSE", batch_year=2026
        )

        conn = get_read_only_connection(self.test_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM export_audit_log WHERE sha256_checksum = ?", (checksum,))
            log_entry = cursor.fetchone()
            self.assertIsNotNone(log_entry, "Audit log entry was not created for export!")
            self.assertEqual(log_entry["user_id"], "admin_audit")
            self.assertEqual(log_entry["role"], "ADMIN")
            self.assertEqual(log_entry["programme_filter"], "BTECH_CSE")
        finally:
            conn.close()

    # =========================================================================
    # REST API Gateway Tests
    # =========================================================================
    def test_api_gateway_returns_http_codes_and_payloads(self):
        """Tests the unified API dispatch router."""
        admin = RolePermissionManager.create_context("admin", UserRole.ADMIN)
        student_rep = RolePermissionManager.create_context(
            "rep_01", UserRole.STUDENT_REPRESENTATIVE,
            assigned_programmes=["BTECH_CSE"], assigned_batches=[2026]
        )

        # 1. Dashboard API call
        status, headers, body = self.api.handle_request(
            endpoint="/api/v1/dashboard",
            method="GET",
            context=admin,
            params={"programme_id": "BTECH_CSE", "batch_year": 2026}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["student_aggregates"]["registered"], 15)
        self.assertEqual(body["annual_fte_ctc"]["highest"], 2600000.0)

        # 2. Restricted endpoint call from unauthorized role -> 403 Forbidden
        status, headers, body = self.api.handle_request(
            endpoint="/api/v1/restricted/policy-reviews",
            method="GET",
            context=student_rep,
            params={"programme_id": "BTECH_CSE"}
        )
        self.assertEqual(status, 403)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
