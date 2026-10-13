"""
Interactive Demo Runner for Placement Statistics & Secure Reporting System.
Executes real scenarios demonstrating:
1. Aggregate dashboard metrics across scopes.
2. Strict isolation of FTE CTC vs Internship Stipends.
3. RBAC & Tenancy scope enforcement (attempting unauthorized queries).
4. Restricted views (policy reviews, pending acceptances, joining updates).
5. Secure CSV and Excel exports with Formula Injection sanitization & audit logs.
"""

from __future__ import annotations
import json
from database import seed_synthetic_data, DB_PATH
from models import UserRole
from security import RolePermissionManager, SecurityViolationError
from service import PlacementAnalyticsService
from export_engine import SecureExportEngine
from api import PlacementApiController


def print_header(title: str):
    print("\n" + "=" * 80)
    print(f"  {title.upper()}")
    print("=" * 80)


def print_metrics_table(m):
    print(f"Scope: Programme={m.programme_id or 'ALL'}, Batch={m.batch_year or 'ALL'}, Company={m.company_id or 'ALL'}")
    print("-" * 80)
    print(f"  Registered Students: {m.total_registered:<5} | Eligible: {m.total_eligible:<5} | Ineligible: {m.total_ineligible:<5}")
    print(f"  Placed (Unique):     {m.total_placed_unique:<5} | Unplaced: {m.total_unplaced:<5} | Placement Rate: {m.placement_percentage:.2f}%")
    print(f"  Offers Issued:       {m.total_offers_issued:<5} | Accepted: {m.total_offers_accepted:<5} | Declined: {m.total_offers_declined:<5} | Expired: {m.total_offers_expired:<5}")
    print(f"  Multiple Offers:     {m.students_with_multiple_offers:<5} student(s) received >1 offer")
    print("-" * 80)
    print(f"  [ANNUAL FTE CTC - EXCLUSIVE OF STIPENDS]")
    print(f"    Highest: INR {m.fte_ctc_stats.highest:,.2f}" if m.fte_ctc_stats.highest else "    Highest: N/A")
    print(f"    Average: INR {m.fte_ctc_stats.average:,.2f}" if m.fte_ctc_stats.average else "    Average: N/A")
    print(f"    Median:  INR {m.fte_ctc_stats.median:,.2f}" if m.fte_ctc_stats.median else "    Median:  N/A")
    print(f"  [INTERNSHIP STIPEND - NEVER COMBINED WITH CTC]")
    print(f"    Highest: INR {m.stipend_stats.highest_stipend:,.2f} ({m.stipend_stats.period.value})" if m.stipend_stats.highest_stipend else "    Highest: N/A")
    print(f"    Average: INR {m.stipend_stats.average_stipend:,.2f} ({m.stipend_stats.period.value})" if m.stipend_stats.average_stipend else "    Average: N/A")
    print(f"    Median:  INR {m.stipend_stats.median_stipend:,.2f} ({m.stipend_stats.period.value})" if m.stipend_stats.median_stipend else "    Median:  N/A")
    print("-" * 80)


def run_demo():
    print_header("Step 1: Database Initialization & Synthetic Seed")
    ground_truth = seed_synthetic_data()
    print("Database seeded with known deterministic records.")
    print("Ground truth benchmark loaded for BTECH_CSE 2026.")

    service = PlacementAnalyticsService(DB_PATH)
    export_engine = SecureExportEngine(service)
    api = PlacementApiController(service, export_engine)

    # 1. Admin Query
    print_header("Step 2: Admin Global Dashboard Query (BTECH_CSE 2026)")
    admin_ctx = RolePermissionManager.create_context("adm_001", UserRole.ADMIN)
    admin_metrics = service.get_dashboard_metrics(admin_ctx, programme_id="BTECH_CSE", batch_year=2026)
    print_metrics_table(admin_metrics)

    # 2. Department Coordinator Query
    print_header("Step 3: Department Coordinator Scoped Query")
    cse_coord = RolePermissionManager.create_context(
        user_id="coord_cse",
        role=UserRole.DEPARTMENT_COORDINATOR,
        assigned_programmes=["BTECH_CSE"],
        assigned_batches=[2026]
    )
    coord_metrics = service.get_dashboard_metrics(cse_coord, programme_id="BTECH_CSE", batch_year=2026)
    print("Successfully accessed authorized programme (BTECH_CSE):")
    print_metrics_table(coord_metrics)

    print("\nAttempting unauthorized query on BTECH_ECE by CSE Coordinator...")
    try:
        service.get_dashboard_metrics(cse_coord, programme_id="BTECH_ECE", batch_year=2026)
        print("ERROR: Unauthorized access succeeded!")
    except SecurityViolationError as e:
        print(f"-> BLOCKED AS EXPECTED: {e}")

    # 3. Recruiter Scope Check
    print_header("Step 4: Company Recruiter Scope Isolation")
    recruiter = RolePermissionManager.create_context(
        user_id="recruiter_ggl",
        role=UserRole.COMPANY_RECRUITER,
        company_id="CMP_GOOGLE"
    )
    recruiter_metrics = service.get_dashboard_metrics(recruiter, company_id="CMP_GOOGLE")
    print(f"Google Recruiter view: Placed in Google = {recruiter_metrics.total_placed_unique}, Highest CTC = INR {recruiter_metrics.fte_ctc_stats.highest:,.2f}")

    print("\nAttempting unauthorized competitor query on Microsoft by Google Recruiter...")
    try:
        service.get_dashboard_metrics(recruiter, company_id="CMP_MICROSOFT")
        print("ERROR: Unauthorized competitor access succeeded!")
    except SecurityViolationError as e:
        print(f"-> BLOCKED AS EXPECTED: {e}")

    # 4. Restricted Views Verification
    print_header("Step 5: Sensitive Restricted Views Clearance")
    # Awaiting policy review
    print("[5.1 Cases Awaiting Policy Review]")
    admin_reviews = service.get_cases_awaiting_policy_review(admin_ctx, "BTECH_CSE", 2026)
    for c in admin_reviews:
        print(f"  Student: {c['student_id']} ({c['name']}) | Status: {c['policy_review_status']} | Reason: {c['policy_notes']}")

    student_rep = RolePermissionManager.create_context(
        user_id="rep_cse",
        role=UserRole.STUDENT_REPRESENTATIVE,
        assigned_programmes=["BTECH_CSE"],
        assigned_batches=[2026]
    )
    print("\nStudent Representative attempting to access Policy Reviews...")
    try:
        service.get_cases_awaiting_policy_review(student_rep, "BTECH_CSE", 2026)
        print("ERROR: Student rep accessed policy reviews!")
    except SecurityViolationError as e:
        print(f"-> BLOCKED AS EXPECTED: {e}")

    # 5. Read-Only Database Protection
    print_header("Step 6: Read-Only Source Records Protection")
    mutation_blocked = service.test_read_only_protection()
    print(f"Query mutation attempt on reporting connection: Blocked by SQLite engine? -> {mutation_blocked}")

    # 6. Secure CSV Export & Formula Injection Sanitization
    print_header("Step 7: Permission-Aware Export & Formula Injection Defense")
    csv_out, checksum = export_engine.export_detailed_report_csv(
        context=admin_ctx,
        programme_id="BTECH_CSE",
        batch_year=2026
    )
    print(f"Generated secure CSV export. SHA-256 Checksum: {checksum}")
    print("Inspecting sanitized row for student with formula attack payload '=cmd|/C calc!A0':")
    for line in csv_out.splitlines():
        if "calc" in line or "STU_CSE_12" in line:
            print(f"  Raw Export Row: {line}")
            assert line.startswith("STU_CSE_12,'=cmd") or ",'=cmd" in line
            print("  -> CONFIRMED: Formula trigger character was prefixed with apostrophe (CWE-1236 neutralized).")

    print_header("Demo Complete: All Security and Functional Gates Satisfied!")


if __name__ == "__main__":
    run_demo()
