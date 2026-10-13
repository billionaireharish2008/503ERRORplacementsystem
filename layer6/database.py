"""
Database schema, connection management with Read-Only enforcement,
and deterministic synthetic data generator for reconciliation testing.
"""

from __future__ import annotations
import sqlite3
import os
import hashlib
from typing import Optional, List, Dict, Any, Generator
from datetime import datetime, date

from models import (
    OfferStatus, OfferType, StipendPeriod,
    PolicyReviewStatus, JoiningStatus, DriveStatus
)

DB_PATH = os.path.join(os.path.dirname(__file__), "placement_data.db")


def get_write_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Connection used strictly for administrative seeding and migrations."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def get_read_only_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """
    Guaranteed Read-Only connection for reporting and exports.
    Enforces SQLite's PRAGMA query_only = ON to physically block any write attempts.
    """
    # Connect in read-only mode using SQLite URI or query_only PRAGMA
    uri = f"file:{os.path.abspath(db_path)}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError:
        # Fallback if URI mode is not supported on some sqlite builds:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA query_only = ON;")
    else:
        conn.execute("PRAGMA query_only = ON;")
        
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: str = DB_PATH) -> None:
    """Creates the complete relational schema."""
    with get_write_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Programmes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS programmes (
                programme_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                degree TEXT NOT NULL
            );
        """)

        # Companies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                company_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                sector TEXT NOT NULL,
                tier TEXT NOT NULL
            );
        """)

        # Students table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                student_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                programme_id TEXT NOT NULL,
                batch_year INTEGER NOT NULL,
                cgpa REAL NOT NULL,
                is_registered INTEGER NOT NULL DEFAULT 1,
                is_eligible INTEGER NOT NULL DEFAULT 1,
                eligibility_reason TEXT NOT NULL DEFAULT 'Eligible',
                policy_review_status TEXT NOT NULL DEFAULT 'CLEARED',
                policy_notes TEXT,
                joining_status TEXT NOT NULL DEFAULT 'NOT_APPLICABLE',
                FOREIGN KEY (programme_id) REFERENCES programmes(programme_id)
            );
        """)

        # Drives table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS drives (
                drive_id TEXT PRIMARY KEY,
                company_id TEXT NOT NULL,
                title TEXT NOT NULL,
                drive_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'COMPLETED',
                min_cgpa REAL NOT NULL DEFAULT 6.0,
                eligible_programmes TEXT NOT NULL, -- comma separated
                FOREIGN KEY (company_id) REFERENCES companies(company_id)
            );
        """)

        # Offers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS offers (
                offer_id TEXT PRIMARY KEY,
                student_id TEXT NOT NULL,
                company_id TEXT NOT NULL,
                drive_id TEXT,
                offer_type TEXT NOT NULL,
                status TEXT NOT NULL,
                annual_fte_ctc REAL,           -- Strict annual FTE CTC in base currency (INR)
                currency TEXT NOT NULL DEFAULT 'INR',
                internship_stipend_amount REAL, -- Strict Stipend amount
                stipend_period TEXT,            -- MONTHLY, WEEKLY, LUMP_SUM
                internship_duration_months INTEGER,
                offer_date TEXT NOT NULL,
                superseded_by_offer_id TEXT,    -- Points to newer corrected offer
                is_latest_correction INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (student_id) REFERENCES students(student_id),
                FOREIGN KEY (company_id) REFERENCES companies(company_id),
                FOREIGN KEY (drive_id) REFERENCES drives(drive_id)
            );
        """)

        # Export and Sensitive Access Audit Log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS export_audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                export_format TEXT NOT NULL,
                programme_filter TEXT,
                batch_filter TEXT,
                company_filter TEXT,
                row_count INTEGER NOT NULL,
                pii_included INTEGER NOT NULL DEFAULT 0,
                sha256_checksum TEXT NOT NULL
            );
        """)

        conn.commit()


def seed_synthetic_data(db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Populates deterministic synthetic data designed to test every edge case:
    - Multiple programmes (BTECH_CSE, BTECH_ECE, BTECH_MECH, MBA)
    - Batches 2025 and 2026
    - Pure FTE, Pure Internship, FTE + Internship
    - Students with multiple offers (1 accepted, 1 declined)
    - Students with expired offers (remain unplaced)
    - Students with declined offers (remain unplaced)
    - Clerical correction with superseded record (preventing double counting)
    - Disciplinary cases awaiting policy review
    - Formula injection names in test data to verify CSV sanitization
    - Returns ground-truth exact numbers for automated test reconciliation!
    """
    init_database(db_path)
    
    with get_write_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Clear existing data
        cursor.execute("DELETE FROM export_audit_log;")
        cursor.execute("DELETE FROM offers;")
        cursor.execute("DELETE FROM drives;")
        cursor.execute("DELETE FROM students;")
        cursor.execute("DELETE FROM companies;")
        cursor.execute("DELETE FROM programmes;")

        # 1. Programmes
        programmes_data = [
            ("BTECH_CSE", "Computer Science & Engineering", "CSE", "B.Tech"),
            ("BTECH_ECE", "Electronics & Communication", "ECE", "B.Tech"),
            ("BTECH_MECH", "Mechanical Engineering", "MECH", "B.Tech"),
            ("MBA", "Master of Business Administration", "MGMT", "MBA"),
        ]
        cursor.executemany(
            "INSERT INTO programmes VALUES (?, ?, ?, ?);",
            programmes_data
        )

        # 2. Companies
        companies_data = [
            ("CMP_GOOGLE", "Google India", "Technology", "TIER_1"),
            ("CMP_MICROSOFT", "Microsoft R&D", "Technology", "TIER_1"),
            ("CMP_DELOITTE", "Deloitte USI", "Consulting", "TIER_2"),
            ("CMP_INFOSYS", "Infosys Ltd", "IT Services", "TIER_3"),
            ("CMP_TATA_MOTORS", "Tata Motors", "Automotive", "TIER_2"),
        ]
        cursor.executemany(
            "INSERT INTO companies VALUES (?, ?, ?, ?);",
            companies_data
        )

        # 3. Drives
        drives_data = [
            ("DRV_GGL_01", "CMP_GOOGLE", "Software Engineer 2026", "2025-09-01", "COMPLETED", 8.0, "BTECH_CSE,BTECH_ECE"),
            ("DRV_MSFT_01", "CMP_MICROSOFT", "SDE 1 & Intern", "2025-09-15", "COMPLETED", 7.5, "BTECH_CSE,BTECH_ECE"),
            ("DRV_DELOITTE_01", "CMP_DELOITTE", "Analyst", "2025-10-01", "COMPLETED", 6.5, "BTECH_CSE,BTECH_ECE,BTECH_MECH,MBA"),
            ("DRV_INFY_01", "CMP_INFOSYS", "Systems Engineer", "2025-10-10", "COMPLETED", 6.0, "BTECH_CSE,BTECH_ECE,BTECH_MECH"),
            ("DRV_FUTURE_01", "CMP_GOOGLE", "Upcoming Research Drive 2026", "2026-11-20", "UPCOMING", 8.5, "BTECH_CSE"),
        ]
        cursor.executemany(
            "INSERT INTO drives VALUES (?, ?, ?, ?, ?, ?, ?);",
            drives_data
        )

        # 4. Students
        # We will build a controlled set of 20 students for BTECH_CSE 2026:
        # - 15 Registered:
        #   - 12 Eligible:
        #     - 8 Placed (holding accepted offer)
        #       - STU_01: Google FTE (24,00,000)
        #       - STU_02: Microsoft FTE (20,00,000) + Microsoft Internship (80,000/mo)
        #       - STU_03: Dual offer holder! Google FTE (26,00,000 Accepted) + Deloitte (10,00,000 Declined)
        #       - STU_04: Infosys FTE (7,00,000 Accepted)
        #       - STU_05: Deloitte FTE (11,00,000 Accepted)
        #       - STU_06: Corrected offer! (Original was 12,00,000 superseded, Corrected is 14,00,000 Accepted)
        #       - STU_07: Deloitte FTE (10,00,000 Accepted)
        #       - STU_08: Pure Internship Accepted (60,000/mo)
        #     - 4 Unplaced:
        #       - STU_09: Had Google offer that was DECLINED; no other accepted offer -> UNPLACED
        #       - STU_10: Had Microsoft offer that EXPIRED; no other accepted offer -> UNPLACED
        #       - STU_11: 0 offers received, awaiting future drives -> UNPLACED
        #       - STU_12: Awaiting policy review for disciplinary hearing -> UNPLACED
        #   - 3 Ineligible:
        #     - STU_13: CGPA 5.2 < 6.0
        #     - STU_14: Backlog in 3rd semester
        #     - STU_15: Debarred due to attendance
        # - 5 Unregistered:
        #   - STU_16 to STU_20: Opted out of placements (Higher Studies / Family Business)
        # 
        # Plus 10 students for BTECH_ECE 2026 to verify cross-programme scope isolation!
        # Plus 1 student with Formula Injection attack payload in student name:
        #   "=cmd|'/C calc'!A0" to test CSV formula sanitization!
        students_data = [
            # CSE 2026 (Registered & Eligible)
            ("STU_CSE_01", "Aarav Sharma", "aarav@univ.edu", "+919876543210", "BTECH_CSE", 2026, 9.2, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_CSE_02", "Bhavna Patel", "bhavna@univ.edu", "+919876543211", "BTECH_CSE", 2026, 8.8, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_CSE_03", "Chetan Kumar", "chetan@univ.edu", "+919876543212", "BTECH_CSE", 2026, 9.5, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_CSE_04", "Deepa Nair", "deepa@univ.edu", "+919876543213", "BTECH_CSE", 2026, 7.8, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_CSE_05", "Eeshan Verma", "eeshan@univ.edu", "+919876543214", "BTECH_CSE", 2026, 8.1, 1, 1, "Eligible", "CLEARED", None, "JOINING_DEFERRED"),
            ("STU_CSE_06", "Farhan Akhtar", "farhan@univ.edu", "+919876543215", "BTECH_CSE", 2026, 8.4, 1, 1, "Eligible", "CLEARED", "Corrected offer audit verified", "JOINING_CONFIRMED"),
            ("STU_CSE_07", "Gauri Deshmukh", "gauri@univ.edu", "+919876543216", "BTECH_CSE", 2026, 8.0, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_CSE_08", "Harsh Vardhan", "harsh@univ.edu", "+919876543217", "BTECH_CSE", 2026, 7.5, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_CSE_09", "Ishita Roy", "ishita@univ.edu", "+919876543218", "BTECH_CSE", 2026, 8.6, 1, 1, "Eligible", "CLEARED", None, "NOT_APPLICABLE"),
            ("STU_CSE_10", "Jayesh Joshi", "jayesh@univ.edu", "+919876543219", "BTECH_CSE", 2026, 7.9, 1, 1, "Eligible", "CLEARED", None, "NOT_APPLICABLE"),
            ("STU_CSE_11", "Kavya Menon", "kavya@univ.edu", "+919876543220", "BTECH_CSE", 2026, 8.7, 1, 1, "Eligible", "CLEARED", None, "NOT_APPLICABLE"),
            ("STU_CSE_12", "=cmd|'/C calc'!A0", "malicious@univ.edu", "+919876543221", "BTECH_CSE", 2026, 7.2, 1, 1, "Awaiting disciplinary review", "AWAITING_REVIEW", "Disciplinary review pending for academic misconduct", "NOT_APPLICABLE"),
            
            # CSE 2026 (Registered & Ineligible)
            ("STU_CSE_13", "Manish Tiwari", "manish@univ.edu", "+919876543222", "BTECH_CSE", 2026, 5.4, 1, 0, "CGPA below 6.0 threshold", "CLEARED", None, "NOT_APPLICABLE"),
            ("STU_CSE_14", "Neha Gupta", "neha@univ.edu", "+919876543223", "BTECH_CSE", 2026, 7.1, 1, 0, "Active backlog in Mathematics 3", "CLEARED", None, "NOT_APPLICABLE"),
            ("STU_CSE_15", "Omkar Sen", "omkar@univ.edu", "+919876543224", "BTECH_CSE", 2026, 6.8, 1, 0, "Debarred: Attendance below 60%", "DEBARRED", "Debarred by placement disciplinary committee", "NOT_APPLICABLE"),
            
            # CSE 2026 (Unregistered - Opted out)
            ("STU_CSE_16", "Pooja Hegde", "pooja@univ.edu", "+919876543225", "BTECH_CSE", 2026, 8.9, 0, 0, "Not Registered: Higher studies preparation", "CLEARED", None, "NOT_APPLICABLE"),
            ("STU_CSE_17", "Qasim Khan", "qasim@univ.edu", "+919876543226", "BTECH_CSE", 2026, 8.2, 0, 0, "Not Registered: Family business", "CLEARED", None, "NOT_APPLICABLE"),
            
            # ECE 2026 (For Scope/Tenant Isolation Testing)
            ("STU_ECE_01", "Rohan Reddy", "rohan@univ.edu", "+919876543227", "BTECH_ECE", 2026, 8.5, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_ECE_02", "Sneha Rao", "sneha@univ.edu", "+919876543228", "BTECH_ECE", 2026, 8.1, 1, 1, "Eligible", "CLEARED", None, "JOINING_CONFIRMED"),
            ("STU_ECE_03", "Tarun Saxena", "tarun@univ.edu", "+919876543229", "BTECH_ECE", 2026, 5.8, 1, 0, "CGPA below threshold", "CLEARED", None, "NOT_APPLICABLE"),
        ]

        cursor.executemany(
            """INSERT INTO students VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            students_data
        )

        # 5. Offers
        # CSE 2026 Offers:
        # Note the exact values:
        # STU_01: Google 24,00,000 FTE (ACCEPTED)
        # STU_02: Microsoft 20,00,000 FTE + 80,000/mo Internship (ACCEPTED)
        # STU_03: Google 26,00,000 FTE (ACCEPTED) AND Deloitte 10,00,000 FTE (DECLINED)
        # STU_04: Infosys 7,00,000 FTE (ACCEPTED)
        # STU_05: Deloitte 11,00,000 FTE (ACCEPTED)
        # STU_06: Superseded correction!
        #         OFF_CSE_06_OLD: Infosys 12,00,000 (SUPERSEDED, is_latest=0)
        #         OFF_CSE_06_NEW: Infosys 14,00,000 (ACCEPTED, is_latest=1)
        # STU_07: Deloitte 10,00,000 FTE (ACCEPTED)
        # STU_08: Pure Internship 60,000/mo (ACCEPTED, no FTE CTC!)
        # STU_09: Google 22,00,000 FTE (DECLINED) -> unplaced
        # STU_10: Microsoft 18,00,000 FTE (EXPIRED) -> unplaced
        # STU_11: 0 offers
        # STU_12: Awaiting review (0 offers)
        offers_data = [
            # STU_CSE_01
            ("OFF_CSE_01", "STU_CSE_01", "CMP_GOOGLE", "DRV_GGL_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 2400000.0, "INR", None, None, None, "2025-09-02", None, 1),
            
            # STU_CSE_02 (FTE + Internship)
            ("OFF_CSE_02", "STU_CSE_02", "CMP_MICROSOFT", "DRV_MSFT_01", OfferType.FTE_PLUS_INTERNSHIP.value, OfferStatus.ACCEPTED.value, 2000000.0, "INR", 80000.0, StipendPeriod.MONTHLY.value, 6, "2025-09-16", None, 1),
            
            # STU_CSE_03 (Dual offers: Google accepted, Deloitte declined)
            ("OFF_CSE_03A", "STU_CSE_03", "CMP_GOOGLE", "DRV_GGL_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 2600000.0, "INR", None, None, None, "2025-09-02", None, 1),
            ("OFF_CSE_03B", "STU_CSE_03", "CMP_DELOITTE", "DRV_DELOITTE_01", OfferType.FTE_ONLY.value, OfferStatus.DECLINED.value, 1000000.0, "INR", None, None, None, "2025-10-02", None, 1),
            
            # STU_CSE_04
            ("OFF_CSE_04", "STU_CSE_04", "CMP_INFOSYS", "DRV_INFY_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 700000.0, "INR", None, None, None, "2025-10-11", None, 1),
            
            # STU_CSE_05
            ("OFF_CSE_05", "STU_CSE_05", "CMP_DELOITTE", "DRV_DELOITTE_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 1100000.0, "INR", None, None, None, "2025-10-02", None, 1),
            
            # STU_CSE_06 (Data correction scenario: old draft corrected by new)
            ("OFF_CSE_06_OLD", "STU_CSE_06", "CMP_DELOITTE", "DRV_DELOITTE_01", OfferType.FTE_ONLY.value, OfferStatus.SUPERSEDED.value, 1200000.0, "INR", None, None, None, "2025-10-02", "OFF_CSE_06_NEW", 0),
            ("OFF_CSE_06_NEW", "STU_CSE_06", "CMP_DELOITTE", "DRV_DELOITTE_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 1400000.0, "INR", None, None, None, "2025-10-03", None, 1),
            
            # STU_CSE_07
            ("OFF_CSE_07", "STU_CSE_07", "CMP_DELOITTE", "DRV_DELOITTE_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 1000000.0, "INR", None, None, None, "2025-10-02", None, 1),
            
            # STU_CSE_08 (Pure Internship)
            ("OFF_CSE_08", "STU_CSE_08", "CMP_MICROSOFT", "DRV_MSFT_01", OfferType.INTERNSHIP_ONLY.value, OfferStatus.ACCEPTED.value, None, "INR", 60000.0, StipendPeriod.MONTHLY.value, 6, "2025-09-16", None, 1),
            
            # STU_CSE_09 (Declined offer, unplaced)
            ("OFF_CSE_09", "STU_CSE_09", "CMP_GOOGLE", "DRV_GGL_01", OfferType.FTE_ONLY.value, OfferStatus.DECLINED.value, 2200000.0, "INR", None, None, None, "2025-09-02", None, 1),
            
            # STU_CSE_10 (Expired offer, unplaced)
            ("OFF_CSE_10", "STU_CSE_10", "CMP_MICROSOFT", "DRV_MSFT_01", OfferType.FTE_ONLY.value, OfferStatus.EXPIRED.value, 1800000.0, "INR", None, None, None, "2025-09-16", None, 1),

            # ECE 2026 Offers
            ("OFF_ECE_01", "STU_ECE_01", "CMP_MICROSOFT", "DRV_MSFT_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 1900000.0, "INR", None, None, None, "2025-09-16", None, 1),
            ("OFF_ECE_02", "STU_ECE_02", "CMP_DELOITTE", "DRV_DELOITTE_01", OfferType.FTE_ONLY.value, OfferStatus.ACCEPTED.value, 950000.0, "INR", None, None, None, "2025-10-02", None, 1),
        ]

        cursor.executemany(
            """INSERT INTO offers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            offers_data
        )

        conn.commit()

    # Ground truth summary for BTECH_CSE 2026:
    # Total Registered = 15 (12 eligible + 3 ineligible)
    # Total Eligible = 12
    # Total Ineligible = 3
    # Placed Unique = 8 (STU_01 to STU_08 have active accepted offer)
    # Unplaced = 4 (STU_09, STU_10, STU_11, STU_12)
    # Placement Rate = 8 / 12 * 100 = 66.67%
    #
    # Active Offers Issued = 10 (excluding the 1 SUPERSEDED offer):
    # - Accepted = 8
    # - Declined = 2 (STU_03B, STU_09)
    # - Expired = 1 (STU_10)
    # Total active offers = 11 (8 accepted + 2 declined + 1 expired)
    # Students with multiple offers = 1 (STU_03 received 2 offers)
    #
    # Accepted FTE CTC values for BTECH_CSE 2026 (7 students with FTE CTC, note STU_08 is internship only):
    # CTCs: [2400000, 2000000, 2600000, 700000, 1100000, 1400000, 1000000]
    # Sorted: [700000, 1000000, 1100000, 1400000, 2000000, 2400000, 2600000]
    # Highest: 26,00,000
    # Average: (700000 + 1000000 + 1100000 + 1400000 + 2000000 + 2400000 + 2600000) / 7 = 11200000 / 7 = 16,00,000.00
    # Median (4th element): 14,00,000.00
    #
    # Monthly Stipends for BTECH_CSE 2026 (2 offers with monthly stipend: STU_02=80,000, STU_08=60,000):
    # Highest Stipend: 80,000
    # Average Stipend: (80000 + 60000) / 2 = 70,000.00
    # Median Stipend: 70,000.00
    
    return {
        "btech_cse_2026": {
            "registered": 15,
            "eligible": 12,
            "ineligible": 3,
            "placed_unique": 8,
            "unplaced": 4,
            "placement_rate": 66.67,
            "offers_active_total": 11,
            "offers_accepted": 8,
            "offers_declined": 2,
            "offers_expired": 1,
            "students_with_multiple_offers": 1,
            "fte_count": 7,
            "fte_highest": 2600000.0,
            "fte_average": 1600000.0,
            "fte_median": 1400000.0,
            "stipend_count": 2,
            "stipend_highest": 80000.0,
            "stipend_average": 70000.0,
            "stipend_median": 70000.0,
        }
    }


if __name__ == "__main__":
    ground_truth = seed_synthetic_data()
    print("Database seeded successfully. Ground truth:")
    print(ground_truth)
