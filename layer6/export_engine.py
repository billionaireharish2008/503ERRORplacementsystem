"""
Export Engine: Secure CSV and Excel Export with Formula Injection defense,
PII redaction by default, RBAC enforcement, and audit logging.
"""

from __future__ import annotations
import csv
import io
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from database import get_write_connection
from models import UserContext, UserRole
from security import (
    SecurityViolationError, FormulaInjectionSanitizer, ScopeEnforcer
)
from service import PlacementAnalyticsService


class SecureExportEngine:
    """
    Handles permission-aware exports of placement statistics and detailed reports.
    Guarantees:
    1. CSV/Excel Formula Injection protection (CWE-1236).
    2. Zero PII leakage by default (Phone and Email excluded unless explicit privilege).
    3. Immutable audit logging of all generated exports.
    4. Strict RBAC scope enforcement matching dashboard analytics.
    """

    def __init__(self, analytics_service: PlacementAnalyticsService):
        self.analytics_service = analytics_service

    def _log_export_audit(
        self,
        context: UserContext,
        export_format: str,
        programme_filter: Optional[str],
        batch_filter: Optional[int],
        company_filter: Optional[str],
        row_count: int,
        pii_included: bool,
        file_bytes: bytes,
    ) -> str:
        """
        Records an immutable audit entry in the database.
        Returns the SHA-256 hash of the generated report.
        """
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Audit logging uses a dedicated write connection
        db_path = self.analytics_service.db_path
        conn = get_write_connection(db_path) if db_path else get_write_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO export_audit_log (
                        timestamp, user_id, role, export_format, 
                        programme_filter, batch_filter, company_filter, 
                        row_count, pii_included, sha256_checksum
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        timestamp,
                        context.user_id,
                        context.role.value,
                        export_format,
                        programme_filter,
                        str(batch_filter) if batch_filter else None,
                        company_filter,
                        row_count,
                        1 if pii_included else 0,
                        sha256_hash,
                    )
                )
        finally:
            conn.close()

        return sha256_hash

    def export_detailed_report_csv(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None,
        company_id: Optional[str] = None,
        include_pii_override: bool = False,
    ) -> Tuple[str, str]:
        """
        Generates a secure CSV report.
        Returns:
            Tuple[csv_content_string, sha256_checksum]
        """
        if not context.can_export:
            raise SecurityViolationError(
                f"Export Denied: Role {context.role.value} does not have export permissions."
            )

        eff_prog, eff_batch, eff_comp = ScopeEnforcer.enforce_scope(
            context, programme_id, batch_year, company_id
        )

        # Retrieve row data via analytics service
        records = self.analytics_service.get_detailed_report_data(
            context=context,
            programme_id=eff_prog,
            batch_year=eff_batch,
            company_id=eff_comp,
        )

        # PII exclusion check
        # Only include PII if user has permission AND explicitly requested it
        allow_pii = context.can_view_pii and include_pii_override

        # Define export columns (Phone and Email are omitted by default!)
        headers = [
            "Student ID",
            "Student Name",
            "Programme",
            "Batch Year",
            "CGPA",
            "Eligibility Status",
            "Eligibility Reason",
            "Company Name",
            "Offer Type",
            "Offer Status",
            "Annual FTE CTC (INR)",
            "Internship Stipend (INR)",
            "Stipend Period",
            "Joining Status"
        ]

        if allow_pii:
            headers.insert(2, "Phone")
            headers.insert(2, "Email")

        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(headers)

        sanitized_row_count = 0
        for r in records:
            row = [
                FormulaInjectionSanitizer.sanitize_cell(r.get("student_id")),
                FormulaInjectionSanitizer.sanitize_cell(r.get("name")),
                FormulaInjectionSanitizer.sanitize_cell(r.get("programme_id")),
                FormulaInjectionSanitizer.sanitize_cell(r.get("batch_year")),
                FormulaInjectionSanitizer.sanitize_cell(r.get("cgpa")),
                FormulaInjectionSanitizer.sanitize_cell("Eligible" if r.get("is_eligible") else "Ineligible"),
                FormulaInjectionSanitizer.sanitize_cell(r.get("eligibility_reason")),
                FormulaInjectionSanitizer.sanitize_cell(r.get("company_name") or "N/A"),
                FormulaInjectionSanitizer.sanitize_cell(r.get("offer_type") or "N/A"),
                FormulaInjectionSanitizer.sanitize_cell(r.get("offer_status") or "UNPLACED"),
                FormulaInjectionSanitizer.sanitize_cell(r.get("annual_fte_ctc") if r.get("annual_fte_ctc") is not None else ""),
                FormulaInjectionSanitizer.sanitize_cell(r.get("internship_stipend_amount") if r.get("internship_stipend_amount") is not None else ""),
                FormulaInjectionSanitizer.sanitize_cell(r.get("stipend_period") or ""),
                FormulaInjectionSanitizer.sanitize_cell(r.get("joining_status")),
            ]

            if allow_pii:
                row.insert(2, FormulaInjectionSanitizer.sanitize_cell(r.get("phone")))
                row.insert(2, FormulaInjectionSanitizer.sanitize_cell(r.get("email")))

            writer.writerow(row)
            sanitized_row_count += 1

        csv_content = output.getvalue()
        file_bytes = csv_content.encode("utf-8-sig")

        checksum = self._log_export_audit(
            context=context,
            export_format="CSV",
            programme_filter=eff_prog,
            batch_filter=eff_batch,
            company_filter=eff_comp,
            row_count=sanitized_row_count,
            pii_included=allow_pii,
            file_bytes=file_bytes,
        )

        return csv_content, checksum

    def export_detailed_report_excel_xml(
        self,
        context: UserContext,
        programme_id: Optional[str] = None,
        batch_year: Optional[int] = None,
        company_id: Optional[str] = None,
        include_pii_override: bool = False,
    ) -> Tuple[str, str]:
        """
        Generates an Excel XML Spreadsheet 2003 (.xml/.xls) file.
        Excel opens this format directly while supporting rich formatting and cell types.
        Formula injection is strictly sanitized in every XML node.
        """
        if not context.can_export:
            raise SecurityViolationError(
                f"Export Denied: Role {context.role.value} does not have export permissions."
            )

        eff_prog, eff_batch, eff_comp = ScopeEnforcer.enforce_scope(
            context, programme_id, batch_year, company_id
        )

        records = self.analytics_service.get_detailed_report_data(
            context=context,
            programme_id=eff_prog,
            batch_year=eff_batch,
            company_id=eff_comp,
        )

        allow_pii = context.can_view_pii and include_pii_override

        headers = [
            "Student ID", "Student Name", "Programme", "Batch Year", "CGPA",
            "Eligibility Status", "Eligibility Reason", "Company Name",
            "Offer Type", "Offer Status", "Annual FTE CTC (INR)",
            "Internship Stipend (INR)", "Stipend Period", "Joining Status"
        ]

        if allow_pii:
            headers.insert(2, "Phone")
            headers.insert(2, "Email")

        xml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<?mso-application progid="Excel.Sheet"?>',
            '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"',
            ' xmlns:o="urn:schemas-microsoft-com:office:office"',
            ' xmlns:x="urn:schemas-microsoft-com:office:excel"',
            ' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">',
            ' <Styles>',
            '  <Style ss:ID="Header">',
            '   <Font ss:Bold="1" ss:Color="#FFFFFF"/>',
            '   <Interior ss:Color="#1F4E78" ss:Pattern="Solid"/>',
            '  </Style>',
            '  <Style ss:ID="Currency">',
            '   <NumberFormat ss:Format="#,##0.00"/>',
            '  </Style>',
            ' </Styles>',
            ' <Worksheet ss:Name="Placement_Report">',
            '  <Table>',
        ]

        # Header Row
        xml_parts.append('   <Row ss:StyleID="Header">')
        for h in headers:
            xml_parts.append(f'    <Cell><Data ss:Type="String">{h}</Data></Cell>')
        xml_parts.append('   </Row>')

        # Data Rows
        for r in records:
            xml_parts.append('   <Row>')
            
            def add_cell(val: Any, is_num: bool = False):
                clean_val = FormulaInjectionSanitizer.sanitize_cell(val)
                # XML escape & < >
                clean_str = str(clean_val).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                if is_num and isinstance(val, (int, float)):
                    xml_parts.append(f'    <Cell ss:StyleID="Currency"><Data ss:Type="Number">{val}</Data></Cell>')
                else:
                    xml_parts.append(f'    <Cell><Data ss:Type="String">{clean_str}</Data></Cell>')

            add_cell(r.get("student_id"))
            add_cell(r.get("name"))
            if allow_pii:
                add_cell(r.get("email"))
                add_cell(r.get("phone"))
            add_cell(r.get("programme_id"))
            add_cell(r.get("batch_year"))
            add_cell(r.get("cgpa"), is_num=True)
            add_cell("Eligible" if r.get("is_eligible") else "Ineligible")
            add_cell(r.get("eligibility_reason"))
            add_cell(r.get("company_name") or "N/A")
            add_cell(r.get("offer_type") or "N/A")
            add_cell(r.get("offer_status") or "UNPLACED")
            add_cell(r.get("annual_fte_ctc") if r.get("annual_fte_ctc") is not None else "", is_num=True if r.get("annual_fte_ctc") is not None else False)
            add_cell(r.get("internship_stipend_amount") if r.get("internship_stipend_amount") is not None else "", is_num=True if r.get("internship_stipend_amount") is not None else False)
            add_cell(r.get("stipend_period") or "")
            add_cell(r.get("joining_status"))

            xml_parts.append('   </Row>')

        xml_parts.extend([
            '  </Table>',
            ' </Worksheet>',
            '</Workbook>'
        ])

        xml_content = "\n".join(xml_parts)
        file_bytes = xml_content.encode("utf-8")

        checksum = self._log_export_audit(
            context=context,
            export_format="EXCEL_XML",
            programme_filter=eff_prog,
            batch_filter=eff_batch,
            company_filter=eff_comp,
            row_count=len(records),
            pii_included=allow_pii,
            file_bytes=file_bytes,
        )

        return xml_content, checksum
