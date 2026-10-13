"""
REST API layer and Request Handlers for Placement Statistics and Reports.
Provides HTTP/JSON interface with RBAC middleware, secure file downloads,
and direct testable dispatch without network dependencies.
"""

from __future__ import annotations
import json
import urllib.parse
from http import HTTPStatus
from typing import Dict, Any, Tuple, Optional

from models import UserContext, UserRole
from security import SecurityViolationError, RolePermissionManager
from service import PlacementAnalyticsService
from export_engine import SecureExportEngine


class PlacementApiController:
    """
    High-level API dispatcher and security gateway.
    Can be mounted into any web framework (FastAPI, Flask, Django, WSGI)
    or invoked directly for headless testing and CLI execution.
    """

    def __init__(self, service: PlacementAnalyticsService, export_engine: SecureExportEngine):
        self.service = service
        self.export_engine = export_engine

    def handle_request(
        self,
        endpoint: str,
        method: str,
        context: UserContext,
        params: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Dict[str, str], Any]:
        """
        Unified dispatch router.
        Returns: (status_code, headers, body)
        """
        params = params or {}
        programme_id = params.get("programme_id")
        batch_year = int(params["batch_year"]) if params.get("batch_year") else None
        company_id = params.get("company_id")

        try:
            # 1. Dashboard Metrics Endpoint
            if endpoint == "/api/v1/dashboard" and method == "GET":
                metrics = self.service.get_dashboard_metrics(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year,
                    company_id=company_id
                )
                return (
                    HTTPStatus.OK,
                    {"Content-Type": "application/json"},
                    metrics.to_dict()
                )

            # 2. Detailed Report Data Endpoint
            elif endpoint == "/api/v1/reports/detailed" and method == "GET":
                data = self.service.get_detailed_report_data(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year,
                    company_id=company_id
                )
                return (
                    HTTPStatus.OK,
                    {"Content-Type": "application/json"},
                    {"count": len(data), "records": data}
                )

            # 3. CSV Export Endpoint
            elif endpoint == "/api/v1/reports/export/csv" and method == "GET":
                include_pii = str(params.get("include_pii", "false")).lower() == "true"
                csv_data, checksum = self.export_engine.export_detailed_report_csv(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year,
                    company_id=company_id,
                    include_pii_override=include_pii
                )
                filename = f"placement_report_{programme_id or 'all'}_{batch_year or 'all'}.csv"
                headers = {
                    "Content-Type": "text/csv; charset=utf-8",
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Checksum-SHA256": checksum
                }
                return HTTPStatus.OK, headers, csv_data

            # 4. Excel XML Export Endpoint
            elif endpoint == "/api/v1/reports/export/excel" and method == "GET":
                include_pii = str(params.get("include_pii", "false")).lower() == "true"
                excel_data, checksum = self.export_engine.export_detailed_report_excel_xml(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year,
                    company_id=company_id,
                    include_pii_override=include_pii
                )
                filename = f"placement_report_{programme_id or 'all'}_{batch_year or 'all'}.xml"
                headers = {
                    "Content-Type": "application/vnd.ms-excel",
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Checksum-SHA256": checksum
                }
                return HTTPStatus.OK, headers, excel_data

            # 5. Restricted: Future Drive Candidates
            elif endpoint == "/api/v1/restricted/future-drives" and method == "GET":
                drive_id = params.get("drive_id")
                if not drive_id:
                    return HTTPStatus.BAD_REQUEST, {"Content-Type": "application/json"}, {"error": "Missing drive_id"}
                students = self.service.get_eligible_students_for_future_drives(
                    context=context, drive_id=drive_id
                )
                return HTTPStatus.OK, {"Content-Type": "application/json"}, {"drive_id": drive_id, "students": students}

            # 6. Restricted: Pending Acceptances
            elif endpoint == "/api/v1/restricted/pending-acceptances" and method == "GET":
                pending = self.service.get_pending_acceptances(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year
                )
                return HTTPStatus.OK, {"Content-Type": "application/json"}, {"pending_count": len(pending), "records": pending}

            # 7. Restricted: Joining Updates
            elif endpoint == "/api/v1/restricted/joining-updates" and method == "GET":
                joining = self.service.get_joining_updates(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year
                )
                return HTTPStatus.OK, {"Content-Type": "application/json"}, {"count": len(joining), "records": joining}

            # 8. Restricted: Cases Awaiting Policy Review
            elif endpoint == "/api/v1/restricted/policy-reviews" and method == "GET":
                cases = self.service.get_cases_awaiting_policy_review(
                    context=context,
                    programme_id=programme_id,
                    batch_year=batch_year
                )
                return HTTPStatus.OK, {"Content-Type": "application/json"}, {"count": len(cases), "cases": cases}

            else:
                return HTTPStatus.NOT_FOUND, {"Content-Type": "application/json"}, {"error": "Endpoint not found"}

        except SecurityViolationError as sve:
            return (
                HTTPStatus.FORBIDDEN,
                {"Content-Type": "application/json"},
                {"error": "Access Denied", "detail": str(sve)}
            )
        except ValueError as ve:
            return (
                HTTPStatus.BAD_REQUEST,
                {"Content-Type": "application/json"},
                {"error": "Bad Request", "detail": str(ve)}
            )
        except Exception as ex:
            return (
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"Content-Type": "application/json"},
                {"error": "Internal Server Error", "detail": str(ex)}
            )
