"""
Security enforcement, RBAC, scope authorization, PII redaction,
and CSV / Formula Injection defense.
"""

from __future__ import annotations
import re
from typing import Optional, List, Dict, Any, Tuple
from models import UserRole, UserContext


class SecurityViolationError(PermissionError):
    """Raised when an operation violates security, tenancy, or scope constraints."""
    pass


class RolePermissionManager:
    """Configures default contexts and permission rules for different user roles."""

    @staticmethod
    def create_context(
        user_id: str,
        role: UserRole,
        assigned_programmes: Optional[List[str]] = None,
        assigned_batches: Optional[List[int]] = None,
        company_id: Optional[str] = None,
        explicit_pii_grant: bool = False,
    ) -> UserContext:
        """
        Creates an immutable, strictly validated UserContext with least-privilege defaults.
        """
        if role == UserRole.ADMIN:
            return UserContext(
                user_id=user_id,
                role=role,
                allowed_programmes=None,  # Unrestricted
                allowed_batches=None,     # Unrestricted
                company_id=None,
                can_view_pii=explicit_pii_grant,
                can_view_policy_reviews=True,
                can_view_future_drives=True,
                can_view_joining_updates=True,
                can_export=True,
            )

        elif role == UserRole.PLACEMENT_OFFICER:
            return UserContext(
                user_id=user_id,
                role=role,
                allowed_programmes=None,  # Unrestricted across university
                allowed_batches=None,
                company_id=None,
                can_view_pii=explicit_pii_grant,
                can_view_policy_reviews=True,
                can_view_future_drives=True,
                can_view_joining_updates=True,
                can_export=True,
            )

        elif role == UserRole.DEPARTMENT_COORDINATOR:
            if not assigned_programmes:
                raise SecurityViolationError("Department Coordinator must have assigned programmes.")
            return UserContext(
                user_id=user_id,
                role=role,
                allowed_programmes=assigned_programmes,
                allowed_batches=assigned_batches,
                company_id=None,
                can_view_pii=explicit_pii_grant,
                can_view_policy_reviews=False, # Restricted to Placement Cell Leadership
                can_view_future_drives=True,   # Within department scope
                can_view_joining_updates=True, # Within department scope
                can_export=True,
            )

        elif role == UserRole.STUDENT_REPRESENTATIVE:
            if not assigned_programmes or not assigned_batches:
                raise SecurityViolationError("Student Representative must have assigned programme and batch.")
            return UserContext(
                user_id=user_id,
                role=role,
                allowed_programmes=assigned_programmes,
                allowed_batches=assigned_batches,
                company_id=None,
                can_view_pii=False,            # Strictly forbidden
                can_view_policy_reviews=False, # Strictly forbidden
                can_view_future_drives=False,
                can_view_joining_updates=False,
                can_export=False,              # No raw exports permitted
            )

        elif role == UserRole.COMPANY_RECRUITER:
            if not company_id:
                raise SecurityViolationError("Company Recruiter must have an associated company_id.")
            return UserContext(
                user_id=user_id,
                role=role,
                allowed_programmes=None,
                allowed_batches=None,
                company_id=company_id,
                can_view_pii=False,            # No general student PII
                can_view_policy_reviews=False, # Strictly forbidden
                can_view_future_drives=False,
                can_view_joining_updates=True, # Only for their company's hires
                can_export=True,               # Only for their own offers
            )

        elif role == UserRole.AUDITOR:
            return UserContext(
                user_id=user_id,
                role=role,
                allowed_programmes=None,
                allowed_batches=None,
                company_id=None,
                can_view_pii=False,            # Aggregates only
                can_view_policy_reviews=True,  # Audit compliance view
                can_view_future_drives=False,
                can_view_joining_updates=True,
                can_export=True,
            )

        raise SecurityViolationError(f"Unsupported user role: {role}")


class ScopeEnforcer:
    """
    Validates and enforces that incoming query filters never cross the authorized boundary.
    Prevents data leaks across departments, batches, and competing companies.
    """

    @staticmethod
    def enforce_scope(
        context: UserContext,
        requested_programme: Optional[str],
        requested_batch: Optional[int],
        requested_company: Optional[str]
    ) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """
        Validates request against user's permitted scope.
        Returns the sanitized effective (programme, batch, company) filters.
        Raises SecurityViolationError if a prohibited boundary is queried.
        """
        # 1. Company Scope Check
        effective_company = requested_company
        if context.role == UserRole.COMPANY_RECRUITER:
            if requested_company and requested_company != context.company_id:
                raise SecurityViolationError(
                    f"Access Denied: Recruiter from {context.company_id} cannot query company {requested_company}."
                )
            effective_company = context.company_id  # Force recruiter's own company

        # 2. Programme Scope Check
        effective_programme = requested_programme
        if context.allowed_programmes is not None:
            if requested_programme:
                if requested_programme not in context.allowed_programmes:
                    raise SecurityViolationError(
                        f"Access Denied: User role {context.role.value} has scope {context.allowed_programmes}, "
                        f"cannot access programme {requested_programme}."
                    )
            else:
                # If no specific programme requested, restrict query to the primary authorized programme
                # or require the query to use the allowed subset
                effective_programme = context.allowed_programmes[0]

        # 3. Batch Scope Check
        effective_batch = requested_batch
        if context.allowed_batches is not None:
            if requested_batch:
                if requested_batch not in context.allowed_batches:
                    raise SecurityViolationError(
                        f"Access Denied: User role {context.role.value} has batch scope {context.allowed_batches}, "
                        f"cannot access batch {requested_batch}."
                    )
            else:
                effective_batch = context.allowed_batches[0]

        return effective_programme, effective_batch, effective_company


class PIISanitizer:
    """Protects Personally Identifiable Information (phone, email) from exposure."""

    @staticmethod
    def mask_email(email: Optional[str]) -> str:
        if not email:
            return ""
        parts = email.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[:2] + "****" if len(name) > 2 else "****"
            return f"{masked_name}@{domain}"
        return "****@****"

    @staticmethod
    def mask_phone(phone: Optional[str]) -> str:
        if not phone:
            return ""
        if len(phone) >= 6:
            return phone[:3] + "******" + phone[-2:]
        return "**********"

    @classmethod
    def sanitize_student_record(cls, record: Dict[str, Any], can_view_pii: bool) -> Dict[str, Any]:
        """Returns a copy of the record with PII redacted if not authorized."""
        sanitized = dict(record)
        if not can_view_pii:
            if "email" in sanitized:
                sanitized["email"] = "[REDACTED]"
            if "phone" in sanitized:
                sanitized["phone"] = "[REDACTED]"
        return sanitized


class FormulaInjectionSanitizer:
    """
    Prevents CSV / Excel Formula Injection (CWE-1236).
    Neutralizes formulas starting with '=', '+', '-', '@', '\t', '\r', or '%'
    by prepending a safe single quote apostrophe prefix.
    """

    DANGEROUS_PREFIXES = ('=', '+', '-', '@', '\t', '\r', '%')

    @classmethod
    def sanitize_cell(cls, value: Any) -> Any:
        if value is None:
            return ""
        
        # If numeric or boolean, it cannot be a formula injection payload
        if isinstance(value, (int, float, bool)):
            return value

        str_val = str(value)
        # Check if the string begins with any formula trigger character
        if str_val.startswith(cls.DANGEROUS_PREFIXES):
            # Prepend single quote apostrophe to force spreadsheet engines to treat as pure string
            return f"'{str_val}"

        return str_val

    @classmethod
    def sanitize_row(cls, row: List[Any]) -> List[Any]:
        return [cls.sanitize_cell(item) for item in row]
