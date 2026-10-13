"""Append-only audit table. Needs Django. Run `makemigrations audit_ops`, review, then migrate.

App-level guards below stop accidental edits. They do NOT stop someone with database access:
apply sql/postgres_append_only.sql (REVOKE UPDATE/DELETE + trigger) for the real control.
"""
import uuid

from django.db import models

from .events import PAYLOAD_FIELDS, payload_from_row


class _AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise PermissionError("AuditEvent is append-only")

    def delete(self):
        raise PermissionError("AuditEvent is append-only")

    def bulk_update(self, *args, **kwargs):
        raise PermissionError("AuditEvent is append-only")

    def update_or_create(self, *args, **kwargs):
        raise PermissionError("AuditEvent is append-only")


class AuditEvent(models.Model):
    seq = models.BigAutoField(primary_key=True)
    event_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    timestamp = models.DateTimeField(db_index=True)
    # Plain strings, not FKs: deleting a user must never cascade into (or be blocked by) the audit trail.
    actor_id = models.CharField(max_length=128, db_index=True)
    action = models.CharField(max_length=40, db_index=True)
    target_type = models.CharField(max_length=64)
    target_id = models.CharField(max_length=128)
    outcome = models.CharField(max_length=10)
    request_id = models.CharField(max_length=64, db_index=True)
    source_ip = models.CharField(max_length=45, blank=True, default="")
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    metadata = models.JSONField(default=dict)
    prev_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64, unique=True)

    objects = _AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["seq"]
        default_permissions = ("view",)                       # no add/change/delete permissions exist
        permissions = [("export_auditevent", "Can export audit events")]
        indexes = [models.Index(fields=["target_type", "target_id"])]

    def payload(self) -> dict:
        return payload_from_row({f: getattr(self, f) for f in PAYLOAD_FIELDS})

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise PermissionError("AuditEvent is append-only")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("AuditEvent is append-only")

    def __str__(self):
        return f"{self.seq} {self.action} {self.outcome}"
