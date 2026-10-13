"""Append-only decision history. Needs Django; the engine itself does not."""
from django.conf import settings
from django.db import models

from .types import Decision


class _AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise PermissionError("PolicyDecision is append-only")

    def delete(self):
        raise PermissionError("PolicyDecision is append-only")

    def bulk_update(self, *args, **kwargs):
        raise PermissionError("PolicyDecision is append-only")


class PolicyDecision(models.Model):
    placement_id = models.CharField(max_length=32, db_index=True)
    drive_id = models.CharField(max_length=64, db_index=True)
    action = models.CharField(max_length=32, default="DRIVE_APPLICATION")
    decision = models.CharField(max_length=6, choices=[(d.value, d.value) for d in Decision])
    policy_version = models.CharField(max_length=64)
    rule_ids = models.JSONField(default=list)
    reasons = models.JSONField(default=list)
    exceptions_applied = models.JSONField(default=list)
    facts_hash = models.CharField(max_length=64)
    evaluated_at = models.DateTimeField()
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
                                     related_name="+")

    objects = _AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["-evaluated_at"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise PermissionError("PolicyDecision is append-only")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("PolicyDecision is append-only")
