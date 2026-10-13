"""Read-only audit viewer. Access needs the audit_ops.view_auditevent permission, and every view is itself audited."""
from django.contrib import admin

from .events import Action
from .models import AuditEvent
from .services import record_event


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("seq", "timestamp", "actor_id", "action", "target_type", "target_id", "outcome", "request_id")
    list_filter = ("action", "outcome", "target_type")
    search_fields = ("actor_id", "target_id", "request_id")
    date_hierarchy = "timestamp"
    actions = None
    list_per_page = 50

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]

    def changelist_view(self, request, extra_context=None):
        if self.has_view_permission(request):
            record_event(action=Action.AUDIT_VIEW, target_type="audit_log", target_id="list", request=request,
                         metadata={"filters": sorted(request.GET.keys())})
        return super().changelist_view(request, extra_context)

    def change_view(self, request, object_id, form_url="", extra_context=None):
        if self.has_view_permission(request):
            record_event(action=Action.AUDIT_VIEW, target_type="audit_event", target_id=object_id, request=request)
        return super().change_view(request, object_id, form_url, extra_context)
