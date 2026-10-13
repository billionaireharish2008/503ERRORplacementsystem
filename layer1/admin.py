"""Quick, permission-controlled UI for student management (create/view/update/archive/search)."""
from django.contrib import admin
from .models import (AuditEvent, Batch, Company, Offer, OfferStatusHistory, Programme, Student)


class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False


@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ("placement_id", "full_name", "programme", "batch", "registration_status",
                    "eligibility_status", "placement_status", "is_archived")
    list_filter = ("programme", "batch", "registration_status", "eligibility_status",
                   "placement_status", "is_archived")
    search_fields = ("placement_id", "full_name", "email")
    readonly_fields = ("is_archived", "archived_at")
    actions = ["archive_selected"]

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        before = None
        if change:
            old = Student.objects.get(pk=obj.pk)
            before = {f: str(getattr(old, f)) for f in form.changed_data}
        super().save_model(request, obj, form, change)
        after = {f: str(getattr(obj, f)) for f in form.changed_data} if change else None
        AuditEvent.record(request.user, "student.update" if change else "student.create",
                          obj, before=before, after=after)

    @admin.action(description="Archive selected students")
    def archive_selected(self, request, queryset):
        for s in queryset.filter(is_archived=False):
            s.archive()
            AuditEvent.record(request.user, "student.archive", s)


@admin.register(Offer)
class OfferAdmin(admin.ModelAdmin):
    list_display = ("student", "company", "offer_type", "internship_stipend", "ctc_lpa",
                    "acceptance_status", "joining_status", "offer_date")
    list_filter = ("offer_type", "acceptance_status", "company__category")
    search_fields = ("student__placement_id", "company__name")
    def has_delete_permission(self, request, obj=None): return False


admin.site.register(Programme)
admin.site.register(Batch)
admin.site.register(Company)


@admin.register(OfferStatusHistory)
class HistoryAdmin(ReadOnlyAdmin):
    list_display = ("offer", "field_name", "old_value", "new_value", "changed_by", "changed_at")


@admin.register(AuditEvent)
class AuditAdmin(ReadOnlyAdmin):
    list_display = ("created_at", "actor", "action", "target_type", "target_id", "outcome")
    list_filter = ("action", "outcome")
