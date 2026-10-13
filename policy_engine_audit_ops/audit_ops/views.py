"""Permission-gated, self-audited CSV export of the audit trail."""
import csv

from django.conf import settings
from django.contrib.auth.decorators import login_required, permission_required
from django.http import HttpResponseBadRequest, StreamingHttpResponse
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET

from .events import Action
from .models import AuditEvent
from .sanitize import csv_safe
from .services import record_event

_COLUMNS = ("seq", "timestamp", "actor_id", "action", "target_type", "target_id", "outcome",
            "request_id", "source_ip", "hash")


class _Echo:
    def write(self, value):
        return value


@login_required
@permission_required("audit_ops.export_auditevent", raise_exception=True)
@require_GET
def export_audit_csv(request):
    qs = AuditEvent.objects.all()
    filters = {}
    if request.GET.get("action"):
        try:
            filters["action"] = Action(request.GET["action"]).value
        except ValueError:
            return HttpResponseBadRequest("unknown action")
    for param in ("actor_id", "target_id"):
        if request.GET.get(param):
            filters[param] = request.GET[param][:128]
    qs = qs.filter(**filters)
    for param, lookup in (("from", "timestamp__gte"), ("to", "timestamp__lt")):
        if request.GET.get(param):
            dt = parse_datetime(request.GET[param])
            if dt is None:
                return HttpResponseBadRequest(f"bad {param} timestamp")
            qs = qs.filter(**{lookup: dt})
            filters[param] = request.GET[param][:40]

    limit = getattr(settings, "AUDIT_EXPORT_MAX_ROWS", 50_000)
    rows = list(qs.order_by("seq").values_list(*_COLUMNS)[:limit])
    # Record the export BEFORE any data leaves the server; if this fails, nothing is exported.
    record_event(action=Action.AUDIT_EXPORT, target_type="audit_log", target_id="csv", request=request,
                 metadata={"filters": filters, "row_count": len(rows), "truncated_at_limit": len(rows) == limit})

    writer = csv.writer(_Echo())

    def stream():
        yield writer.writerow(_COLUMNS)
        for row in rows:
            yield writer.writerow([csv_safe(v) for v in row])

    resp = StreamingHttpResponse(stream(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="audit_export.csv"'
    resp["Cache-Control"] = "no-store"
    return resp
