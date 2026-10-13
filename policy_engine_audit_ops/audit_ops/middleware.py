"""Sets request/correlation ID, actor and source IP for logs and audit events. Needs Django."""
from django.conf import settings

from .context import (actor_id_var, client_ip, new_request_id, request_id_var, source_ip_var,
                      valid_request_id)


class RequestContextMiddleware:
    """Place AFTER AuthenticationMiddleware in MIDDLEWARE."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        rid = request.META.get("HTTP_X_REQUEST_ID", "")
        if not valid_request_id(rid):
            rid = new_request_id()
        request.request_id = rid
        tokens = (request_id_var.set(rid),
                  source_ip_var.set(client_ip(request.META, getattr(settings, "AUDIT_TRUSTED_PROXY_COUNT", 0))),
                  actor_id_var.set("-"))
        try:
            response = self.get_response(request)
        finally:
            request_id_var.reset(tokens[0])
            source_ip_var.reset(tokens[1])
            actor_id_var.reset(tokens[2])
        response["X-Request-ID"] = rid
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            actor_id_var.set(str(user.pk))
        return None
