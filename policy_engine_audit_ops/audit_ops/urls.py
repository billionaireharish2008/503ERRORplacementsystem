from django.urls import path

from . import views

app_name = "audit_ops"
urlpatterns = [path("export.csv", views.export_audit_csv, name="export_csv")]
