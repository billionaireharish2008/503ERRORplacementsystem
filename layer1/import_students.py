"""Controlled CSV import. All-or-nothing, row-level errors, no formulas.

  python manage.py import_students students.csv --dry-run
  python manage.py import_students students.csv
Columns: placement_id,full_name,mobile,email,programme_code,batch_label
"""
import csv
import os

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core.models import AuditEvent, Batch, Programme, Student

MAX_BYTES, MAX_ROWS = 1_000_000, 1000
COLUMNS = ["placement_id", "full_name", "mobile", "email", "programme_code", "batch_label"]


class Command(BaseCommand):
    help = "Import students from CSV (validated; nothing is saved if any row fails)."

    def add_arguments(self, parser):
        parser.add_argument("path")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, path, dry_run, **opts):
        if not path.lower().endswith(".csv") or os.path.getsize(path) > MAX_BYTES:
            raise CommandError("Only .csv files up to 1 MB are accepted.")
        errors, created = [], 0
        with open(path, newline="", encoding="utf-8-sig") as f, transaction.atomic():
            reader = csv.DictReader(f)
            if reader.fieldnames != COLUMNS:
                raise CommandError(f"Header must be exactly: {','.join(COLUMNS)}")
            for line, row in enumerate(reader, start=2):
                if line - 1 > MAX_ROWS:
                    raise CommandError("Too many rows.")
                try:
                    clean = {k: (row.get(k) or "").strip() for k in COLUMNS}
                    if any(v[:1] in ("=", "+", "@", "\t", "\r") for v in clean.values()):
                        raise ValidationError("Cell starts with a formula character.")
                    prog = Programme.objects.get(code=clean["programme_code"])
                    batch = Batch.objects.get(programme=prog, label=clean["batch_label"])
                    with transaction.atomic():      # savepoint per row
                        Student(placement_id=clean["placement_id"], full_name=clean["full_name"],
                                mobile=clean["mobile"], email=clean["email"],
                                programme=prog, batch=batch).save()
                    created += 1
                except (ValidationError, ObjectDoesNotExist) as e:
                    msg = "; ".join(e.messages) if hasattr(e, "messages") else "Unknown programme/batch"
                    errors.append(f"Line {line}: {msg}")      # generic text, no stack trace
            if errors or dry_run:
                transaction.set_rollback(True)
        if errors:
            for e in errors:
                self.stderr.write(e)
            raise CommandError(f"{len(errors)} row(s) failed; nothing was imported.")
        if dry_run:
            self.stdout.write(f"Dry run OK: {created} rows would be imported.")
        else:
            AuditEvent.objects.create(action="student.import", target_type="Student",
                                      target_id="bulk", after={"rows": created})
            self.stdout.write(self.style.SUCCESS(f"Imported {created} students."))
