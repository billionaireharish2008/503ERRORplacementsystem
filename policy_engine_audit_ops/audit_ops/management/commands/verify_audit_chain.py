"""python manage.py verify_audit_chain  -- run daily (cron/systemd timer) and alert on non-zero exit.

Prints the head hash and row count: copy those to storage the app server cannot write
(e.g. the incident mailbox or a separate log host). That anchor is what exposes truncation of the newest rows.
"""
from django.core.management.base import BaseCommand, CommandError

from audit_ops.events import Action, Outcome
from audit_ops.services import record_event, verify_db_chain


class Command(BaseCommand):
    help = "Verify the audit hash chain end to end."

    def handle(self, *args, **opts):
        result = verify_db_chain()
        record_event(action=Action.AUDIT_VERIFY, target_type="audit_log", target_id="chain",
                     outcome=Outcome.SUCCESS if result.ok else Outcome.FAILURE, actor="system",
                     metadata={"checked": result.checked, "head_hash": result.head_hash,
                               "first_bad_seq": result.first_bad_seq, "reason": result.reason})
        self.stdout.write(f"checked={result.checked} head={result.head_hash}")
        if not result.ok:
            raise CommandError(f"AUDIT CHAIN BROKEN at seq {result.first_bad_seq}: {result.reason}")
        self.stdout.write(self.style.SUCCESS("audit chain intact"))
