"""Synthetic data only. Run:  python manage.py seed_demo"""
import random
from datetime import date, timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand
from django.db import transaction

from core.models import Batch, Company, Offer, Programme, Student

PROGRAMMES = [("MTECH-CS", "M.Tech. Computer Science"),
              ("MTECH-AIDS", "M.Tech. AI and Data Science"),
              ("BTMT-CS", "B.Tech.-M.Tech. CSE"),
              ("MSC-CS", "M.Sc. Computer Science"),
              ("MSC-DFIS", "M.Sc. Digital Forensics and Information Security")]
COMPANIES = [("Alpha Systems", "A+"), ("Beta Tech", "A"), ("Gamma Soft", "B"), ("Delta Labs", "C")]


class Command(BaseCommand):
    help = "Create synthetic programmes, companies, students and offers."

    @transaction.atomic
    def handle(self, *args, **opts):
        random.seed(42)
        batches = []
        for code, name in PROGRAMMES:
            p, _ = Programme.objects.get_or_create(code=code, defaults={"name": name})
            b, _ = Batch.objects.get_or_create(programme=p, label="2025-27")
            batches.append(b)
        companies = [Company.objects.get_or_create(name=n, defaults={"category": c})[0]
                     for n, c in COMPANIES]
        n = 0
        for i in range(1, 41):
            b = batches[i % len(batches)]
            s, created = Student.objects.get_or_create(
                placement_id=f"NFSU-{i:04d}",
                defaults=dict(full_name=f"Demo Student {i}", mobile=f"9{random.randint(10**8, 10**9 - 1)}",
                              email=f"student{i}@example.com", programme=b.programme, batch=b,
                              registration_status="REGISTERED", eligibility_status="ELIGIBLE"))
            if created and i % 4 == 0:               # some students get an FTE offer
                Offer.objects.create(student=s, company=random.choice(companies), offer_type="F",
                                     ctc_lpa=Decimal(random.choice(["4.5", "7.0", "12.0", "18.0"])),
                                     offer_date=date.today() - timedelta(days=random.randint(1, 30)))
            n += created
        self.stdout.write(self.style.SUCCESS(f"Seeded {n} new students."))
