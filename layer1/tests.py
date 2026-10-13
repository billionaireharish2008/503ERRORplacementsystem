"""Layer 1 completion-gate tests. Run:  python manage.py test"""
from datetime import date, timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from .models import AuditEvent, Batch, Company, Offer, OfferStatusHistory, Programme, Student


class Base(TestCase):
    def setUp(self):
        self.prog = Programme.objects.create(code="MTECH-CS", name="M.Tech. CS")
        self.other = Programme.objects.create(code="MSC-CS", name="M.Sc. CS")
        self.batch = Batch.objects.create(programme=self.prog, label="2025-27")
        self.company = Company.objects.create(name="TestCorp", category="B")
        self.user = get_user_model().objects.create_user("officer", password="Tmp#12345")

    def student(self, pid="NFSU-0001", **kw):
        data = dict(placement_id=pid, full_name="Test Student", mobile="9876543210",
                    email="t@example.com", programme=self.prog, batch=self.batch)
        data.update(kw)
        return Student.objects.create(**data)

    def offer(self, s, **kw):
        data = dict(student=s, company=self.company, offer_type="F", ctc_lpa=Decimal("7.5"),
                    offer_date=date.today() - timedelta(days=1))
        data.update(kw)
        return Offer.objects.create(**data)


class StudentTests(Base):
    def test_duplicate_placement_id_rejected(self):
        self.student()
        with self.assertRaises(ValidationError):
            self.student(pid="nfsu-0001")          # also normalised to upper-case

    def test_batch_must_match_programme(self):
        with self.assertRaises(ValidationError):
            self.student(programme=self.other)

    def test_bad_mobile_and_id_rejected(self):
        with self.assertRaises(ValidationError):
            self.student(mobile="12345")
        with self.assertRaises(ValidationError):
            self.student(pid="'; DROP TABLE--")

    def test_student_cannot_be_deleted_only_archived(self):
        s = self.student()
        with self.assertRaises(RuntimeError):
            s.delete()
        s.archive()
        self.assertEqual(Student.active.count(), 0)
        self.assertEqual(Student.objects.count(), 1)


class OfferTests(Base):
    def test_internship_cannot_carry_ctc(self):
        with self.assertRaises(ValidationError):
            self.offer(self.student(), offer_type="I", internship_stipend=Decimal("20000"),
                       stipend_period="MONTHLY", ctc_lpa=Decimal("5"))

    def test_fte_requires_ctc(self):
        with self.assertRaises(ValidationError):
            self.offer(self.student(), ctc_lpa=None)

    def test_stipend_requires_period(self):
        with self.assertRaises(ValidationError):
            self.offer(self.student(), offer_type="I", ctc_lpa=None, internship_stipend=Decimal("1000"))

    def test_future_offer_date_rejected(self):
        with self.assertRaises(ValidationError):
            self.offer(self.student(), offer_date=date.today() + timedelta(days=5))

    def test_duplicate_offer_event_rejected(self):
        s = self.student()
        self.offer(s)
        with self.assertRaises(ValidationError):
            self.offer(s)

    def test_student_with_offers_cannot_be_removed_and_history_kept(self):
        s = self.student()
        self.offer(s)
        self.offer(s, offer_type="I", ctc_lpa=None, internship_stipend=Decimal("15000"),
                   stipend_period="MONTHLY", offer_date=date.today() - timedelta(days=2))
        self.assertEqual(s.offers.count(), 2)      # two offers, nothing overwritten

    def test_status_change_is_logged_and_validated(self):
        o = self.offer(self.student())
        o.change_status("acceptance_status", "ACCEPTED", self.user, "Confirmed by email")
        self.assertEqual(OfferStatusHistory.objects.filter(offer=o).count(), 1)
        self.assertTrue(AuditEvent.objects.filter(action="offer.acceptance_status.change").exists())
        with self.assertRaises(ValidationError):   # terminal state
            o.change_status("acceptance_status", "DECLINED", self.user)
        with self.assertRaises(ValidationError):   # protected field not in allow-list
            o.change_status("ctc_lpa", "99", self.user)

    def test_audit_events_are_append_only(self):
        e = AuditEvent.record(self.user, "x", self.company)
        with self.assertRaises(RuntimeError):
            e.save()
        with self.assertRaises(RuntimeError):
            e.delete()
