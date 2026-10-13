"""Layer 1 - database models for the NFSU Placement System.

Design rules (from the plan):
  * Placement ID is unique; relationships use PROTECT so history cannot vanish.
  * Offers are separate rows (history is kept); students are archived, never deleted.
  * Internship stipend and annual FTE CTC are separate columns.
  * Database CheckConstraints back up the Python validation.
"""
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone

placement_id_validator = RegexValidator(
    r"^[A-Z0-9-]{4,20}$", "Use 4-20 uppercase letters, digits or hyphens."
)
mobile_validator = RegexValidator(r"^[6-9]\d{9}$", "Enter a valid 10-digit mobile number.")


class Programme(models.Model):
    code = models.CharField(max_length=20, unique=True)      # e.g. MTECH-CS
    name = models.CharField(max_length=120)

    def __str__(self):
        return self.code


class Batch(models.Model):
    programme = models.ForeignKey(Programme, on_delete=models.PROTECT, related_name="batches")
    label = models.CharField(max_length=20)                   # e.g. 2025-27

    class Meta:
        verbose_name_plural = "batches"
        constraints = [
            models.UniqueConstraint(fields=["programme", "label"], name="uniq_batch_per_programme")
        ]

    def __str__(self):
        return f"{self.programme.code} {self.label}"


class ActiveStudentManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_archived=False)


class Student(models.Model):
    class Registration(models.TextChoices):
        REGISTERED = "REGISTERED", "Registered"
        DEREGISTERED = "DEREGISTERED", "Deregistered"
        NOT_REGISTERED = "NOT_REGISTERED", "Not registered"

    class Eligibility(models.TextChoices):
        ELIGIBLE = "ELIGIBLE", "Eligible"
        INELIGIBLE = "INELIGIBLE", "Ineligible"
        PENDING = "PENDING", "Pending verification"

    class PlacementStatus(models.TextChoices):  # summary only; real facts live in Offer rows
        UNPLACED = "UNPLACED", "Unplaced"
        INTERNSHIP_ONLY = "INTERNSHIP_ONLY", "Internship only"
        FTE_ONLY = "FTE_ONLY", "FTE only"
        INTERNSHIP_FTE = "INTERNSHIP_FTE", "Internship + PPO/FTE"

    placement_id = models.CharField(max_length=20, unique=True, validators=[placement_id_validator])
    full_name = models.CharField(max_length=120)
    mobile = models.CharField(max_length=10, validators=[mobile_validator])   # restricted field
    email = models.EmailField()
    programme = models.ForeignKey(Programme, on_delete=models.PROTECT, related_name="students")
    batch = models.ForeignKey(Batch, on_delete=models.PROTECT, related_name="students")
    registration_status = models.CharField(
        max_length=20, choices=Registration.choices, default=Registration.NOT_REGISTERED)
    eligibility_status = models.CharField(
        max_length=20, choices=Eligibility.choices, default=Eligibility.PENDING)
    placement_status = models.CharField(
        max_length=20, choices=PlacementStatus.choices, default=PlacementStatus.UNPLACED)
    remarks = models.TextField(blank=True)

    is_archived = models.BooleanField(default=False)
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = models.Manager()        # everything (admins)
    active = ActiveStudentManager()   # normal day-to-day queries

    class Meta:
        ordering = ["placement_id"]
        indexes = [models.Index(fields=["programme", "batch"])]

    def __str__(self):
        return f"{self.placement_id} - {self.full_name}"

    def clean(self):
        if self.batch_id and self.programme_id and self.batch.programme_id != self.programme_id:
            raise ValidationError("Batch does not belong to the selected programme.")

    def save(self, *args, **kwargs):
        self.placement_id = (self.placement_id or "").strip().upper()
        self.full_clean()             # runs validators, unique checks and CheckConstraints
        super().save(*args, **kwargs)

    def archive(self):
        self.is_archived = True
        self.archived_at = timezone.now()
        self.save()

    def delete(self, *args, **kwargs):
        raise RuntimeError("Students are archived, never deleted. Use archive().")


class Company(models.Model):
    class Category(models.TextChoices):
        A_PLUS = "A+", "A+"
        A = "A", "A"
        B = "B", "B"
        C = "C", "C"

    name = models.CharField(max_length=150, unique=True)
    category = models.CharField(max_length=2, choices=Category.choices)

    class Meta:
        verbose_name_plural = "companies"

    def __str__(self):
        return f"{self.name} ({self.category})"


class Offer(models.Model):
    class OfferType(models.TextChoices):
        I = "I", "Internship only"
        F = "F", "FTE only"
        IF = "I+F", "Internship + PPO/FTE"

    class StipendPeriod(models.TextChoices):
        MONTHLY = "MONTHLY", "Per month"
        TOTAL = "TOTAL", "Total for internship"

    class PPO(models.TextChoices):
        NA = "NA", "Not applicable"
        PENDING = "PENDING", "Pending"
        OFFERED = "OFFERED", "Offered"
        ACCEPTED = "ACCEPTED", "Accepted"
        DECLINED = "DECLINED", "Declined"

    class Acceptance(models.TextChoices):
        PENDING = "PENDING", "Pending"
        ACCEPTED = "ACCEPTED", "Accepted"
        DECLINED = "DECLINED", "Declined"
        EXPIRED = "EXPIRED", "Expired"

    class Joining(models.TextChoices):
        PENDING = "PENDING", "Pending"
        JOINED = "JOINED", "Joined"
        NOT_JOINED = "NOT_JOINED", "Not joined"

    student = models.ForeignKey(Student, on_delete=models.PROTECT, related_name="offers")
    company = models.ForeignKey(Company, on_delete=models.PROTECT, related_name="offers")
    offer_type = models.CharField(max_length=3, choices=OfferType.choices)
    # Kept in SEPARATE columns on purpose: never add these two together.
    internship_stipend = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    stipend_period = models.CharField(max_length=10, choices=StipendPeriod.choices, blank=True)
    ctc_lpa = models.DecimalField("annual FTE CTC (LPA)", max_digits=6, decimal_places=2,
                                  null=True, blank=True)
    ppo_status = models.CharField(max_length=10, choices=PPO.choices, default=PPO.NA)
    acceptance_status = models.CharField(
        max_length=10, choices=Acceptance.choices, default=Acceptance.PENDING)
    joining_status = models.CharField(max_length=10, choices=Joining.choices, default=Joining.PENDING)
    offer_date = models.DateField()
    remarks = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-offer_date"]
        constraints = [
            # I needs stipend only, F needs CTC only, I+F needs both
            models.CheckConstraint(name="offer_fields_match_type", condition=(
                Q(offer_type="I", internship_stipend__isnull=False, ctc_lpa__isnull=True)
                | Q(offer_type="F", ctc_lpa__isnull=False, internship_stipend__isnull=True)
                | Q(offer_type="I+F", ctc_lpa__isnull=False, internship_stipend__isnull=False)
            )),
            models.CheckConstraint(name="offer_ctc_positive",
                                   condition=Q(ctc_lpa__isnull=True) | Q(ctc_lpa__gt=0)),
            models.CheckConstraint(name="offer_stipend_non_negative",
                                   condition=Q(internship_stipend__isnull=True) | Q(internship_stipend__gte=0)),
            models.CheckConstraint(name="offer_stipend_needs_period",
                                   condition=Q(internship_stipend__isnull=True) | ~Q(stipend_period="")),
            # blocks accidental duplicate imports of the same offer
            models.UniqueConstraint(fields=["student", "company", "offer_type", "offer_date"],
                                    name="uniq_offer_event"),
        ]

    def __str__(self):
        return f"{self.student.placement_id} / {self.company.name} / {self.offer_type}"

    def clean(self):
        if self.offer_date and self.offer_date > timezone.localdate():
            raise ValidationError({"offer_date": "Offer date cannot be in the future."})
        if self.student_id and self.student.is_archived:
            raise ValidationError("Cannot add offers to an archived student.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("Offers are never deleted; change the status instead.")

    # Acceptance may only move out of PENDING; the history table keeps every change.
    ACCEPTANCE_FLOW = {"PENDING": {"ACCEPTED", "DECLINED", "EXPIRED"},
                       "ACCEPTED": set(), "DECLINED": set(), "EXPIRED": set()}
    CHANGEABLE = {"acceptance_status", "joining_status", "ppo_status"}   # allow-list

    def change_status(self, field, new_value, user, reason=""):
        if field not in self.CHANGEABLE:
            raise ValidationError("This field cannot be changed here.")
        old_value = getattr(self, field)
        if old_value == new_value:
            return
        if field == "acceptance_status" and new_value not in self.ACCEPTANCE_FLOW.get(old_value, set()):
            raise ValidationError(f"Invalid acceptance change: {old_value} -> {new_value}.")
        with transaction.atomic():
            setattr(self, field, new_value)
            self.save()
            OfferStatusHistory.objects.create(offer=self, field_name=field, old_value=old_value,
                                              new_value=new_value, changed_by=user, reason=reason)
            AuditEvent.record(user, f"offer.{field}.change", self,
                              before={field: old_value}, after={field: new_value})


class OfferStatusHistory(models.Model):
    offer = models.ForeignKey(Offer, on_delete=models.PROTECT, related_name="history")
    field_name = models.CharField(max_length=30)
    old_value = models.CharField(max_length=20)
    new_value = models.CharField(max_length=20)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    reason = models.CharField(max_length=255, blank=True)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-changed_at"]


class AuditEvent(models.Model):
    """Append-only baseline (Layer 5 adds hash chaining / restricted access)."""
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                              on_delete=models.SET_NULL)
    action = models.CharField(max_length=60)
    target_type = models.CharField(max_length=40)
    target_id = models.CharField(max_length=40)
    outcome = models.CharField(max_length=10, default="SUCCESS")
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    @classmethod
    def record(cls, actor, action, target, before=None, after=None, outcome="SUCCESS"):
        # Keep PII out of before/after: pass only the fields that changed.
        return cls.objects.create(
            actor=actor if getattr(actor, "pk", None) else None, action=action,
            target_type=target.__class__.__name__, target_id=str(target.pk),
            outcome=outcome, before=before, after=after)

    def save(self, *args, **kwargs):
        if self.pk:
            raise RuntimeError("Audit events cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError("Audit events cannot be deleted.")
