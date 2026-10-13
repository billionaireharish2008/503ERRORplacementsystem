"""Automatic audit events: logins, logouts, failed logins, privilege and password changes."""
import hashlib

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import m2m_changed, post_save, pre_save
from django.dispatch import receiver

from .events import Action, Outcome
from .services import record_event

User = get_user_model()
_PRIV_FIELDS = ("is_staff", "is_superuser", "is_active")


@receiver(user_logged_in)
def _login_ok(sender, request, user, **kw):
    record_event(action=Action.LOGIN_SUCCESS, target_type="user_account", target_id=user.pk,
                 actor=user, request=request, fail_closed=False)


@receiver(user_logged_out)
def _logout(sender, request, user, **kw):
    if user is not None:
        record_event(action=Action.LOGOUT, target_type="user_account", target_id=user.pk,
                     actor=user, request=request, fail_closed=False)


@receiver(user_login_failed)
def _login_failed(sender, credentials, request=None, **kw):
    # People sometimes type their password into the username box: store only a hash of what was typed,
    # and never look at credentials["password"].
    typed = str(credentials.get("username") or credentials.get("email") or "")
    digest = hashlib.sha256(typed.encode("utf-8")).hexdigest()[:16]
    record_event(action=Action.LOGIN_FAILURE, target_type="user_account", target_id=f"uh:{digest}",
                 outcome=Outcome.FAILURE, actor="anonymous", request=request, fail_closed=False)


@receiver(pre_save, sender=User)
def _remember_old_state(sender, instance, **kw):
    uf = kw.get("update_fields")
    if instance.pk is None or (uf and set(uf) <= {"last_login"}):
        instance._audit_old = None
        return
    instance._audit_old = User.objects.filter(pk=instance.pk).values(*_PRIV_FIELDS, "password").first()


@receiver(post_save, sender=User)
def _user_saved(sender, instance, created, **kw):
    if created:
        record_event(action=Action.RECORD_CREATE, target_type="user_account", target_id=instance.pk,
                     after={f: getattr(instance, f) for f in _PRIV_FIELDS})
        return
    old = getattr(instance, "_audit_old", None)
    if not old:
        return
    before = {f: old[f] for f in _PRIV_FIELDS if old[f] != getattr(instance, f)}
    if before:
        record_event(action=Action.PERMISSION_CHANGE, target_type="user_account", target_id=instance.pk,
                     before=before, after={f: getattr(instance, f) for f in before}, minimise=False)
    if old["password"] != instance.password:        # flag only: never store the hash
        record_event(action=Action.PASSWORD_CHANGE, target_type="user_account", target_id=instance.pk,
                     metadata={"password_changed": True})


def _m2m(kind):
    def handler(sender, instance, action, reverse, pk_set, **kw):
        if action in ("post_add", "post_remove", "post_clear"):
            record_event(action=Action.PERMISSION_CHANGE, target_type=kind, target_id=instance.pk,
                         metadata={"change": action, "reverse": reverse, "pk_set": sorted(pk_set or [])})
    return handler


m2m_changed.connect(_m2m("user_groups"), sender=User.groups.through, weak=False,
                    dispatch_uid="audit_user_groups")
m2m_changed.connect(_m2m("user_permissions"), sender=User.user_permissions.through, weak=False,
                    dispatch_uid="audit_user_perms")
m2m_changed.connect(_m2m("group_permissions"),
                    sender=User.groups.through._meta.get_field("group").related_model.permissions.through,
                    weak=False, dispatch_uid="audit_group_perms")
