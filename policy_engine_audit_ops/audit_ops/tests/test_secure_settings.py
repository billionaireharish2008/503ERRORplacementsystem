import os
import tempfile
import unittest

from audit_ops.secure_settings import ConfigError, build_database_settings, build_security_settings

GOOD = {"NFSU_ENV": "production", "DJANGO_SECRET_KEY": "k" * 60, "AUDIT_HMAC_KEY": "h" * 40,
        "DJANGO_ALLOWED_HOSTS": "placement.example.edu"}


class SettingsTests(unittest.TestCase):
    def test_production_ok_and_hardened(self):
        s = build_security_settings(GOOD)
        self.assertFalse(s["DEBUG"])
        self.assertTrue(s["SESSION_COOKIE_SECURE"] and s["CSRF_COOKIE_SECURE"] and s["SECURE_SSL_REDIRECT"])

    def test_default_environment_is_production(self):
        with self.assertRaises(ConfigError):
            build_security_settings({})

    def test_missing_or_short_secrets_refuse_to_start(self):
        for drop in ("DJANGO_SECRET_KEY", "AUDIT_HMAC_KEY", "DJANGO_ALLOWED_HOSTS"):
            env = {k: v for k, v in GOOD.items() if k != drop}
            with self.assertRaises(ConfigError, msg=drop):
                build_security_settings(env)
        with self.assertRaises(ConfigError):
            build_security_settings({**GOOD, "DJANGO_SECRET_KEY": "short"})

    def test_debug_and_wildcard_rejected_in_production(self):
        with self.assertRaises(ConfigError):
            build_security_settings({**GOOD, "DJANGO_DEBUG": "true"})
        with self.assertRaises(ConfigError):
            build_security_settings({**GOOD, "DJANGO_ALLOWED_HOSTS": "*"})

    def test_secret_from_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("f" * 70 + "\n")
        try:
            env = {k: v for k, v in GOOD.items() if k != "DJANGO_SECRET_KEY"}
            env["DJANGO_SECRET_KEY_FILE"] = fh.name
            self.assertEqual(build_security_settings(env)["SECRET_KEY"], "f" * 70)
        finally:
            os.remove(fh.name)

    def test_development_allows_debug_with_random_keys(self):
        s = build_security_settings({"NFSU_ENV": "development", "DJANGO_DEBUG": "1"})
        self.assertTrue(s["DEBUG"])
        self.assertGreater(len(s["SECRET_KEY"]), 40)

    def test_database_timeouts_and_no_sqlite_in_prod(self):
        db = build_database_settings({"NFSU_ENV": "production", "DB_NAME": "n", "DB_USER": "u", "DB_PASSWORD": "pw-123456"})  # secret-scan: allow
        self.assertIn("statement_timeout", db["default"]["OPTIONS"]["options"])
        self.assertEqual(db["default"]["OPTIONS"]["sslmode"], "require")
        with self.assertRaises(ConfigError):
            build_database_settings({"NFSU_ENV": "production", "DB_ENGINE": "sqlite"})


if __name__ == "__main__":
    unittest.main()
