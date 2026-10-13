-- Run ONCE per environment as the database OWNER / a DBA role, after `manage.py migrate`.
-- Replace nfsu_app with the role the Django application connects as (it must NOT be the owner or a superuser).
-- Why: the model-level append-only guards stop mistakes in the app; these statements stop a stolen
-- app credential or a SQL-injection from rewriting history.

REVOKE UPDATE, DELETE, TRUNCATE ON audit_ops_auditevent       FROM nfsu_app;
REVOKE UPDATE, DELETE, TRUNCATE ON policy_engine_policydecision FROM nfsu_app;
GRANT  SELECT, INSERT           ON audit_ops_auditevent       TO nfsu_app;
GRANT  SELECT, INSERT           ON policy_engine_policydecision TO nfsu_app;
GRANT  USAGE, SELECT ON SEQUENCE audit_ops_auditevent_seq_seq TO nfsu_app;

-- Belt and braces: even the owner cannot update/delete by accident.
CREATE OR REPLACE FUNCTION nfsu_forbid_change() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update_delete ON audit_ops_auditevent;
CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_ops_auditevent
  FOR EACH ROW EXECUTE FUNCTION nfsu_forbid_change();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit_ops_auditevent;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_ops_auditevent
  FOR EACH STATEMENT EXECUTE FUNCTION nfsu_forbid_change();

DROP TRIGGER IF EXISTS decision_no_update_delete ON policy_engine_policydecision;
CREATE TRIGGER decision_no_update_delete BEFORE UPDATE OR DELETE ON policy_engine_policydecision
  FOR EACH ROW EXECUTE FUNCTION nfsu_forbid_change();

-- Separate roles (create with passwords from your secret store, never in this file):
--   nfsu_audit_reader : SELECT on audit_ops_auditevent only (security officer / auditor tooling)
--   nfsu_backup       : read-only role used by pg_dump (pg_read_all_data)
