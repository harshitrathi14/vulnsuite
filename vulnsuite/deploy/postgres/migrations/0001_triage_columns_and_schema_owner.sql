-- 0001 — for databases created BEFORE the triage / role-split change.
--
-- init_db (API start-up) runs create_all, which adds new TABLES but never
-- new COLUMNS, and it cannot change who owns existing tables. Run this
-- once, as the bootstrap superuser, on an existing database:
--
--   psql -U vulnsuite_bootstrap -d vulnsuite -f 0001_triage_columns_and_schema_owner.sql
--
-- Fresh databases need none of this: 10-application-role.sh creates both
-- roles and init_db creates everything under the migrator.

BEGIN;

-- 1) Analyst triage columns (core/triage.py)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner          VARCHAR(256);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triage_note    TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triaged_by     VARCHAR(256);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triaged_at     TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_until TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS ix_findings_accepted_until ON findings (accepted_until);

-- 2) Schema-owner role (skip the CREATE ROLE if it already exists).
--    Replace the password; it must match VULNSUITE_DB_MIGRATION_URL.
-- CREATE ROLE vulnsuite_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
--     NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '<migrator-password>';
-- GRANT CONNECT ON DATABASE vulnsuite TO vulnsuite_migrator;
-- GRANT USAGE, CREATE ON SCHEMA public TO vulnsuite_migrator;
-- REVOKE CREATE ON SCHEMA public FROM vulnsuite_app;

-- 3) Hand existing tables to the migrator so the runtime role no longer
--    owns them (and so can no longer alter its own RLS policies).
-- ALTER TABLE assets                OWNER TO vulnsuite_migrator;
-- ALTER TABLE findings              OWNER TO vulnsuite_migrator;
-- ALTER TABLE tenant_cloud_accounts OWNER TO vulnsuite_migrator;
-- ALTER TABLE tenant_scopes         OWNER TO vulnsuite_migrator;
-- ALTER TABLE audit_events          OWNER TO vulnsuite_migrator;
-- ALTER FUNCTION audit_events_immutable() OWNER TO vulnsuite_migrator;

COMMIT;

-- After this, start the API with VULNSUITE_DB_MIGRATION_URL set; init_db
-- re-applies RLS and grants the runtime role exactly what it needs.
