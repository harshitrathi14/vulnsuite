#!/bin/sh
# Runs only during first initialization of an empty PostgreSQL data directory.
#
# Two roles, neither of them the bootstrap superuser:
#   vulnsuite_migrator  owns the schema; only init_db (API start-up) uses it
#                       via VULNSUITE_DB_MIGRATION_URL for DDL, RLS, grants.
#   vulnsuite_app       runtime role; DML only, granted by init_db. It owns
#                       nothing, so it cannot alter RLS policies or drop the
#                       audit_events immutability trigger.
set -eu

: "${VULNSUITE_APP_DB_PASSWORD:?Application database password is required}"
: "${VULNSUITE_MIGRATOR_DB_PASSWORD:?Migrator database password is required}"
: "${POSTGRES_PASSWORD:?Bootstrap database password is required}"
: "${POSTGRES_USER:?Bootstrap database role is required}"
: "${POSTGRES_DB:?Database name is required}"

check_password() {
    name="$1"; value="$2"
    if [ "${#value}" -lt 32 ] || [ "${#value}" -gt 128 ]; then
        printf '%s\n' "$name password must contain 32..128 URL-safe characters." >&2
        exit 1
    fi
    case "$value" in
        *[!A-Za-z0-9_-]*)
            printf '%s\n' "$name password must use letters, digits, underscore or hyphen." >&2
            exit 1
            ;;
    esac
}
check_password Application "$VULNSUITE_APP_DB_PASSWORD"
check_password Migrator "$VULNSUITE_MIGRATOR_DB_PASSWORD"

if [ "$VULNSUITE_APP_DB_PASSWORD" = "$VULNSUITE_MIGRATOR_DB_PASSWORD" ]; then
    printf '%s\n' 'Application and migrator passwords must differ.' >&2
    exit 1
fi
if [ "${#POSTGRES_PASSWORD}" -lt 32 ] || [ "$POSTGRES_PASSWORD" = "$VULNSUITE_APP_DB_PASSWORD" ] \
   || [ "$POSTGRES_PASSWORD" = "$VULNSUITE_MIGRATOR_DB_PASSWORD" ]; then
    printf '%s\n' 'Bootstrap password must be distinct from the application passwords and at least 32 characters.' >&2
    exit 1
fi
if [ "$POSTGRES_DB" != 'vulnsuite' ] || [ "$POSTGRES_USER" != 'vulnsuite_bootstrap' ]; then
    printf '%s\n' 'This initialization script expects the documented VulnSuite database and bootstrap role.' >&2
    exit 1
fi

# psql reads the credentials from the process environment, not command arguments.
# :'...' uses SQL-literal quoting; the quoted heredoc prevents shell
# interpolation of SQL. Stop immediately on any privilege or role error.
psql --no-psqlrc --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_password VULNSUITE_APP_DB_PASSWORD
\getenv migrator_password VULNSUITE_MIGRATOR_DB_PASSWORD
BEGIN;
CREATE ROLE vulnsuite_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'migrator_password';
CREATE ROLE vulnsuite_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';

REVOKE ALL ON DATABASE vulnsuite FROM PUBLIC;
GRANT CONNECT ON DATABASE vulnsuite TO vulnsuite_migrator, vulnsuite_app;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Only the migrator may create objects; the runtime role gets USAGE and
-- per-table DML grants from init_db.
GRANT USAGE, CREATE ON SCHEMA public TO vulnsuite_migrator;
GRANT USAGE ON SCHEMA public TO vulnsuite_app;

ALTER ROLE vulnsuite_migrator IN DATABASE vulnsuite SET search_path = public, pg_catalog;
ALTER ROLE vulnsuite_app IN DATABASE vulnsuite SET search_path = public, pg_catalog;
ALTER ROLE vulnsuite_app IN DATABASE vulnsuite SET row_security = on;
COMMIT;
SQL
