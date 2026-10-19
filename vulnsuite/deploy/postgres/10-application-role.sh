#!/bin/sh
# Runs only during first initialization of an empty PostgreSQL data directory.
set -eu

: "${VULNSUITE_APP_DB_PASSWORD:?Application database password is required}"
: "${POSTGRES_PASSWORD:?Bootstrap database password is required}"
: "${POSTGRES_USER:?Bootstrap database role is required}"
: "${POSTGRES_DB:?Database name is required}"

if [ "${#VULNSUITE_APP_DB_PASSWORD}" -lt 32 ] || [ "${#VULNSUITE_APP_DB_PASSWORD}" -gt 128 ]; then
    printf '%s\n' 'Application database password must contain 32..128 URL-safe characters.' >&2
    exit 1
fi
case "$VULNSUITE_APP_DB_PASSWORD" in
    *[!A-Za-z0-9_-]*)
        printf '%s\n' 'Application database password must use letters, digits, underscore or hyphen.' >&2
        exit 1
        ;;
esac
if [ "${#POSTGRES_PASSWORD}" -lt 32 ] || [ "$POSTGRES_PASSWORD" = "$VULNSUITE_APP_DB_PASSWORD" ]; then
    printf '%s\n' 'Bootstrap password must be distinct from the application password and at least 32 characters.' >&2
    exit 1
fi
if [ "$POSTGRES_DB" != 'vulnsuite' ] || [ "$POSTGRES_USER" != 'vulnsuite_bootstrap' ]; then
    printf '%s\n' 'This initialization script expects the documented VulnSuite database and bootstrap role.' >&2
    exit 1
fi

# psql reads the credential from the process environment, not command arguments.
# :'app_password' uses SQL-literal quoting; the quoted heredoc prevents shell
# interpolation of SQL. Stop immediately on any privilege or role error.
psql --no-psqlrc --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_password VULNSUITE_APP_DB_PASSWORD
BEGIN;
CREATE ROLE vulnsuite_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';
REVOKE ALL ON DATABASE vulnsuite FROM PUBLIC;
GRANT CONNECT ON DATABASE vulnsuite TO vulnsuite_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO vulnsuite_app;
ALTER ROLE vulnsuite_app IN DATABASE vulnsuite SET search_path = public, pg_catalog;
ALTER ROLE vulnsuite_app IN DATABASE vulnsuite SET row_security = on;
COMMIT;
SQL
