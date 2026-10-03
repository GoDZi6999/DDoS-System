#!/bin/sh
# Runs once, when the PostgreSQL volume is first initialised.
#
# Creates the least-privilege role that the backend and alert engine connect
# as. Tables are created by the migrate service as POSTGRES_USER (the owner);
# default privileges give the app role SELECT/INSERT/UPDATE/DELETE on them but
# not ownership, so it cannot alter the schema or disable the trigger that
# keeps audit_logs append-only.
#
# No `set -u`: the postgres entrypoint sources this file when it is not
# executable, and nounset would leak into the entrypoint's own shell.
set -e
: "${APP_DB_USER:?APP_DB_USER must be set}"
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_user="$APP_DB_USER" -v app_password="$APP_DB_PASSWORD" \
  -v owner="$POSTGRES_USER" -v db="$POSTGRES_DB" <<'EOSQL'
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE :"db" TO :"app_user";
GRANT USAGE ON SCHEMA public TO :"app_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";
EOSQL
