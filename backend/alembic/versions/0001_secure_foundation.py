"""Phase 1 secure foundation only.

Detection, case-management, AI, response-action, and reporting tables are
intentionally deferred to their roadmap phases.
"""

from alembic import op


def _execute_script(script: str) -> None:
    statement: list[str] = []
    quote: str | None = None
    dollar_tag: str | None = None
    index = 0
    while index < len(script):
        if dollar_tag is not None:
            if script.startswith(dollar_tag, index):
                statement.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = None
            else:
                statement.append(script[index])
                index += 1
            continue
        if quote is not None:
            statement.append(script[index])
            if script[index] == quote:
                if index + 1 < len(script) and script[index + 1] == quote:
                    statement.append(script[index + 1])
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if script[index] in ("'", '"'):
            quote = script[index]
            statement.append(script[index])
            index += 1
            continue
        if script[index] == "$":
            end = script.find("$", index + 1)
            if end > index:
                dollar_tag = script[index : end + 1]
                statement.append(dollar_tag)
                index = end + 1
                continue
        if script[index] == ";":
            sql = "".join(statement).strip()
            if sql:
                op.execute(sql)
            statement = []
        else:
            statement.append(script[index])
        index += 1
    sql = "".join(statement).strip()
    if sql:
        op.execute(sql)


revision = "0001_secure_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    _execute_script(
        """
        CREATE EXTENSION IF NOT EXISTS pgcrypto;
        CREATE EXTENSION IF NOT EXISTS citext;
        DO $$ BEGIN
          CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
        EXCEPTION WHEN duplicate_object THEN NULL; END $$;
        DO $$ BEGIN
          CREATE ROLE platform_admin NOLOGIN NOSUPERUSER NOBYPASSRLS;
        EXCEPTION WHEN duplicate_object THEN NULL; END $$;
        CREATE TYPE severity AS ENUM ('low','medium','high','critical');
        CREATE TYPE outcome AS ENUM ('success','failure','unknown');

        CREATE TABLE tenants (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL,
          slug text UNIQUE NOT NULL, status text NOT NULL DEFAULT 'active',
          created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE users (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          email citext NOT NULL, display_name text NOT NULL, password_hash text,
          external_id text, provisioned_by text, mfa_enabled boolean NOT NULL DEFAULT false,
          failed_login_count integer NOT NULL DEFAULT 0, locked_until timestamptz,
          disabled_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE(tenant_id,email), UNIQUE(tenant_id,id)
        );
        CREATE TABLE roles (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          name text NOT NULL, UNIQUE(tenant_id,name), UNIQUE(tenant_id,id)
        );
        CREATE TABLE permissions (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), key text UNIQUE NOT NULL, description text NOT NULL
        );
        CREATE TABLE role_permissions (
          tenant_id uuid NOT NULL REFERENCES tenants(id), role_id uuid NOT NULL REFERENCES roles(id),
          permission_id uuid NOT NULL REFERENCES permissions(id),
          PRIMARY KEY(tenant_id,role_id,permission_id),
          FOREIGN KEY(tenant_id,role_id) REFERENCES roles(tenant_id,id)
        );
        CREATE TABLE role_assignments (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          user_id uuid NOT NULL REFERENCES users(id), role_id uuid NOT NULL REFERENCES roles(id),
          attributes jsonb NOT NULL DEFAULT '{}',
          FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id),
          FOREIGN KEY(tenant_id,role_id) REFERENCES roles(tenant_id,id)
        );
        CREATE TABLE api_keys (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          name text NOT NULL, prefix text NOT NULL, key_hash text NOT NULL, scopes text[] NOT NULL,
          ip_allowlist inet[], revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE identity_providers (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          kind text NOT NULL CHECK(kind IN ('oidc','saml')), config jsonb NOT NULL DEFAULT '{}',
          secret_ref text, enabled boolean NOT NULL DEFAULT false
        );
        CREATE TABLE connectors (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          name text NOT NULL, kind text NOT NULL, config jsonb NOT NULL DEFAULT '{}',
          secret_ref text, enabled boolean NOT NULL DEFAULT true, UNIQUE(tenant_id,id)
        );
        CREATE TABLE connector_health (
          connector_id uuid PRIMARY KEY REFERENCES connectors(id), tenant_id uuid NOT NULL REFERENCES tenants(id),
          status text NOT NULL, last_success_at timestamptz, event_count bigint NOT NULL DEFAULT 0,
          error_count bigint NOT NULL DEFAULT 0, last_error text, checked_at timestamptz,
          FOREIGN KEY(tenant_id,connector_id) REFERENCES connectors(tenant_id,id)
        );
        CREATE TABLE raw_event_refs (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          event_id text NOT NULL, object_uri text NOT NULL, sha256 char(64) NOT NULL,
          byte_length bigint, retention_until timestamptz, legal_hold boolean NOT NULL DEFAULT false,
          created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,event_id)
        );
        CREATE TABLE events (
          tenant_id uuid NOT NULL REFERENCES tenants(id), event_id text NOT NULL,
          observed_at timestamptz NOT NULL, ingested_at timestamptz NOT NULL,
          source jsonb NOT NULL, actor jsonb NOT NULL, target jsonb NOT NULL,
          event_type text NOT NULL, severity severity NOT NULL, confidence numeric(4,3)
            CHECK(confidence BETWEEN 0 AND 1), action text, outcome outcome NOT NULL DEFAULT 'unknown',
          raw_event_ref text NOT NULL, parser_name text NOT NULL, parser_version text NOT NULL,
          raw_event_sha256 char(64) NOT NULL, retention_class text NOT NULL DEFAULT 'security_event',
          retention_until timestamptz, legal_hold boolean NOT NULL DEFAULT false,
          processing_history jsonb NOT NULL DEFAULT '[]', payload jsonb NOT NULL DEFAULT '{}',
          PRIMARY KEY(tenant_id,event_id,observed_at)
        ) PARTITION BY RANGE(observed_at);
        DO $$
        DECLARE start_date date := date_trunc('month', CURRENT_DATE)::date;
        BEGIN
          EXECUTE format(
            'CREATE TABLE events_%s PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
            to_char(start_date, 'YYYY_MM'), start_date, (start_date + interval '1 month')::date
          );
        END $$;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
          GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
          GRANT SELECT ON TABLES TO app_runtime;
        CREATE TABLE parsers (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          name text NOT NULL, version text NOT NULL, source_kind text NOT NULL,
          config jsonb NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT true,
          UNIQUE(tenant_id,name,version)
        );
        CREATE TABLE totp_secrets (
          user_id uuid PRIMARY KEY REFERENCES users(id), tenant_id uuid NOT NULL REFERENCES tenants(id),
          encrypted_secret text NOT NULL, recovery_code_hashes text[] NOT NULL DEFAULT '{}',
          FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id)
        );
        CREATE TABLE refresh_tokens (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          user_id uuid NOT NULL REFERENCES users(id), family_id uuid NOT NULL, token_hash text UNIQUE NOT NULL,
          used_at timestamptz, revoked_at timestamptz, expires_at timestamptz NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id)
        );
        CREATE TABLE audit_log (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          actor_id uuid REFERENCES users(id), action text NOT NULL, resource_type text NOT NULL,
          resource_id text, metadata jsonb NOT NULL DEFAULT '{}', prev_hash char(64),
          entry_hash char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
          FOREIGN KEY(tenant_id,actor_id) REFERENCES users(tenant_id,id)
        );
        CREATE TABLE retention_policies (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
          data_class text NOT NULL, retention_days integer NOT NULL CHECK(retention_days > 0),
          legal_hold boolean NOT NULL DEFAULT false, enabled boolean NOT NULL DEFAULT true,
          UNIQUE(tenant_id,data_class)
        );
        CREATE INDEX events_tenant_time_idx ON events(tenant_id,observed_at DESC);
        CREATE INDEX events_source_gin ON events USING gin(source);
        CREATE INDEX events_actor_gin ON events USING gin(actor);
        CREATE INDEX events_target_gin ON events USING gin(target);
        CREATE INDEX events_payload_gin ON events USING gin(payload);
        CREATE INDEX audit_chain_idx ON audit_log(tenant_id,created_at);
        ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON tenants
          USING (id = current_setting('app.current_tenant', true)::uuid)
          WITH CHECK (id = current_setting('app.current_tenant', true)::uuid);
        CREATE POLICY platform_admin_tenant_registry ON tenants TO platform_admin
          USING (true) WITH CHECK (true);
        DO $$
        DECLARE table_name text;
        BEGIN
          FOREACH table_name IN ARRAY ARRAY[
            'users','roles','role_permissions','role_assignments','api_keys',
            'identity_providers','connectors','connector_health','raw_event_refs',
            'events','parsers','totp_secrets','refresh_tokens','audit_log','retention_policies'
          ] LOOP
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
            EXECUTE format(
              'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.current_tenant'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.current_tenant'', true)::uuid)',
              table_name
            );
          END LOOP;
          FOR table_name IN SELECT c.relname FROM pg_class c WHERE c.relname LIKE 'events_%' AND c.relkind = 'r' LOOP
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
            BEGIN
              EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.current_tenant'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.current_tenant'', true)::uuid)',
                table_name
              );
            EXCEPTION WHEN duplicate_object THEN NULL;
            END;
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO app_runtime', table_name);
          END LOOP;
        END $$;
        REVOKE ALL ON tenants FROM app_runtime;
        GRANT SELECT ON permissions TO app_runtime;
        GRANT SELECT,INSERT,UPDATE,DELETE ON tenants TO platform_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON
          users, roles, role_permissions, role_assignments, api_keys,
          identity_providers, connectors, connector_health, raw_event_refs,
          events, parsers, totp_secrets, refresh_tokens, audit_log,
          retention_policies TO app_runtime;
        GRANT SELECT,INSERT ON audit_log TO app_runtime;
        REVOKE UPDATE,DELETE ON audit_log FROM app_runtime;
        REVOKE UPDATE,DELETE ON audit_log FROM PUBLIC;
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
            WHERE r.rolname IN ('app_runtime', 'platform_admin')
              AND c.relkind IN ('r','p','v','m','f')
          ) THEN RAISE EXCEPTION 'service group roles must not own application objects'; END IF;
          IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname IN ('app_runtime', 'platform_admin')
              AND (rolsuper OR rolbypassrls)
          ) THEN RAISE EXCEPTION 'service group roles must not be superuser or bypass RLS'; END IF;
        END $$;
        CREATE OR REPLACE FUNCTION assert_connecting_role()
        RETURNS void LANGUAGE plpgsql SECURITY INVOKER AS $fn$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
          ) THEN RAISE EXCEPTION 'connecting role must not be superuser or bypass RLS'; END IF;
          IF EXISTS (
            SELECT 1 FROM pg_class
            WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
              AND relkind IN ('r','p','v','m','f')
          ) THEN RAISE EXCEPTION 'connecting role must not own application objects'; END IF;
        END $fn$;
        GRANT EXECUTE ON FUNCTION assert_connecting_role() TO app_runtime, platform_admin;
        """
    )


def downgrade() -> None:
    _execute_script(
        """
        DROP TABLE IF EXISTS retention_policies, audit_log, refresh_tokens, totp_secrets,
          parsers, events, raw_event_refs, connector_health, connectors,
          identity_providers, api_keys, role_assignments, role_permissions,
          permissions, roles, users, tenants CASCADE;
        DROP TYPE IF EXISTS outcome;
        DROP TYPE IF EXISTS severity;
        """
    )
