-- Phase 0 review sketch. Alembic migrations will own executable DDL.
-- Deployment contract: migrations run as a separate DDL/owner role. The
-- app_runtime and platform_admin roles are NOLOGIN group roles; deployment
-- creates per-service LOGIN roles and grants membership (for example,
-- GRANT app_runtime TO app_api_login). A connecting LOGIN role must be
-- NOSUPERUSER, NOBYPASSRLS, and own no application objects. The control-plane
-- service uses platform_admin for tenant-registry access; app_runtime has no
-- SELECT privilege on tenants.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
    CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_admin') THEN
    CREATE ROLE platform_admin NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
CREATE TYPE severity AS ENUM ('low','medium','high','critical');
CREATE TYPE outcome AS ENUM ('success','failure','unknown');
CREATE TYPE incident_status AS ENUM ('open','investigating','contained','resolved','closed');
CREATE TYPE action_status AS ENUM ('proposed','previewed','permission_checked','pending_approval','approved','rejected','expired','executing','verified','failed','rollback_pending','rolled_back','rollback_failed');

CREATE TABLE tenants (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, slug text UNIQUE NOT NULL, status text NOT NULL DEFAULT 'active', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE users (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), email citext NOT NULL, display_name text NOT NULL, password_hash text, external_id text, provisioned_by text, mfa_enabled boolean NOT NULL DEFAULT false, disabled_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,email));
CREATE TABLE roles (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, UNIQUE(tenant_id,name));
CREATE TABLE permissions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), key text UNIQUE NOT NULL, description text NOT NULL);
CREATE TABLE role_permissions (tenant_id uuid NOT NULL REFERENCES tenants(id), role_id uuid REFERENCES roles(id) ON DELETE CASCADE, permission_id uuid REFERENCES permissions(id) ON DELETE CASCADE, PRIMARY KEY(role_id,permission_id));
CREATE TABLE role_assignments (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), user_id uuid NOT NULL REFERENCES users(id), role_id uuid NOT NULL REFERENCES roles(id), attributes jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE api_keys (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, prefix text NOT NULL, key_hash text NOT NULL, scopes text[] NOT NULL, ip_allowlist inet[], revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE identity_providers (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), kind text NOT NULL CHECK(kind IN ('oidc','saml')), config jsonb NOT NULL, secret_ref text, enabled boolean NOT NULL DEFAULT false);
CREATE TABLE connectors (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, kind text NOT NULL, config jsonb NOT NULL DEFAULT '{}', secret_ref text, enabled boolean NOT NULL DEFAULT true, deleted_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE connector_health (connector_id uuid PRIMARY KEY REFERENCES connectors(id) ON DELETE CASCADE, tenant_id uuid NOT NULL REFERENCES tenants(id), status text NOT NULL, last_success_at timestamptz, event_count bigint NOT NULL DEFAULT 0, error_count bigint NOT NULL DEFAULT 0, last_error text, checked_at timestamptz);
CREATE TABLE raw_event_refs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), event_id text NOT NULL, object_uri text NOT NULL CHECK (object_uri ~ ('^object://raw/' || tenant_id::text || '/[0-9]{4}/[0-9]{2}/[0-9]{2}/[^/]+$')), sha256 char(64) NOT NULL, byte_length bigint, retention_until timestamptz, legal_hold boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,event_id));

CREATE TABLE events (tenant_id uuid NOT NULL REFERENCES tenants(id), event_id text NOT NULL, observed_at timestamptz NOT NULL, ingested_at timestamptz NOT NULL, source jsonb NOT NULL, actor jsonb NOT NULL, target jsonb NOT NULL, event_type text NOT NULL, severity severity NOT NULL, confidence numeric(4,3) CHECK(confidence BETWEEN 0 AND 1), action text, outcome outcome NOT NULL DEFAULT 'unknown', raw_event_ref text NOT NULL, parser_name text NOT NULL, parser_version text NOT NULL, raw_event_sha256 char(64) NOT NULL, retention_class text NOT NULL DEFAULT 'security_event', retention_until timestamptz, legal_hold boolean NOT NULL DEFAULT false, processing_history jsonb NOT NULL DEFAULT '[]', payload jsonb NOT NULL DEFAULT '{}', PRIMARY KEY(tenant_id,event_id,observed_at)) PARTITION BY RANGE(observed_at);
-- Partition manager creates the current month, N months ahead, and a small
-- back-window. It must grant direct maintenance access and apply ENABLE +
-- FORCE RLS plus the same policy below to every partition it creates. No
-- DEFAULT partition is used.
CREATE TABLE events_2026_08 PARTITION OF events FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
ALTER TABLE events_2026_08 ENABLE ROW LEVEL SECURITY;
ALTER TABLE events_2026_08 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON events_2026_08
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE INDEX events_tenant_time_idx ON events(tenant_id,observed_at DESC);
CREATE INDEX events_source_gin ON events USING gin(source);
CREATE INDEX events_actor_gin ON events USING gin(actor);
CREATE INDEX events_target_gin ON events USING gin(target);
CREATE INDEX events_payload_gin ON events USING gin(payload);
CREATE TABLE parsers (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, version text NOT NULL, source_kind text NOT NULL, config jsonb NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT true, UNIQUE(tenant_id,name,version));
CREATE TABLE detection_rules (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, description text NOT NULL, logic jsonb NOT NULL, severity severity NOT NULL, confidence_config jsonb NOT NULL DEFAULT '{}', attack_techniques text[] NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT false, version integer NOT NULL DEFAULT 1, UNIQUE(tenant_id,name,version));
CREATE TABLE alerts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), rule_id uuid REFERENCES detection_rules(id), dedup_key text NOT NULL, title text NOT NULL, severity severity NOT NULL, confidence numeric(4,3), status text NOT NULL DEFAULT 'open', first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, evidence jsonb NOT NULL DEFAULT '[]', UNIQUE(tenant_id,dedup_key));
CREATE TABLE incidents (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), number bigint NOT NULL, title text NOT NULL, status incident_status NOT NULL DEFAULT 'open', severity severity NOT NULL, assignee_id uuid REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), resolved_at timestamptz, UNIQUE(tenant_id,number));
CREATE TABLE incident_events (tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id) ON DELETE CASCADE, event_tenant_id uuid NOT NULL, event_id text NOT NULL, observed_at timestamptz NOT NULL, CHECK (event_tenant_id = tenant_id), PRIMARY KEY(incident_id,event_tenant_id,event_id,observed_at));
CREATE TABLE evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, kind text NOT NULL, source_ref text NOT NULL, sha256 char(64) NOT NULL, collected_at timestamptz NOT NULL DEFAULT now(), collected_by uuid REFERENCES users(id), legal_hold boolean NOT NULL DEFAULT false);
CREATE TABLE tasks (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id), title text NOT NULL, status text NOT NULL DEFAULT 'open', assignee_id uuid REFERENCES users(id), due_at timestamptz);
CREATE TABLE comments (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id), author_id uuid NOT NULL REFERENCES users(id), body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE assets (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, kind text NOT NULL, criticality integer CHECK(criticality BETWEEN 1 AND 5), classification text, internet_exposed boolean, os text, last_seen_at timestamptz, deleted_at timestamptz);
CREATE TABLE asset_owners (tenant_id uuid NOT NULL REFERENCES tenants(id), asset_id uuid REFERENCES assets(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id), PRIMARY KEY(asset_id,user_id));
CREATE TABLE business_services (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, criticality integer CHECK(criticality BETWEEN 1 AND 5), recovery_priority integer);
CREATE TABLE identities (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), username text NOT NULL, kind text NOT NULL, asset_id uuid REFERENCES assets(id), external_id text, UNIQUE(tenant_id,username));
CREATE TABLE vulnerabilities (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), asset_id uuid REFERENCES assets(id), cve text, severity severity, status text NOT NULL, detected_at timestamptz);
CREATE TABLE threat_intel (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), indicator text NOT NULL, indicator_type text NOT NULL, confidence numeric(4,3), source text, expires_at timestamptz);
CREATE TABLE ai_investigations (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id), status text NOT NULL DEFAULT 'draft', bundle_hash char(64), provider text, model text, prompt_version text, retrieval_version text, output jsonb, validation_result jsonb, reviewer_id uuid REFERENCES users(id), review_state text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE response_actions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id), action_type text NOT NULL, target jsonb NOT NULL, preview jsonb, status action_status NOT NULL DEFAULT 'proposed', requested_by uuid REFERENCES users(id), executed_at timestamptz, verification jsonb, rollback jsonb);
CREATE TABLE approvals (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), action_id uuid NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE, approver_id uuid NOT NULL REFERENCES users(id), decision text NOT NULL CHECK(decision IN ('approved','rejected')), reason text, decided_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE notifications (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id), channel text NOT NULL, destination_ref text NOT NULL, status text NOT NULL DEFAULT 'queued', sent_at timestamptz, error text);
CREATE TABLE reports (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), kind text NOT NULL, status text NOT NULL DEFAULT 'queued', object_uri text, sha256 char(64), requested_by uuid REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE audit_log (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), actor_id uuid REFERENCES users(id), action text NOT NULL, resource_type text NOT NULL, resource_id text, metadata jsonb NOT NULL DEFAULT '{}', prev_hash char(64), entry_hash char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE retention_policies (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), data_class text NOT NULL, retention_days integer NOT NULL CHECK(retention_days > 0), legal_hold boolean NOT NULL DEFAULT false, enabled boolean NOT NULL DEFAULT true, UNIQUE(tenant_id,data_class));

CREATE INDEX alerts_tenant_status_idx ON alerts(tenant_id,status,severity);
CREATE INDEX incidents_tenant_status_idx ON incidents(tenant_id,status,severity);
CREATE INDEX evidence_incident_idx ON evidence(tenant_id,incident_id);
CREATE INDEX audit_chain_idx ON audit_log(tenant_id,created_at);

-- Composite uniqueness/FKs prevent a tenant-scoped row from referencing an
-- object whose tenant_id differs, even though internal IDs are globally unique.
CREATE UNIQUE INDEX users_tenant_id_uq ON users(tenant_id,id);
CREATE UNIQUE INDEX roles_tenant_id_uq ON roles(tenant_id,id);
CREATE UNIQUE INDEX connectors_tenant_id_uq ON connectors(tenant_id,id);
CREATE UNIQUE INDEX detection_rules_tenant_id_uq ON detection_rules(tenant_id,id);
CREATE UNIQUE INDEX incidents_tenant_id_uq ON incidents(tenant_id,id);
CREATE UNIQUE INDEX assets_tenant_id_uq ON assets(tenant_id,id);
CREATE UNIQUE INDEX ai_investigations_tenant_id_uq ON ai_investigations(tenant_id,id);
CREATE UNIQUE INDEX response_actions_tenant_id_uq ON response_actions(tenant_id,id);

ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_role_tenant_fk FOREIGN KEY (tenant_id,role_id) REFERENCES roles(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE role_assignments ADD CONSTRAINT role_assignments_user_tenant_fk FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id);
ALTER TABLE role_assignments ADD CONSTRAINT role_assignments_role_tenant_fk FOREIGN KEY (tenant_id,role_id) REFERENCES roles(tenant_id,id);
ALTER TABLE connector_health ADD CONSTRAINT connector_health_connector_tenant_fk FOREIGN KEY (tenant_id,connector_id) REFERENCES connectors(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE alerts ADD CONSTRAINT alerts_rule_tenant_fk FOREIGN KEY (tenant_id,rule_id) REFERENCES detection_rules(tenant_id,id);
ALTER TABLE incidents ADD CONSTRAINT incidents_assignee_tenant_fk FOREIGN KEY (tenant_id,assignee_id) REFERENCES users(tenant_id,id);
ALTER TABLE incident_events ADD CONSTRAINT incident_events_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE evidence ADD CONSTRAINT evidence_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE evidence ADD CONSTRAINT evidence_collector_tenant_fk FOREIGN KEY (tenant_id,collected_by) REFERENCES users(tenant_id,id);
ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_tenant_fk FOREIGN KEY (tenant_id,actor_id) REFERENCES users(tenant_id,id);
ALTER TABLE tasks ADD CONSTRAINT tasks_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id);
ALTER TABLE tasks ADD CONSTRAINT tasks_assignee_tenant_fk FOREIGN KEY (tenant_id,assignee_id) REFERENCES users(tenant_id,id);
ALTER TABLE comments ADD CONSTRAINT comments_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id);
ALTER TABLE comments ADD CONSTRAINT comments_author_tenant_fk FOREIGN KEY (tenant_id,author_id) REFERENCES users(tenant_id,id);
ALTER TABLE asset_owners ADD CONSTRAINT asset_owners_asset_tenant_fk FOREIGN KEY (tenant_id,asset_id) REFERENCES assets(tenant_id,id) ON DELETE CASCADE;
ALTER TABLE asset_owners ADD CONSTRAINT asset_owners_user_tenant_fk FOREIGN KEY (tenant_id,user_id) REFERENCES users(tenant_id,id);
ALTER TABLE identities ADD CONSTRAINT identities_asset_tenant_fk FOREIGN KEY (tenant_id,asset_id) REFERENCES assets(tenant_id,id);
ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_asset_tenant_fk FOREIGN KEY (tenant_id,asset_id) REFERENCES assets(tenant_id,id);
ALTER TABLE ai_investigations ADD CONSTRAINT ai_investigations_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id);
ALTER TABLE ai_investigations ADD CONSTRAINT ai_investigations_reviewer_tenant_fk FOREIGN KEY (tenant_id,reviewer_id) REFERENCES users(tenant_id,id);
ALTER TABLE response_actions ADD CONSTRAINT response_actions_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id);
ALTER TABLE response_actions ADD CONSTRAINT response_actions_requester_tenant_fk FOREIGN KEY (tenant_id,requested_by) REFERENCES users(tenant_id,id);
ALTER TABLE approvals ADD CONSTRAINT approvals_action_tenant_fk FOREIGN KEY (tenant_id,action_id) REFERENCES response_actions(tenant_id,id);
ALTER TABLE approvals ADD CONSTRAINT approvals_approver_tenant_fk FOREIGN KEY (tenant_id,approver_id) REFERENCES users(tenant_id,id);
ALTER TABLE notifications ADD CONSTRAINT notifications_incident_tenant_fk FOREIGN KEY (tenant_id,incident_id) REFERENCES incidents(tenant_id,id);
ALTER TABLE reports ADD CONSTRAINT reports_requester_tenant_fk FOREIGN KEY (tenant_id,requested_by) REFERENCES users(tenant_id,id);

-- Apply the same policy pattern to every tenant-owned table in the migration generator.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','roles','role_assignments','api_keys','identity_providers','connectors','connector_health','raw_event_refs','events','parsers','role_permissions','detection_rules','alerts','incidents','incident_events','evidence','tasks','comments','assets','asset_owners','business_services','identities','vulnerabilities','threat_intel','ai_investigations','response_actions','approvals','notifications','reports','audit_log','retention_policies']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.current_tenant'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.current_tenant'', true)::uuid)', t);
  END LOOP;
END $$;

CREATE POLICY tenant_isolation ON tenants
  USING (id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY platform_admin_tenant_registry ON tenants TO platform_admin
  USING (true) WITH CHECK (true);

-- Grant split: app_runtime gets DML only on tenant-plane tables. Global
-- catalogues are explicit SELECT-only grants; the registry is inaccessible.
GRANT SELECT, INSERT, UPDATE, DELETE ON
  users, roles, role_permissions, role_assignments, api_keys,
  identity_providers, connectors, connector_health, events,
  parsers, detection_rules, alerts, incidents, incident_events,
  tasks, comments, assets, asset_owners, business_services, identities,
  vulnerabilities, threat_intel, ai_investigations, response_actions,
  approvals, notifications, reports, retention_policies TO app_runtime;
GRANT SELECT, INSERT ON raw_event_refs, evidence TO app_runtime;
GRANT SELECT ON permissions TO app_runtime;
REVOKE ALL ON tenants FROM app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO platform_admin;
GRANT SELECT, INSERT ON audit_log TO app_runtime;
REVOKE UPDATE, DELETE ON audit_log FROM app_runtime;

-- These checks are meaningful as deployment health checks on an already
-- provisioned cluster; the owner role necessarily owns objects in this sketch.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE r.rolname IN ('app_runtime', 'platform_admin')
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  ) THEN
    RAISE EXCEPTION 'service group role % must not own application objects', (SELECT string_agg(r.rolname, ',') FROM pg_roles r JOIN pg_class c ON c.relowner = r.oid WHERE r.rolname IN ('app_runtime', 'platform_admin') AND c.relkind IN ('r', 'p', 'v', 'm', 'f'));
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_roles r
    WHERE (r.rolsuper OR r.rolbypassrls)
      AND EXISTS (
        SELECT 1
        FROM pg_roles g
        WHERE g.rolname IN ('app_runtime', 'platform_admin')
          AND pg_has_role(g.oid, r.oid, 'member')
      )
  ) THEN
    RAISE EXCEPTION 'service group roles must not be superusers';
  END IF;
END $$;

-- Append-only audit grants are defined above; PUBLIC cannot mutate it.
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

-- Deployment invokes this as each per-service LOGIN role. Checking
-- current_user (rather than only the group roles above) catches an unsafe
-- connecting role even when its group membership looks correct.
CREATE OR REPLACE FUNCTION assert_connecting_role()
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_roles r
    WHERE (r.rolsuper OR r.rolbypassrls)
      AND (r.rolname = current_user OR pg_has_role(current_user, r.oid, 'member'))
  ) THEN
    RAISE EXCEPTION 'connecting role must not be superuser or bypass RLS';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_class
    WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
      AND relkind IN ('r', 'p', 'v', 'm', 'f')
  ) THEN
    RAISE EXCEPTION 'connecting role must not own application objects';
  END IF;
END $$;
GRANT EXECUTE ON FUNCTION assert_connecting_role() TO app_runtime, platform_admin;
