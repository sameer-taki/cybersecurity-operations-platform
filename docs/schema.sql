-- Phase 0 review sketch. Alembic migrations will own executable DDL.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
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
CREATE TABLE raw_event_refs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), event_id text NOT NULL, object_uri text NOT NULL, sha256 char(64) NOT NULL, byte_length bigint, retention_until timestamptz, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,event_id));

CREATE TABLE events (tenant_id uuid NOT NULL REFERENCES tenants(id), event_id text NOT NULL, observed_at timestamptz NOT NULL, ingested_at timestamptz NOT NULL, source jsonb NOT NULL, actor jsonb NOT NULL, target jsonb NOT NULL, event_type text NOT NULL, severity severity NOT NULL, confidence numeric(4,3) CHECK(confidence BETWEEN 0 AND 1), action text, outcome outcome NOT NULL DEFAULT 'unknown', raw_event_ref text, parser_name text NOT NULL, parser_version text NOT NULL, raw_event_sha256 char(64), retention_class text NOT NULL DEFAULT 'security_event', retention_until timestamptz, processing_history jsonb NOT NULL DEFAULT '[]', payload jsonb NOT NULL DEFAULT '{}', PRIMARY KEY(tenant_id,event_id,observed_at)) PARTITION BY RANGE(observed_at);
CREATE TABLE events_2026_01 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE INDEX events_tenant_time_idx ON events(tenant_id,observed_at DESC);
CREATE INDEX events_source_gin ON events USING gin(source);
CREATE INDEX events_actor_gin ON events USING gin(actor);
CREATE INDEX events_target_gin ON events USING gin(target);
CREATE INDEX events_payload_gin ON events USING gin(payload);
CREATE TABLE parsers (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, version text NOT NULL, source_kind text NOT NULL, config jsonb NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT true, UNIQUE(tenant_id,name,version));
CREATE TABLE detection_rules (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), name text NOT NULL, description text NOT NULL, logic jsonb NOT NULL, severity severity NOT NULL, confidence_config jsonb NOT NULL DEFAULT '{}', attack_techniques text[] NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT false, version integer NOT NULL DEFAULT 1, UNIQUE(tenant_id,name,version));
CREATE TABLE alerts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), rule_id uuid REFERENCES detection_rules(id), dedup_key text NOT NULL, title text NOT NULL, severity severity NOT NULL, confidence numeric(4,3), status text NOT NULL DEFAULT 'open', first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, evidence jsonb NOT NULL DEFAULT '[]', UNIQUE(tenant_id,dedup_key));
CREATE TABLE incidents (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id), number bigint NOT NULL, title text NOT NULL, status incident_status NOT NULL DEFAULT 'open', severity severity NOT NULL, assignee_id uuid REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), resolved_at timestamptz, UNIQUE(tenant_id,number));
CREATE TABLE incident_events (tenant_id uuid NOT NULL REFERENCES tenants(id), incident_id uuid REFERENCES incidents(id) ON DELETE CASCADE, event_tenant_id uuid NOT NULL, event_id text NOT NULL, observed_at timestamptz NOT NULL, PRIMARY KEY(incident_id,event_tenant_id,event_id,observed_at));
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

-- Apply the same policy pattern to every tenant-owned table in the migration generator.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','roles','role_assignments','api_keys','identity_providers','connectors','connector_health','raw_event_refs','events','parsers','role_permissions','detection_rules','alerts','incidents','incident_events','evidence','tasks','comments','assets','asset_owners','business_services','identities','vulnerabilities','threat_intel','ai_investigations','response_actions','approvals','notifications','reports','audit_log','retention_policies']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.current_tenant'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.current_tenant'', true)::uuid)', t);
  END LOOP;
END $$;

-- The application role must also be granted only INSERT/SELECT on this table;
-- deployment migrations should explicitly revoke UPDATE and DELETE.
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;
