-- Gatedhouse schema, version 1.

CREATE SCHEMA IF NOT EXISTS gatedhouse;

-- =========================================================================
-- Enums
-- =========================================================================

CREATE TYPE gatedhouse.entity_type       AS ENUM ('user', 'agent');
CREATE TYPE gatedhouse.membership_status AS ENUM ('active', 'suspended', 'pending');
CREATE TYPE gatedhouse.audit_op          AS ENUM ('INSERT', 'UPDATE', 'DELETE');

-- =========================================================================
-- Permission catalog (Shape A: fully scoped service / resource / action)
-- =========================================================================

CREATE TABLE gatedhouse.services (
    service     TEXT PRIMARY KEY,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gatedhouse.resources (
    service     TEXT NOT NULL REFERENCES gatedhouse.services(service) ON DELETE CASCADE,
    resource    TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (service, resource)
);

CREATE TABLE gatedhouse.actions (
    service     TEXT NOT NULL,
    resource    TEXT NOT NULL,
    action      TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (service, resource, action),
    FOREIGN KEY (service, resource)
        REFERENCES gatedhouse.resources(service, resource) ON DELETE CASCADE
);

-- =========================================================================
-- Roles (global) and their relations
-- =========================================================================

CREATE TABLE gatedhouse.roles (
    key         TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role permissions: each row grants one permission (possibly with NULL
-- wildcards). NULL columns make the corresponding composite FKs skip the
-- referential check, which is exactly the wildcard semantics we want.
CREATE TABLE gatedhouse.role_permissions (
    id        UUID PRIMARY KEY,
    role_key  TEXT NOT NULL REFERENCES gatedhouse.roles(key) ON DELETE CASCADE,
    service   TEXT,
    resource  TEXT,
    action    TEXT,
    FOREIGN KEY (service)
        REFERENCES gatedhouse.services(service) ON DELETE CASCADE,
    FOREIGN KEY (service, resource)
        REFERENCES gatedhouse.resources(service, resource) ON DELETE CASCADE,
    FOREIGN KEY (service, resource, action)
        REFERENCES gatedhouse.actions(service, resource, action) ON DELETE CASCADE
);

-- A role cannot grant the same (service, resource, action) tuple twice.
-- COALESCE forces NULLs to compare as equal so wildcards de-duplicate too.
CREATE UNIQUE INDEX role_permissions_unique
    ON gatedhouse.role_permissions
    (role_key,
     COALESCE(service,  ''),
     COALESCE(resource, ''),
     COALESCE(action,   ''));

CREATE INDEX role_permissions_role_key
    ON gatedhouse.role_permissions (role_key);

-- Role inheritance (DAG; cycles caught at application level).
CREATE TABLE gatedhouse.role_inherits (
    child_key  TEXT NOT NULL REFERENCES gatedhouse.roles(key) ON DELETE CASCADE,
    parent_key TEXT NOT NULL REFERENCES gatedhouse.roles(key) ON DELETE CASCADE,
    PRIMARY KEY (child_key, parent_key),
    CHECK (child_key <> parent_key)
);

CREATE INDEX role_inherits_parent
    ON gatedhouse.role_inherits (parent_key);

-- =========================================================================
-- Identity-side (per-org) tables
-- =========================================================================

CREATE TABLE gatedhouse.memberships (
    id          UUID PRIMARY KEY,
    identity_id TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    entity_type gatedhouse.entity_type NOT NULL,
    status      gatedhouse.membership_status NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, org_id)
);

CREATE INDEX memberships_org_id
    ON gatedhouse.memberships (org_id);

CREATE TABLE gatedhouse.role_assignments (
    id          UUID PRIMARY KEY,
    identity_id TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    role_key    TEXT NOT NULL REFERENCES gatedhouse.roles(key) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, org_id, role_key)
);

CREATE INDEX role_assignments_identity_org
    ON gatedhouse.role_assignments (identity_id, org_id);

-- Groups: library-owned tables, but written either via the local API
-- (LocalGroupSource) or by an event listener (CitadelGroupSource).
-- Group IDs are opaque, supplied by the host.
CREATE TABLE gatedhouse.groups (
    id          TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    name        TEXT,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, org_id)
);

CREATE TABLE gatedhouse.group_memberships (
    group_id    TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, org_id, identity_id),
    FOREIGN KEY (group_id, org_id)
        REFERENCES gatedhouse.groups(id, org_id) ON DELETE CASCADE
);

CREATE INDEX group_memberships_identity_org
    ON gatedhouse.group_memberships (identity_id, org_id);

CREATE TABLE gatedhouse.group_roles (
    group_id    TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    role_key    TEXT NOT NULL REFERENCES gatedhouse.roles(key) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, org_id, role_key),
    FOREIGN KEY (group_id, org_id)
        REFERENCES gatedhouse.groups(id, org_id) ON DELETE CASCADE
);

CREATE INDEX group_roles_group_org
    ON gatedhouse.group_roles (group_id, org_id);

-- =========================================================================
-- Generic audit log + trigger
-- =========================================================================

CREATE TABLE gatedhouse.audit_log (
    id         BIGSERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    op         gatedhouse.audit_op NOT NULL,
    old_row    JSONB,
    new_row    JSONB,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by TEXT
);

CREATE INDEX audit_log_table_changed_at
    ON gatedhouse.audit_log (table_name, changed_at DESC);

-- Trigger function: writes to audit_log. Reads optional session variable
-- 'gatedhouse.actor' for changed_by; missing setting => NULL.
CREATE OR REPLACE FUNCTION gatedhouse.audit_trigger() RETURNS trigger AS $$
DECLARE
    actor TEXT;
BEGIN
    actor := current_setting('gatedhouse.actor', true);

    IF (TG_OP = 'INSERT') THEN
        INSERT INTO gatedhouse.audit_log (table_name, op, old_row, new_row, changed_by)
        VALUES (TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, 'INSERT',
                NULL, to_jsonb(NEW), actor);
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO gatedhouse.audit_log (table_name, op, old_row, new_row, changed_by)
        VALUES (TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, 'UPDATE',
                to_jsonb(OLD), to_jsonb(NEW), actor);
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO gatedhouse.audit_log (table_name, op, old_row, new_row, changed_by)
        VALUES (TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, 'DELETE',
                to_jsonb(OLD), NULL, actor);
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Attach to every authorization-config table. (audit_log itself is excluded
-- to avoid recursion; schema_versions is excluded as it is the migration
-- runner's bookkeeping, not auth state.)
CREATE TRIGGER audit_services
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.services
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_resources
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.resources
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_actions
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.actions
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_roles
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.roles
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_role_permissions
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.role_permissions
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_role_inherits
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.role_inherits
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_role_assignments
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.role_assignments
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_groups
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.groups
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_group_memberships
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.group_memberships
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_group_roles
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.group_roles
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

CREATE TRIGGER audit_memberships
    AFTER INSERT OR UPDATE OR DELETE ON gatedhouse.memberships
    FOR EACH ROW EXECUTE FUNCTION gatedhouse.audit_trigger();

-- =========================================================================
-- Seed: built-in owner role with full superuser permission (NULL wildcards)
-- =========================================================================

INSERT INTO gatedhouse.roles (key, name, description, is_system)
VALUES ('gatedhouse:owner', 'Owner', 'Built-in superuser role for org owners.', TRUE);

INSERT INTO gatedhouse.role_permissions (id, role_key, service, resource, action)
VALUES ('00000000-0000-0000-0000-000000000001',
        'gatedhouse:owner', NULL, NULL, NULL);
