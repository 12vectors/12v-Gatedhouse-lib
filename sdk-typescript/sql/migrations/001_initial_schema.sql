-- Gatedhouse v1: Initial Schema
-- This SQL is shared across ALL language SDKs. Each SDK wraps it
-- in its own migration runner but the DDL is identical.

-- Role definitions (service-specific)
CREATE TABLE IF NOT EXISTS gatedhouse_roles (
    id          TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    inherits    TEXT[] NOT NULL DEFAULT '{}',
    is_system   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id)
);
CREATE INDEX IF NOT EXISTS idx_gh_roles_org ON gatedhouse_roles(org_id);

-- Role assignments (membership -> role)
CREATE TABLE IF NOT EXISTS gatedhouse_role_assignments (
    membership_id TEXT NOT NULL,
    role_id       TEXT NOT NULL,
    org_id        TEXT NOT NULL,
    assigned_by   TEXT,
    assigned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (membership_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_gh_assignments_org ON gatedhouse_role_assignments(org_id);
CREATE INDEX IF NOT EXISTS idx_gh_assignments_role ON gatedhouse_role_assignments(role_id);

-- Group role assignments (group -> role)
CREATE TABLE IF NOT EXISTS gatedhouse_group_roles (
    group_id    TEXT NOT NULL,
    role_id     TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    assigned_by TEXT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_gh_group_roles_org ON gatedhouse_group_roles(org_id);

-- Registered permissions (service-specific)
CREATE TABLE IF NOT EXISTS gatedhouse_permissions (
    key           TEXT PRIMARY KEY,
    description   TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Membership cache (synced from Citadel events)
CREATE TABLE IF NOT EXISTS gatedhouse_membership_cache (
    membership_id TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    is_owner      BOOLEAN NOT NULL DEFAULT false,
    status        TEXT NOT NULL,
    groups        TEXT[] NOT NULL DEFAULT '{}',
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gh_cache_org_entity
    ON gatedhouse_membership_cache(org_id, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_gh_cache_entity
    ON gatedhouse_membership_cache(entity_type, entity_id);

-- Delegation cache (synced from Sphinx events)
CREATE TABLE IF NOT EXISTS gatedhouse_delegation_cache (
    delegation_id           TEXT PRIMARY KEY,
    agent_id                TEXT NOT NULL,
    delegator_id            TEXT NOT NULL,
    delegator_membership_id TEXT NOT NULL,
    org_id                  TEXT NOT NULL,
    scopes                  TEXT[] NOT NULL,
    constraints             JSONB NOT NULL DEFAULT '{}',
    max_uses                INTEGER,
    use_count               INTEGER NOT NULL DEFAULT 0,
    status                  TEXT NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    synced_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gh_delegation_agent
    ON gatedhouse_delegation_cache(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_gh_delegation_delegator
    ON gatedhouse_delegation_cache(delegator_id);

-- Resolved permissions cache (materialized for fast lookups)
CREATE TABLE IF NOT EXISTS gatedhouse_resolved_permissions (
    membership_id TEXT NOT NULL,
    permission    TEXT NOT NULL,
    source        TEXT NOT NULL,
    PRIMARY KEY (membership_id, permission)
);
CREATE INDEX IF NOT EXISTS idx_gh_resolved_membership
    ON gatedhouse_resolved_permissions(membership_id);
