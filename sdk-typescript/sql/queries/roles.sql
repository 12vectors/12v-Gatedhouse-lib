-- ============================================================
-- Role queries — shared across all SDKs
-- Parameter placeholders use $N (PostgreSQL positional params)
-- ============================================================

-- name: seed_role
-- Insert a base role for an org, skip if already exists
INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, id) DO NOTHING;

-- name: upsert_role
-- Insert or update a role definition
INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
VALUES ($1, $2, $3, $4, $5, $6, false)
ON CONFLICT (org_id, id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    permissions = EXCLUDED.permissions,
    inherits = EXCLUDED.inherits,
    updated_at = now();

-- name: find_role_by_id
SELECT * FROM gatedhouse_roles WHERE org_id = $1 AND id = $2;

-- name: list_roles_for_org
-- Includes both org-specific and system roles
SELECT * FROM gatedhouse_roles
WHERE org_id IN ($1, '__system__')
ORDER BY is_system DESC, name;

-- name: create_role
INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
VALUES ($1, $2, $3, $4, $5, $6, false)
RETURNING *;

-- name: delete_role
-- Only custom roles can be deleted
DELETE FROM gatedhouse_roles WHERE org_id = $1 AND id = $2 AND is_system = false;

-- name: delete_all_roles_for_org
DELETE FROM gatedhouse_roles WHERE org_id = $1;
