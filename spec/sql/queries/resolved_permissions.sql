-- ============================================================
-- Resolved permissions cache queries — shared across all SDKs
-- ============================================================

-- name: get_resolved_permissions
SELECT * FROM gatedhouse_resolved_permissions WHERE membership_id = $1;

-- name: clear_resolved_permissions
DELETE FROM gatedhouse_resolved_permissions WHERE membership_id = $1;

-- name: register_permission
INSERT INTO gatedhouse_permissions (key, description)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description;

-- name: get_all_permissions
SELECT key FROM gatedhouse_permissions ORDER BY key;
