-- ============================================================
-- Role assignment queries — shared across all SDKs
-- ============================================================

-- name: assign_role_to_membership
INSERT INTO gatedhouse_role_assignments (membership_id, role_id, org_id, assigned_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (membership_id, role_id) DO NOTHING;

-- name: revoke_role_from_membership
DELETE FROM gatedhouse_role_assignments WHERE membership_id = $1 AND role_id = $2;

-- name: get_role_ids_for_membership
SELECT role_id FROM gatedhouse_role_assignments WHERE membership_id = $1;

-- name: has_role
SELECT 1 FROM gatedhouse_role_assignments WHERE membership_id = $1 AND role_id = $2;

-- name: memberships_with_role
SELECT membership_id FROM gatedhouse_role_assignments WHERE org_id = $1 AND role_id = $2;

-- name: delete_all_assignments_for_membership
DELETE FROM gatedhouse_role_assignments WHERE membership_id = $1;

-- name: delete_all_assignments_for_org
DELETE FROM gatedhouse_role_assignments WHERE org_id = $1;

-- name: assign_role_to_group
INSERT INTO gatedhouse_group_roles (group_id, role_id, org_id, assigned_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (group_id, role_id) DO NOTHING;

-- name: revoke_role_from_group
DELETE FROM gatedhouse_group_roles WHERE group_id = $1 AND role_id = $2;

-- name: get_role_ids_for_group
SELECT role_id FROM gatedhouse_group_roles WHERE group_id = $1;

-- name: get_role_ids_for_groups
-- Note: SDK must dynamically build the IN clause for the group_ids array
SELECT DISTINCT role_id FROM gatedhouse_group_roles WHERE group_id = ANY($1);

-- name: delete_all_group_roles_for_group
DELETE FROM gatedhouse_group_roles WHERE group_id = $1;

-- name: delete_all_group_roles_for_org
DELETE FROM gatedhouse_group_roles WHERE org_id = $1;
