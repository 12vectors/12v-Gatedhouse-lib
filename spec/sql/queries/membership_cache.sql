-- ============================================================
-- Membership cache queries — shared across all SDKs
-- ============================================================

-- name: upsert_membership
INSERT INTO gatedhouse_membership_cache
    (membership_id, org_id, entity_type, entity_id, is_owner, status, groups, synced_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (membership_id) DO UPDATE SET
    org_id = EXCLUDED.org_id,
    entity_type = EXCLUDED.entity_type,
    entity_id = EXCLUDED.entity_id,
    is_owner = EXCLUDED.is_owner,
    status = EXCLUDED.status,
    groups = EXCLUDED.groups,
    synced_at = now();

-- name: find_membership_by_id
SELECT * FROM gatedhouse_membership_cache WHERE membership_id = $1;

-- name: find_membership_by_entity_and_org
SELECT * FROM gatedhouse_membership_cache
WHERE org_id = $1 AND entity_type = $2 AND entity_id = $3;

-- name: list_memberships_by_org
SELECT * FROM gatedhouse_membership_cache WHERE org_id = $1;

-- name: update_membership_status
UPDATE gatedhouse_membership_cache
SET status = $1, synced_at = now()
WHERE membership_id = $2;

-- name: add_group_to_membership
UPDATE gatedhouse_membership_cache
SET groups = array_append(groups, $1), synced_at = now()
WHERE membership_id = $2 AND NOT ($1 = ANY(groups));

-- name: remove_group_from_membership
UPDATE gatedhouse_membership_cache
SET groups = array_remove(groups, $1), synced_at = now()
WHERE membership_id = $2;

-- name: remove_membership
DELETE FROM gatedhouse_membership_cache WHERE membership_id = $1;

-- name: remove_all_memberships_for_org
DELETE FROM gatedhouse_membership_cache WHERE org_id = $1;

-- name: suspend_all_memberships_for_org
UPDATE gatedhouse_membership_cache
SET status = 'suspended', synced_at = now()
WHERE org_id = $1;

-- name: reactivate_all_memberships_for_org
UPDATE gatedhouse_membership_cache
SET status = 'active', synced_at = now()
WHERE org_id = $1 AND status = 'suspended';

-- name: remove_group_from_all_memberships
UPDATE gatedhouse_membership_cache
SET groups = array_remove(groups, $1), synced_at = now()
WHERE $1 = ANY(groups);
