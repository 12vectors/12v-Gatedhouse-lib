-- ============================================================
-- Delegation cache queries — shared across all SDKs
-- ============================================================

-- name: upsert_delegation
INSERT INTO gatedhouse_delegation_cache
    (delegation_id, agent_id, delegator_id, delegator_membership_id,
     org_id, scopes, constraints, max_uses, use_count, status, expires_at, synced_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
ON CONFLICT (delegation_id) DO UPDATE SET
    agent_id = EXCLUDED.agent_id,
    delegator_id = EXCLUDED.delegator_id,
    delegator_membership_id = EXCLUDED.delegator_membership_id,
    org_id = EXCLUDED.org_id,
    scopes = EXCLUDED.scopes,
    constraints = EXCLUDED.constraints,
    max_uses = EXCLUDED.max_uses,
    use_count = EXCLUDED.use_count,
    status = EXCLUDED.status,
    expires_at = EXCLUDED.expires_at,
    synced_at = now();

-- name: find_active_delegation_for_agent
SELECT * FROM gatedhouse_delegation_cache
WHERE agent_id = $1 AND org_id = $2 AND status = 'active'
    AND expires_at > now()
    AND (max_uses IS NULL OR use_count < max_uses)
ORDER BY synced_at DESC
LIMIT 1;

-- name: find_delegation_by_id
SELECT * FROM gatedhouse_delegation_cache WHERE delegation_id = $1;

-- name: update_delegation_status
UPDATE gatedhouse_delegation_cache
SET status = $1, synced_at = now()
WHERE delegation_id = $2;

-- name: increment_delegation_use_count
UPDATE gatedhouse_delegation_cache
SET use_count = use_count + 1, synced_at = now()
WHERE delegation_id = $1;

-- name: revoke_all_delegations_for_agent
UPDATE gatedhouse_delegation_cache
SET status = 'revoked', synced_at = now()
WHERE agent_id = $1 AND status = 'active';

-- name: remove_all_delegations_for_org
DELETE FROM gatedhouse_delegation_cache WHERE org_id = $1;
