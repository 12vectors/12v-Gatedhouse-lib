/**
 * Delegation cache — local cache of Sphinx delegation data.
 *
 * Delegation data is synced via Sphinx events and cached in the
 * service's own database for fast lookups during delegated agent requests.
 */

import { DatabaseConnection } from '../database/connection';
import { CachedDelegation } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('delegation-cache');

interface DelegationRow {
  delegation_id: string;
  agent_id: string;
  delegator_id: string;
  delegator_membership_id: string;
  org_id: string;
  scopes: string[];
  constraints: Record<string, unknown>;
  max_uses: number | null;
  use_count: number;
  status: string;
  expires_at: Date;
  synced_at: Date;
}

function toCachedDelegation(row: DelegationRow): CachedDelegation {
  return {
    delegationId: row.delegation_id,
    agentId: row.agent_id,
    delegatorId: row.delegator_id,
    delegatorMembershipId: row.delegator_membership_id,
    orgId: row.org_id,
    scopes: row.scopes,
    constraints: row.constraints,
    maxUses: row.max_uses,
    useCount: row.use_count,
    status: row.status,
    expiresAt: row.expires_at,
    syncedAt: row.synced_at,
  };
}

export class DelegationCache {
  constructor(private db: DatabaseConnection) {}

  /**
   * Upsert a delegation into the local cache.
   */
  async upsert(delegation: Omit<CachedDelegation, 'syncedAt'>): Promise<void> {
    await this.db.execute(
      `INSERT INTO gatedhouse_delegation_cache
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
         synced_at = now()`,
      [
        delegation.delegationId,
        delegation.agentId,
        delegation.delegatorId,
        delegation.delegatorMembershipId,
        delegation.orgId,
        delegation.scopes,
        JSON.stringify(delegation.constraints),
        delegation.maxUses,
        delegation.useCount,
        delegation.status,
        delegation.expiresAt,
      ],
    );
  }

  /**
   * Find an active delegation for an agent.
   */
  async findActiveForAgent(
    agentId: string,
    orgId: string,
  ): Promise<CachedDelegation | null> {
    const row = await this.db.queryOne<DelegationRow>(
      `SELECT * FROM gatedhouse_delegation_cache
       WHERE agent_id = $1 AND org_id = $2 AND status = 'active'
         AND expires_at > now()
         AND (max_uses IS NULL OR use_count < max_uses)
       ORDER BY synced_at DESC
       LIMIT 1`,
      [agentId, orgId],
    );
    return row ? toCachedDelegation(row) : null;
  }

  /**
   * Find a delegation by ID.
   */
  async findById(delegationId: string): Promise<CachedDelegation | null> {
    const row = await this.db.queryOne<DelegationRow>(
      'SELECT * FROM gatedhouse_delegation_cache WHERE delegation_id = $1',
      [delegationId],
    );
    return row ? toCachedDelegation(row) : null;
  }

  /**
   * Update delegation status.
   */
  async updateStatus(delegationId: string, status: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_delegation_cache
       SET status = $1, synced_at = now()
       WHERE delegation_id = $2`,
      [status, delegationId],
    );
    logger.info({ delegationId, status }, 'Delegation status updated');
  }

  /**
   * Increment use count for a delegation.
   */
  async incrementUseCount(delegationId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_delegation_cache
       SET use_count = use_count + 1, synced_at = now()
       WHERE delegation_id = $1`,
      [delegationId],
    );
  }

  /**
   * Revoke all delegations for an agent.
   */
  async revokeAllForAgent(agentId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_delegation_cache
       SET status = 'revoked', synced_at = now()
       WHERE agent_id = $1 AND status = 'active'`,
      [agentId],
    );
    logger.info({ agentId }, 'All delegations revoked for agent');
  }

  /**
   * Remove all delegations for an org.
   */
  async removeAllForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_delegation_cache WHERE org_id = $1',
      [orgId],
    );
  }
}
