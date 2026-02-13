/**
 * Membership cache — local cache of Citadel membership data.
 *
 * Membership data is synced via Citadel events and cached in the
 * service's own database for fast lookups during authorization.
 */

import { DatabaseConnection } from '../database/connection';
import { CachedMembership, EntityType } from '../types';
interface MembershipRow {
  membership_id: string;
  org_id: string;
  entity_type: string;
  entity_id: string;
  is_owner: boolean;
  status: string;
  groups: string[];
  synced_at: Date;
}

function toCachedMembership(row: MembershipRow): CachedMembership {
  return {
    membershipId: row.membership_id,
    orgId: row.org_id,
    entityType: row.entity_type as EntityType,
    entityId: row.entity_id,
    isOwner: row.is_owner,
    status: row.status,
    groups: row.groups,
    syncedAt: row.synced_at,
  };
}

export class MembershipCache {
  constructor(private db: DatabaseConnection) {}

  /**
   * Upsert a membership into the local cache.
   */
  async upsert(membership: Omit<CachedMembership, 'syncedAt'>): Promise<void> {
    await this.db.execute(
      `INSERT INTO gatedhouse_membership_cache
         (membership_id, org_id, entity_type, entity_id, is_owner, status, groups, synced_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now())
       ON CONFLICT (membership_id) DO UPDATE SET
         org_id = EXCLUDED.org_id,
         entity_type = EXCLUDED.entity_type,
         entity_id = EXCLUDED.entity_id,
         is_owner = EXCLUDED.is_owner,
         status = EXCLUDED.status,
         groups = EXCLUDED.groups,
         synced_at = now()`,
      [
        membership.membershipId,
        membership.orgId,
        membership.entityType,
        membership.entityId,
        membership.isOwner,
        membership.status,
        membership.groups,
      ],
    );
  }

  /**
   * Find a membership by ID.
   */
  async findById(membershipId: string): Promise<CachedMembership | null> {
    const row = await this.db.queryOne<MembershipRow>(
      'SELECT * FROM gatedhouse_membership_cache WHERE membership_id = $1',
      [membershipId],
    );
    return row ? toCachedMembership(row) : null;
  }

  /**
   * Find a membership by entity ID and org.
   */
  async findByEntityAndOrg(
    entityType: EntityType,
    entityId: string,
    orgId: string,
  ): Promise<CachedMembership | null> {
    const row = await this.db.queryOne<MembershipRow>(
      `SELECT * FROM gatedhouse_membership_cache
       WHERE org_id = $1 AND entity_type = $2 AND entity_id = $3`,
      [orgId, entityType, entityId],
    );
    return row ? toCachedMembership(row) : null;
  }

  /**
   * List all memberships for an org.
   */
  async listByOrg(orgId: string): Promise<CachedMembership[]> {
    const rows = await this.db.query<MembershipRow>(
      'SELECT * FROM gatedhouse_membership_cache WHERE org_id = $1',
      [orgId],
    );
    return rows.map(toCachedMembership);
  }

  /**
   * Update membership status.
   */
  async updateStatus(membershipId: string, status: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_membership_cache
       SET status = $1, synced_at = now()
       WHERE membership_id = $2`,
      [status, membershipId],
    );
  }

  /**
   * Update group membership.
   */
  async addGroup(membershipId: string, groupId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_membership_cache
       SET groups = array_append(groups, $1), synced_at = now()
       WHERE membership_id = $2 AND NOT ($1 = ANY(groups))`,
      [groupId, membershipId],
    );
  }

  async removeGroup(membershipId: string, groupId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_membership_cache
       SET groups = array_remove(groups, $1), synced_at = now()
       WHERE membership_id = $2`,
      [groupId, membershipId],
    );
  }

  /**
   * Remove a membership from the cache.
   */
  async remove(membershipId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_membership_cache WHERE membership_id = $1',
      [membershipId],
    );
  }

  /**
   * Remove all memberships for an org.
   */
  async removeAllForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_membership_cache WHERE org_id = $1',
      [orgId],
    );
  }

  /**
   * Suspend all memberships for an org.
   */
  async suspendAllForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_membership_cache
       SET status = 'suspended', synced_at = now()
       WHERE org_id = $1`,
      [orgId],
    );
  }

  /**
   * Reactivate all memberships for an org.
   */
  async reactivateAllForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_membership_cache
       SET status = 'active', synced_at = now()
       WHERE org_id = $1 AND status = 'suspended'`,
      [orgId],
    );
  }

  /**
   * Remove a group from all memberships (used when group is deleted).
   */
  async removeGroupFromAll(groupId: string): Promise<void> {
    await this.db.execute(
      `UPDATE gatedhouse_membership_cache
       SET groups = array_remove(groups, $1), synced_at = now()
       WHERE $1 = ANY(groups)`,
      [groupId],
    );
  }

  /**
   * Get the oldest sync timestamp (for staleness check on startup).
   */
  async getOldestSyncTime(): Promise<Date | null> {
    const row = await this.db.queryOne<{ oldest: Date }>(
      'SELECT MIN(synced_at) as oldest FROM gatedhouse_membership_cache',
    );
    return row?.oldest ?? null;
  }

  /**
   * Get membership count (for health checks).
   */
  async count(): Promise<number> {
    const row = await this.db.queryOne<{ count: string }>(
      'SELECT COUNT(*) as count FROM gatedhouse_membership_cache',
    );
    return parseInt(row?.count ?? '0', 10);
  }
}
