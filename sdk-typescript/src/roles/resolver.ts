/**
 * Permission resolver — walks the role inheritance DAG and computes
 * the effective permission set for a membership.
 *
 * The resolver materializes permissions into the gatedhouse_resolved_permissions
 * table for fast lookups at request time.
 */

import { DatabaseConnection } from '../database/connection';
import { RoleRepository } from './repository';
import { RoleAssignmentManager } from './assignment';
import { ResolvedPermission, RoleSource } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('permission-resolver');

export class PermissionResolver {
  private customSources: Map<string, RoleSource> = new Map();

  constructor(
    private db: DatabaseConnection,
    private roleRepo: RoleRepository,
    private assignments: RoleAssignmentManager,
  ) {}

  /**
   * Register a custom role source for extending role resolution.
   */
  addSource(name: string, source: RoleSource): void {
    this.customSources.set(name, source);
  }

  /**
   * Resolve all effective roles for a membership (direct + group + custom sources).
   */
  async resolveRoles(
    membershipId: string,
    orgId: string,
    groups: string[],
  ): Promise<string[]> {
    const roleSet = new Set<string>();

    // Direct role assignments
    const directRoles = await this.assignments.getRoleIds(membershipId);
    for (const r of directRoles) roleSet.add(r);

    // Group role assignments
    const groupRoles = await this.assignments.getRoleIdsForGroups(groups);
    for (const r of groupRoles) roleSet.add(r);

    // Custom role sources
    for (const [name, source] of this.customSources) {
      try {
        const customRoles = await source(membershipId, orgId);
        for (const r of customRoles) roleSet.add(r);
      } catch (err) {
        logger.error({ err, source: name }, 'Custom role source failed');
      }
    }

    return Array.from(roleSet);
  }

  /**
   * Resolve all effective permissions for a membership by walking the
   * role inheritance DAG and unioning all permissions.
   */
  async resolvePermissions(
    membershipId: string,
    orgId: string,
    groups: string[],
  ): Promise<string[]> {
    const roles = await this.resolveRoles(membershipId, orgId, groups);
    const permissionSet = new Set<string>();
    const visited = new Set<string>();

    for (const roleId of roles) {
      await this.collectPermissions(orgId, roleId, permissionSet, visited);
    }

    return Array.from(permissionSet);
  }

  /**
   * Rebuild the materialized permission cache for a membership.
   */
  async rebuildForMembership(
    membershipId: string,
    orgId: string,
    groups: string[],
  ): Promise<string[]> {
    const roles = await this.resolveRoles(membershipId, orgId, groups);
    const permissionMap = new Map<string, string>(); // permission -> source
    const visited = new Set<string>();

    for (const roleId of roles) {
      await this.collectPermissionsWithSource(
        orgId,
        roleId,
        `direct`,
        permissionMap,
        visited,
      );
    }

    // Transactionally rebuild
    await this.db.execute('BEGIN');
    try {
      await this.db.execute(
        'DELETE FROM gatedhouse_resolved_permissions WHERE membership_id = $1',
        [membershipId],
      );

      if (permissionMap.size > 0) {
        const values: string[] = [];
        const params: unknown[] = [];
        let idx = 1;

        for (const [permission, source] of permissionMap) {
          values.push(`($${idx}, $${idx + 1}, $${idx + 2})`);
          params.push(membershipId, permission, source);
          idx += 3;
        }

        await this.db.execute(
          `INSERT INTO gatedhouse_resolved_permissions (membership_id, permission, source)
           VALUES ${values.join(', ')}
           ON CONFLICT (membership_id, permission) DO UPDATE SET source = EXCLUDED.source`,
          params,
        );
      }

      await this.db.execute('COMMIT');
    } catch (err) {
      await this.db.execute('ROLLBACK');
      throw err;
    }

    logger.debug(
      { membershipId, permissionCount: permissionMap.size },
      'Permissions rebuilt',
    );

    return Array.from(permissionMap.keys());
  }

  /**
   * Get cached resolved permissions for a membership.
   */
  async getCachedPermissions(membershipId: string): Promise<ResolvedPermission[]> {
    const rows = await this.db.query<{
      membership_id: string;
      permission: string;
      source: string;
    }>(
      'SELECT * FROM gatedhouse_resolved_permissions WHERE membership_id = $1',
      [membershipId],
    );
    return rows.map((r) => ({
      membershipId: r.membership_id,
      permission: r.permission,
      source: r.source,
    }));
  }

  /**
   * Delete cached permissions for a membership.
   */
  async clearForMembership(membershipId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_resolved_permissions WHERE membership_id = $1',
      [membershipId],
    );
  }

  /**
   * Recursively collect permissions by walking role inheritance.
   */
  private async collectPermissions(
    orgId: string,
    roleId: string,
    permissionSet: Set<string>,
    visited: Set<string>,
  ): Promise<void> {
    if (visited.has(roleId)) return; // Cycle detection
    visited.add(roleId);

    const role = await this.roleRepo.resolve(orgId, roleId);
    if (!role) {
      logger.warn({ orgId, roleId }, 'Role not found during resolution');
      return;
    }

    for (const perm of role.permissions) {
      permissionSet.add(perm);
    }

    // Walk inheritance chain
    for (const parentRoleId of role.inherits) {
      await this.collectPermissions(orgId, parentRoleId, permissionSet, visited);
    }
  }

  private async collectPermissionsWithSource(
    orgId: string,
    roleId: string,
    sourcePrefix: string,
    permissionMap: Map<string, string>,
    visited: Set<string>,
  ): Promise<void> {
    if (visited.has(roleId)) return;
    visited.add(roleId);

    const role = await this.roleRepo.resolve(orgId, roleId);
    if (!role) return;

    const source = `${sourcePrefix}:${roleId}`;
    for (const perm of role.permissions) {
      if (!permissionMap.has(perm)) {
        permissionMap.set(perm, source);
      }
    }

    for (const parentRoleId of role.inherits) {
      await this.collectPermissionsWithSource(
        orgId,
        parentRoleId,
        `inherited`,
        permissionMap,
        visited,
      );
    }
  }
}
