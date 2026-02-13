/**
 * Role assignment operations — assigning/revoking roles for memberships and groups.
 */

import { DatabaseConnection } from '../database/connection';
import { RoleAssignment, GroupRoleAssignment } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('role-assignment');

interface AssignmentRow {
  membership_id: string;
  role_id: string;
  org_id: string;
  assigned_by: string | null;
  assigned_at: Date;
}

interface GroupRoleRow {
  group_id: string;
  role_id: string;
  org_id: string;
  assigned_by: string | null;
  assigned_at: Date;
}

function toAssignment(row: AssignmentRow): RoleAssignment {
  return {
    membershipId: row.membership_id,
    roleId: row.role_id,
    orgId: row.org_id,
    assignedBy: row.assigned_by,
    assignedAt: row.assigned_at,
  };
}

function toGroupAssignment(row: GroupRoleRow): GroupRoleAssignment {
  return {
    groupId: row.group_id,
    roleId: row.role_id,
    orgId: row.org_id,
    assignedBy: row.assigned_by,
    assignedAt: row.assigned_at,
  };
}

export class RoleAssignmentManager {
  constructor(private db: DatabaseConnection) {}

  // ─── Membership Role Assignments ───────────────────────────────

  async assign(
    membershipId: string,
    roleId: string,
    orgId: string,
    assignedBy?: string,
  ): Promise<void> {
    await this.db.execute(
      `INSERT INTO gatedhouse_role_assignments (membership_id, role_id, org_id, assigned_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (membership_id, role_id) DO NOTHING`,
      [membershipId, roleId, orgId, assignedBy ?? null],
    );
    logger.info({ membershipId, roleId, orgId }, 'Role assigned');
  }

  async revoke(membershipId: string, roleId: string): Promise<boolean> {
    const count = await this.db.execute(
      'DELETE FROM gatedhouse_role_assignments WHERE membership_id = $1 AND role_id = $2',
      [membershipId, roleId],
    );
    if (count > 0) {
      logger.info({ membershipId, roleId }, 'Role revoked');
    }
    return count > 0;
  }

  async forMembership(membershipId: string): Promise<RoleAssignment[]> {
    const rows = await this.db.query<AssignmentRow>(
      'SELECT * FROM gatedhouse_role_assignments WHERE membership_id = $1',
      [membershipId],
    );
    return rows.map(toAssignment);
  }

  async getRoleIds(membershipId: string): Promise<string[]> {
    const rows = await this.db.query<{ role_id: string }>(
      'SELECT role_id FROM gatedhouse_role_assignments WHERE membership_id = $1',
      [membershipId],
    );
    return rows.map((r) => r.role_id);
  }

  async has(membershipId: string, roleId: string): Promise<boolean> {
    const row = await this.db.queryOne(
      'SELECT 1 FROM gatedhouse_role_assignments WHERE membership_id = $1 AND role_id = $2',
      [membershipId, roleId],
    );
    return row !== null;
  }

  async membershipsWithRole(orgId: string, roleId: string): Promise<string[]> {
    const rows = await this.db.query<{ membership_id: string }>(
      'SELECT membership_id FROM gatedhouse_role_assignments WHERE org_id = $1 AND role_id = $2',
      [orgId, roleId],
    );
    return rows.map((r) => r.membership_id);
  }

  async deleteAllForMembership(membershipId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_role_assignments WHERE membership_id = $1',
      [membershipId],
    );
  }

  async deleteAllForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_role_assignments WHERE org_id = $1',
      [orgId],
    );
  }

  // ─── Group Role Assignments ────────────────────────────────────

  async assignToGroup(
    groupId: string,
    roleId: string,
    orgId: string,
    assignedBy?: string,
  ): Promise<void> {
    await this.db.execute(
      `INSERT INTO gatedhouse_group_roles (group_id, role_id, org_id, assigned_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (group_id, role_id) DO NOTHING`,
      [groupId, roleId, orgId, assignedBy ?? null],
    );
    logger.info({ groupId, roleId, orgId }, 'Role assigned to group');
  }

  async revokeFromGroup(groupId: string, roleId: string): Promise<boolean> {
    const count = await this.db.execute(
      'DELETE FROM gatedhouse_group_roles WHERE group_id = $1 AND role_id = $2',
      [groupId, roleId],
    );
    return count > 0;
  }

  async forGroup(groupId: string): Promise<GroupRoleAssignment[]> {
    const rows = await this.db.query<GroupRoleRow>(
      'SELECT * FROM gatedhouse_group_roles WHERE group_id = $1',
      [groupId],
    );
    return rows.map(toGroupAssignment);
  }

  async getGroupRoleIds(groupId: string): Promise<string[]> {
    const rows = await this.db.query<{ role_id: string }>(
      'SELECT role_id FROM gatedhouse_group_roles WHERE group_id = $1',
      [groupId],
    );
    return rows.map((r) => r.role_id);
  }

  async getRoleIdsForGroups(groupIds: string[]): Promise<string[]> {
    if (groupIds.length === 0) return [];

    const placeholders = groupIds.map((_, i) => `$${i + 1}`).join(', ');
    const rows = await this.db.query<{ role_id: string }>(
      `SELECT DISTINCT role_id FROM gatedhouse_group_roles WHERE group_id IN (${placeholders})`,
      groupIds,
    );
    return rows.map((r) => r.role_id);
  }

  async deleteAllForGroup(groupId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_group_roles WHERE group_id = $1',
      [groupId],
    );
  }

  async deleteAllGroupRolesForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_group_roles WHERE org_id = $1',
      [orgId],
    );
  }
}
