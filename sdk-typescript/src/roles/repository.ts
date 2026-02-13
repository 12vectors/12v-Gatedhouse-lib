/**
 * Role repository — CRUD operations for role definitions.
 */

import { DatabaseConnection } from '../database/connection';
import { StoredRole, RoleDefinition } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('role-repository');

interface RoleRow {
  id: string;
  org_id: string;
  name: string;
  description: string | null;
  permissions: string[];
  inherits: string[];
  is_system: boolean;
  created_at: Date;
  updated_at: Date;
}

function toStoredRole(row: RoleRow): StoredRole {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    description: row.description,
    permissions: row.permissions,
    inherits: row.inherits,
    isSystem: row.is_system,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class RoleRepository {
  constructor(private db: DatabaseConnection) {}

  /**
   * Seed base roles for an organization.
   */
  async seedBaseRoles(orgId: string, roles: RoleDefinition[]): Promise<void> {
    for (const role of roles) {
      await this.db.execute(
        `INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (org_id, id) DO NOTHING`,
        [
          role.key,
          orgId,
          role.name,
          role.description ?? null,
          role.permissions,
          role.inherits ?? [],
          role.isSystem ?? false,
        ],
      );
    }
    logger.info({ orgId, count: roles.length }, 'Base roles seeded');
  }

  /**
   * Define custom roles (service-specific).
   */
  async define(orgId: string, roles: RoleDefinition[]): Promise<void> {
    for (const role of roles) {
      await this.db.execute(
        `INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
         VALUES ($1, $2, $3, $4, $5, $6, false)
         ON CONFLICT (org_id, id) DO UPDATE SET
           name = EXCLUDED.name,
           description = EXCLUDED.description,
           permissions = EXCLUDED.permissions,
           inherits = EXCLUDED.inherits,
           updated_at = now()`,
        [
          role.key,
          orgId,
          role.name,
          role.description ?? null,
          role.permissions,
          role.inherits ?? [],
        ],
      );
    }
    logger.info({ orgId, count: roles.length }, 'Roles defined');
  }

  /**
   * Get a single role by ID and org.
   */
  async findById(orgId: string, roleId: string): Promise<StoredRole | null> {
    const row = await this.db.queryOne<RoleRow>(
      'SELECT * FROM gatedhouse_roles WHERE org_id = $1 AND id = $2',
      [orgId, roleId],
    );
    return row ? toStoredRole(row) : null;
  }

  /**
   * Find a role across system and org-specific definitions.
   * Checks org-specific first, then falls back to __system__.
   */
  async resolve(orgId: string, roleId: string): Promise<StoredRole | null> {
    const orgRole = await this.findById(orgId, roleId);
    if (orgRole) return orgRole;
    return this.findById('__system__', roleId);
  }

  /**
   * List all roles available for an organization (org-specific + system).
   */
  async listForOrg(orgId: string): Promise<StoredRole[]> {
    const rows = await this.db.query<RoleRow>(
      `SELECT * FROM gatedhouse_roles
       WHERE org_id IN ($1, '__system__')
       ORDER BY is_system DESC, name`,
      [orgId],
    );
    return rows.map(toStoredRole);
  }

  /**
   * Create a custom role.
   */
  async create(orgId: string, role: RoleDefinition): Promise<StoredRole> {
    const rows = await this.db.query<RoleRow>(
      `INSERT INTO gatedhouse_roles (id, org_id, name, description, permissions, inherits, is_system)
       VALUES ($1, $2, $3, $4, $5, $6, false)
       RETURNING *`,
      [
        role.key,
        orgId,
        role.name,
        role.description ?? null,
        role.permissions,
        role.inherits ?? [],
      ],
    );
    return toStoredRole(rows[0]);
  }

  /**
   * Update a custom role.
   */
  async update(
    orgId: string,
    roleId: string,
    updates: Partial<Pick<RoleDefinition, 'name' | 'description' | 'permissions' | 'inherits'>>,
  ): Promise<StoredRole | null> {
    const setClauses: string[] = [];
    const params: unknown[] = [];
    let idx = 3;

    if (updates.name !== undefined) {
      setClauses.push(`name = $${idx}`);
      params.push(updates.name);
      idx++;
    }
    if (updates.description !== undefined) {
      setClauses.push(`description = $${idx}`);
      params.push(updates.description);
      idx++;
    }
    if (updates.permissions !== undefined) {
      setClauses.push(`permissions = $${idx}`);
      params.push(updates.permissions);
      idx++;
    }
    if (updates.inherits !== undefined) {
      setClauses.push(`inherits = $${idx}`);
      params.push(updates.inherits);
      idx++;
    }

    if (setClauses.length === 0) return this.findById(orgId, roleId);

    setClauses.push('updated_at = now()');

    const rows = await this.db.query<RoleRow>(
      `UPDATE gatedhouse_roles SET ${setClauses.join(', ')}
       WHERE org_id = $1 AND id = $2 AND is_system = false
       RETURNING *`,
      [orgId, roleId, ...params],
    );

    return rows.length > 0 ? toStoredRole(rows[0]) : null;
  }

  /**
   * Delete a custom role. System roles cannot be deleted.
   */
  async delete(orgId: string, roleId: string): Promise<boolean> {
    const count = await this.db.execute(
      'DELETE FROM gatedhouse_roles WHERE org_id = $1 AND id = $2 AND is_system = false',
      [orgId, roleId],
    );
    return count > 0;
  }

  /**
   * Delete all roles for an organization (used on org deletion).
   */
  async deleteAllForOrg(orgId: string): Promise<void> {
    await this.db.execute(
      'DELETE FROM gatedhouse_roles WHERE org_id = $1',
      [orgId],
    );
  }
}
