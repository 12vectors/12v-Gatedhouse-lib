/**
 * Permission registry for tracking known permissions per service.
 */

import { DatabaseConnection } from '../database/connection';
import { createLogger } from '../logger';

const logger = createLogger('permission-registry');

export class PermissionRegistry {
  private registeredPermissions: Set<string> = new Set();

  constructor(private db: DatabaseConnection) {}

  /**
   * Register permissions for this service.
   */
  async register(permissions: Array<{ key: string; description?: string }>): Promise<void> {
    if (permissions.length === 0) return;

    const values: string[] = [];
    const params: unknown[] = [];
    let idx = 1;

    for (const perm of permissions) {
      values.push(`($${idx}, $${idx + 1})`);
      params.push(perm.key, perm.description ?? null);
      idx += 2;
      this.registeredPermissions.add(perm.key);
    }

    await this.db.execute(
      `INSERT INTO gatedhouse_permissions (key, description)
       VALUES ${values.join(', ')}
       ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description`,
      params,
    );

    logger.info({ count: permissions.length }, 'Permissions registered');
  }

  /**
   * Get all registered permission keys.
   */
  async getAll(): Promise<string[]> {
    const rows = await this.db.query<{ key: string }>(
      'SELECT key FROM gatedhouse_permissions ORDER BY key',
    );
    const keys = rows.map((r) => r.key);
    this.registeredPermissions = new Set(keys);
    return keys;
  }

  /**
   * Get the in-memory set of known permissions (for wildcard expansion).
   */
  getKnownPermissions(): string[] {
    return Array.from(this.registeredPermissions);
  }
}
