/**
 * Database migration runner.
 *
 * Manages schema migrations for Gatedhouse tables. Each migration
 * is tracked in a migrations table to ensure idempotent application.
 */

import { DatabaseConnection } from './connection';
import { createLogger } from '../logger';

const logger = createLogger('migrations');

export interface Migration {
  version: number;
  name: string;
  up: string;
  down: string;
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'initial_schema',
    up: `
      -- Role definitions (service-specific)
      CREATE TABLE IF NOT EXISTS gatedhouse_roles (
        id          TEXT NOT NULL,
        org_id      TEXT NOT NULL,
        name        TEXT NOT NULL,
        description TEXT,
        permissions TEXT[] NOT NULL DEFAULT '{}',
        inherits    TEXT[] NOT NULL DEFAULT '{}',
        is_system   BOOLEAN NOT NULL DEFAULT false,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, id)
      );
      CREATE INDEX IF NOT EXISTS idx_gh_roles_org ON gatedhouse_roles(org_id);

      -- Role assignments (membership -> role)
      CREATE TABLE IF NOT EXISTS gatedhouse_role_assignments (
        membership_id TEXT NOT NULL,
        role_id       TEXT NOT NULL,
        org_id        TEXT NOT NULL,
        assigned_by   TEXT,
        assigned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (membership_id, role_id)
      );
      CREATE INDEX IF NOT EXISTS idx_gh_assignments_org ON gatedhouse_role_assignments(org_id);
      CREATE INDEX IF NOT EXISTS idx_gh_assignments_role ON gatedhouse_role_assignments(role_id);

      -- Group role assignments (group -> role)
      CREATE TABLE IF NOT EXISTS gatedhouse_group_roles (
        group_id    TEXT NOT NULL,
        role_id     TEXT NOT NULL,
        org_id      TEXT NOT NULL,
        assigned_by TEXT,
        assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (group_id, role_id)
      );
      CREATE INDEX IF NOT EXISTS idx_gh_group_roles_org ON gatedhouse_group_roles(org_id);

      -- Registered permissions (service-specific)
      CREATE TABLE IF NOT EXISTS gatedhouse_permissions (
        key           TEXT PRIMARY KEY,
        description   TEXT,
        registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      -- Membership cache (synced from Citadel events)
      CREATE TABLE IF NOT EXISTS gatedhouse_membership_cache (
        membership_id TEXT PRIMARY KEY,
        org_id        TEXT NOT NULL,
        entity_type   TEXT NOT NULL,
        entity_id     TEXT NOT NULL,
        is_owner      BOOLEAN NOT NULL DEFAULT false,
        status        TEXT NOT NULL,
        groups        TEXT[] NOT NULL DEFAULT '{}',
        synced_at     TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS idx_gh_cache_org_entity
        ON gatedhouse_membership_cache(org_id, entity_type, entity_id);
      CREATE INDEX IF NOT EXISTS idx_gh_cache_entity
        ON gatedhouse_membership_cache(entity_type, entity_id);

      -- Delegation cache (synced from Sphinx events)
      CREATE TABLE IF NOT EXISTS gatedhouse_delegation_cache (
        delegation_id           TEXT PRIMARY KEY,
        agent_id                TEXT NOT NULL,
        delegator_id            TEXT NOT NULL,
        delegator_membership_id TEXT NOT NULL,
        org_id                  TEXT NOT NULL,
        scopes                  TEXT[] NOT NULL,
        constraints             JSONB NOT NULL DEFAULT '{}',
        max_uses                INTEGER,
        use_count               INTEGER NOT NULL DEFAULT 0,
        status                  TEXT NOT NULL,
        expires_at              TIMESTAMPTZ NOT NULL,
        synced_at               TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS idx_gh_delegation_agent
        ON gatedhouse_delegation_cache(agent_id, status);
      CREATE INDEX IF NOT EXISTS idx_gh_delegation_delegator
        ON gatedhouse_delegation_cache(delegator_id);

      -- Resolved permissions cache (materialized for fast lookups)
      CREATE TABLE IF NOT EXISTS gatedhouse_resolved_permissions (
        membership_id TEXT NOT NULL,
        permission    TEXT NOT NULL,
        source        TEXT NOT NULL,
        PRIMARY KEY (membership_id, permission)
      );
      CREATE INDEX IF NOT EXISTS idx_gh_resolved_membership
        ON gatedhouse_resolved_permissions(membership_id);
    `,
    down: `
      DROP TABLE IF EXISTS gatedhouse_resolved_permissions;
      DROP TABLE IF EXISTS gatedhouse_delegation_cache;
      DROP TABLE IF EXISTS gatedhouse_membership_cache;
      DROP TABLE IF EXISTS gatedhouse_permissions;
      DROP TABLE IF EXISTS gatedhouse_group_roles;
      DROP TABLE IF EXISTS gatedhouse_role_assignments;
      DROP TABLE IF EXISTS gatedhouse_roles;
    `,
  },
];

export class MigrationRunner {
  private migrationsTable: string;

  constructor(
    private db: DatabaseConnection,
    migrationsTable: string = 'gatedhouse_migrations',
  ) {
    this.migrationsTable = migrationsTable;
  }

  async run(): Promise<void> {
    await this.ensureMigrationsTable();

    const applied = await this.getAppliedVersions();
    const pending = MIGRATIONS.filter((m) => !applied.has(m.version));

    if (pending.length === 0) {
      logger.info('No pending migrations');
      return;
    }

    logger.info({ count: pending.length }, 'Running pending migrations');

    for (const migration of pending) {
      logger.info(
        { version: migration.version, name: migration.name },
        'Applying migration',
      );

      await this.db.execute('BEGIN');
      try {
        await this.db.execute(migration.up);
        await this.db.execute(
          `INSERT INTO ${this.migrationsTable} (version, name, applied_at) VALUES ($1, $2, now())`,
          [migration.version, migration.name],
        );
        await this.db.execute('COMMIT');
        logger.info(
          { version: migration.version, name: migration.name },
          'Migration applied',
        );
      } catch (err) {
        await this.db.execute('ROLLBACK');
        logger.error(
          { err, version: migration.version, name: migration.name },
          'Migration failed',
        );
        throw err;
      }
    }
  }

  async rollback(targetVersion: number): Promise<void> {
    const applied = await this.getAppliedVersions();
    const toRollback = MIGRATIONS.filter(
      (m) => applied.has(m.version) && m.version > targetVersion,
    ).sort((a, b) => b.version - a.version);

    for (const migration of toRollback) {
      logger.info(
        { version: migration.version, name: migration.name },
        'Rolling back migration',
      );

      await this.db.execute('BEGIN');
      try {
        await this.db.execute(migration.down);
        await this.db.execute(
          `DELETE FROM ${this.migrationsTable} WHERE version = $1`,
          [migration.version],
        );
        await this.db.execute('COMMIT');
      } catch (err) {
        await this.db.execute('ROLLBACK');
        throw err;
      }
    }
  }

  private async ensureMigrationsTable(): Promise<void> {
    await this.db.execute(`
      CREATE TABLE IF NOT EXISTS ${this.migrationsTable} (
        version    INTEGER PRIMARY KEY,
        name       TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
  }

  private async getAppliedVersions(): Promise<Set<number>> {
    const rows = await this.db.query<{ version: number }>(
      `SELECT version FROM ${this.migrationsTable} ORDER BY version`,
    );
    return new Set(rows.map((r) => r.version));
  }
}
