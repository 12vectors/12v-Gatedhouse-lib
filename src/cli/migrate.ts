#!/usr/bin/env node

/**
 * CLI migration runner.
 *
 * Usage:
 *   npx gatedhouse migrate --database-url $DATABASE_URL
 *   npx gatedhouse migrate --rollback 0
 */

import { DatabaseConnection } from '../database/connection';
import { MigrationRunner } from '../database/migrations';
import { resolveConfig } from '../config';

async function main() {
  const args = process.argv.slice(2);
  const dbUrl =
    getArg(args, '--database-url') ?? process.env.DATABASE_URL;

  if (!dbUrl) {
    console.error(
      'Error: --database-url argument or DATABASE_URL env var required',
    );
    process.exit(1);
  }

  const config = resolveConfig({
    jwksUrl: 'http://placeholder',
    database: { connectionString: dbUrl },
    service: 'cli',
  });

  const db = new DatabaseConnection(config);
  const runner = new MigrationRunner(db, config.database.migrationsTable);

  try {
    const rollbackTarget = getArg(args, '--rollback');
    if (rollbackTarget !== undefined) {
      const target = parseInt(rollbackTarget, 10);
      console.log(`Rolling back to version ${target}...`);
      await runner.rollback(target);
      console.log('Rollback complete.');
    } else {
      console.log('Running migrations...');
      await runner.run();
      console.log('Migrations complete.');
    }
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    await db.close();
  }
}

function getArg(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

main();
