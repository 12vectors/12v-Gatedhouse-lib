/**
 * Database connection management using pg Pool.
 */

import { Pool, PoolConfig } from 'pg';
import { ResolvedConfig } from '../config';
import { createLogger } from '../logger';

const logger = createLogger('database');

export class DatabaseConnection {
  private pool: Pool;

  constructor(config: ResolvedConfig) {
    const poolConfig: PoolConfig = {
      connectionString: config.database.connectionString,
      min: config.database.poolMin,
      max: config.database.poolMax,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    };

    this.pool = new Pool(poolConfig);

    this.pool.on('error', (err) => {
      logger.error({ err }, 'Unexpected pool error');
    });
  }

  getPool(): Pool {
    return this.pool;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async query<T = any>(
    text: string,
    params?: unknown[],
  ): Promise<T[]> {
    const result = await this.pool.query(text, params);
    return result.rows as T[];
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async queryOne<T = any>(
    text: string,
    params?: unknown[],
  ): Promise<T | null> {
    const rows = await this.query<T>(text, params);
    return rows[0] ?? null;
  }

  async execute(text: string, params?: unknown[]): Promise<number> {
    const result = await this.pool.query(text, params);
    return result.rowCount ?? 0;
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    logger.info('Database connection pool closed');
  }
}
