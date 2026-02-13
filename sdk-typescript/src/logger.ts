/**
 * Logger factory using pino.
 */

import pino from 'pino';

const rootLogger = pino({
  name: 'gatedhouse',
  level: process.env.GATEDHOUSE_LOG_LEVEL ?? 'info',
});

export function createLogger(module: string): pino.Logger {
  return rootLogger.child({ module });
}

export { rootLogger };
