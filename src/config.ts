/**
 * Gatedhouse configuration types and validation.
 */

import { RoleDefinition } from './types';

export interface DatabaseConfig {
  connectionString: string;
  migrationsTable?: string;
  tablePrefix?: string;
  poolMin?: number;
  poolMax?: number;
}

export interface EventBusConfig {
  adapter: 'kafka' | 'rabbitmq' | 'in_memory' | 'noop';
  topics?: string[];
  /** Kafka-specific */
  brokers?: string[];
  groupId?: string;
  /** RabbitMQ-specific */
  url?: string;
  exchange?: string;
}

export interface AuditConfig {
  enabled?: boolean;
  logDenied?: boolean;
  logAllowed?: boolean;
}

export interface DelegationConfig {
  enabled?: boolean;
  cacheTtl?: number;
  validateLive?: boolean;
  allowedIdentityTypes?: string[];
}

export interface GatehouseConfig {
  /** Sphinx JWKS endpoint for JWT verification */
  jwksUrl: string;
  /** JWKS cache TTL in seconds (default: 3600) */
  jwksCacheTtl?: number;

  /** Database configuration */
  database: DatabaseConfig;

  /** Event bus configuration */
  eventBus?: EventBusConfig;

  /** Service identity used in permission keys */
  service: string;

  /** Org context header name (default: 'X-Org-Id') */
  orgHeader?: string;
  /** Whether org context is required (default: true) */
  orgRequired?: boolean;

  /** Cache miss strategy: 'fetch' queries Citadel, 'deny' fails closed (default: 'fetch') */
  cacheMissStrategy?: 'fetch' | 'deny';
  /** Cache miss result TTL in seconds (default: 60) */
  cacheMissTtl?: number;
  /** Resolved permissions cache TTL in seconds (default: 300) */
  resolvedPermissionsCacheTtl?: number;

  /** Audit configuration */
  audit?: AuditConfig;

  /** Base roles to seed on org creation (default: owner, admin, member, viewer) */
  baseRoles?: RoleDefinition[];
  /** Default role for new memberships (default: 'member') */
  defaultRole?: string;

  /** Citadel API base URL for cache miss fallback */
  citadelBaseUrl?: string;

  /** Delegation support configuration */
  delegation?: DelegationConfig;
}

const DEFAULT_BASE_ROLES: RoleDefinition[] = [
  {
    key: 'owner',
    name: 'Owner',
    description: 'Organization owner with full access',
    permissions: ['*:*:*'],
    isSystem: true,
  },
  {
    key: 'admin',
    name: 'Administrator',
    description: 'Organization administrator with full access except ownership transfer',
    permissions: ['*:*:*'],
    isSystem: true,
  },
  {
    key: 'member',
    name: 'Member',
    description: 'Regular organization member with standard access',
    permissions: [],
    isSystem: true,
  },
  {
    key: 'viewer',
    name: 'Viewer',
    description: 'Read-only access',
    permissions: [],
    isSystem: true,
  },
];

export interface ResolvedConfig {
  jwksUrl: string;
  jwksCacheTtl: number;
  database: Required<DatabaseConfig>;
  eventBus: EventBusConfig;
  service: string;
  orgHeader: string;
  orgRequired: boolean;
  cacheMissStrategy: 'fetch' | 'deny';
  cacheMissTtl: number;
  resolvedPermissionsCacheTtl: number;
  audit: Required<AuditConfig>;
  baseRoles: RoleDefinition[];
  defaultRole: string;
  citadelBaseUrl: string | null;
  delegation: Required<DelegationConfig>;
}

export function resolveConfig(config: GatehouseConfig): ResolvedConfig {
  if (!config.jwksUrl) {
    throw new Error('Gatedhouse: jwksUrl is required');
  }
  if (!config.database?.connectionString) {
    throw new Error('Gatedhouse: database.connectionString is required');
  }
  if (!config.service) {
    throw new Error('Gatedhouse: service name is required');
  }

  return {
    jwksUrl: config.jwksUrl,
    jwksCacheTtl: config.jwksCacheTtl ?? 3600,
    database: {
      connectionString: config.database.connectionString,
      migrationsTable: config.database.migrationsTable ?? 'gatedhouse_migrations',
      tablePrefix: config.database.tablePrefix ?? 'gatedhouse_',
      poolMin: config.database.poolMin ?? 2,
      poolMax: config.database.poolMax ?? 10,
    },
    eventBus: config.eventBus ?? { adapter: 'noop' },
    service: config.service,
    orgHeader: config.orgHeader ?? 'X-Org-Id',
    orgRequired: config.orgRequired ?? true,
    cacheMissStrategy: config.cacheMissStrategy ?? 'fetch',
    cacheMissTtl: config.cacheMissTtl ?? 60,
    resolvedPermissionsCacheTtl: config.resolvedPermissionsCacheTtl ?? 300,
    audit: {
      enabled: config.audit?.enabled ?? true,
      logDenied: config.audit?.logDenied ?? true,
      logAllowed: config.audit?.logAllowed ?? false,
    },
    baseRoles: config.baseRoles ?? DEFAULT_BASE_ROLES,
    defaultRole: config.defaultRole ?? 'member',
    citadelBaseUrl: config.citadelBaseUrl ?? null,
    delegation: {
      enabled: config.delegation?.enabled ?? true,
      cacheTtl: config.delegation?.cacheTtl ?? 60,
      validateLive: config.delegation?.validateLive ?? false,
      allowedIdentityTypes: config.delegation?.allowedIdentityTypes ?? [
        'human',
        'agent',
        'machine',
      ],
    },
  };
}
