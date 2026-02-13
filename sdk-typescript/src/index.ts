/**
 * @superagent/gatedhouse — Embedded authorization library for the SuperAgent Platform.
 *
 * Provides RBAC/ABAC access control with:
 *   - JWT verification via Sphinx JWKS
 *   - Membership cache synced from Citadel events
 *   - Role-based permission resolution with inheritance
 *   - Attribute-based custom policy engine
 *   - Express middleware integration
 *   - Admin REST API for role management
 *   - Delegation support for agent requests
 *   - Audit logging for compliance
 */

// Main entry point
export { Gatedhouse } from './gatedhouse';

// Configuration
export { resolveConfig } from './config';
export type { GatehouseConfig, DatabaseConfig, EventBusConfig, ResolvedConfig } from './config';

// Types
export type {
  GatedContext,
  Identity,
  IdentityType,
  AuthMethod,
  OrgContext,
  MembershipContext,
  EntityType,
  DelegationContext,
  RoleDefinition,
  StoredRole,
  RoleAssignment,
  GroupRoleAssignment,
  CachedMembership,
  CachedDelegation,
  ResolvedPermission,
  PermissionCheckResult,
  GatehouseEvent,
  EventHandler,
  EventBusAdapter,
  PolicyFunction,
  AuditEntry,
  MetricsCollector,
  RoleSource,
} from './types';

// Permission utilities (for direct use in consuming services)
export {
  matchPermission,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  expandWildcards,
  intersectPermissions,
} from './permissions/matcher';

// Event types (for publishing/consuming events)
export { EventTypes } from './events';

// Event bus adapters (for custom event bus setup)
export { InMemoryEventBus } from './events/adapters/in-memory';
export { NoopEventBus } from './events/adapters/noop';

// Metrics (for custom metrics collector)
export { DefaultMetricsCollector } from './metrics/collector';

// Errors
export { JwtVerificationError, JwksFetchError, JwksKeyNotFoundError } from './jwt';
