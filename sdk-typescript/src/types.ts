/**
 * Core type definitions for the Gatedhouse authorization library.
 */

// ─── Identity Types ────────────────────────────────────────────────

export type IdentityType = 'human' | 'agent' | 'machine';

export type AuthMethod =
  | 'password'
  | 'sso'
  | 'passkey'
  | 'client_credentials'
  | 'api_key'
  | 'workload'
  | 'token_exchange';

export interface Identity {
  /** per_{ulid}, agt_{ulid}, or sva_{ulid} */
  id: string;
  type: IdentityType;
  /** Humans only */
  email?: string;
  /** Agents and service accounts */
  name?: string;
  authMethod: AuthMethod;
  /** Humans only */
  mfaVerified?: boolean;
}

// ─── Organization ──────────────────────────────────────────────────

export interface OrgContext {
  /** org_{ulid} */
  id: string;
}

// ─── Membership ────────────────────────────────────────────────────

export type EntityType = 'person' | 'agent' | 'service_account';

export interface MembershipContext {
  /** mbr_{ulid} */
  id: string;
  entityType: EntityType;
  isOwner: boolean;
  status: string;
  /** grp_{ulid}[] */
  groups: string[];
}

// ─── Delegation ────────────────────────────────────────────────────

export interface DelegationContext {
  /** dlg_{ulid} */
  id: string;
  /** per_{ulid} of the person who granted authority */
  delegatorId: string;
  /** mbr_{ulid} of the delegator in this org */
  delegatorMembershipId: string;
  scopes: string[];
  constraints: Record<string, unknown>;
  expiresAt: string;
  usesRemaining?: number;
}

// ─── GatedContext ──────────────────────────────────────────────────

export interface GatedContext {
  identity: Identity;
  org: OrgContext;
  membership: MembershipContext;
  roles: string[];
  permissions: string[];
  scopes?: string[];
  delegation?: DelegationContext;
}

// ─── Role Definition ───────────────────────────────────────────────

export interface RoleDefinition {
  key: string;
  name: string;
  description?: string;
  permissions: string[];
  inherits?: string[];
  isSystem?: boolean;
}

export interface StoredRole {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  permissions: string[];
  inherits: string[];
  isSystem: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// ─── Role Assignment ───────────────────────────────────────────────

export interface RoleAssignment {
  membershipId: string;
  roleId: string;
  orgId: string;
  assignedBy: string | null;
  assignedAt: Date;
}

export interface GroupRoleAssignment {
  groupId: string;
  roleId: string;
  orgId: string;
  assignedBy: string | null;
  assignedAt: Date;
}

// ─── Membership Cache ──────────────────────────────────────────────

export interface CachedMembership {
  membershipId: string;
  orgId: string;
  entityType: EntityType;
  entityId: string;
  isOwner: boolean;
  status: string;
  groups: string[];
  syncedAt: Date;
}

// ─── Delegation Cache ──────────────────────────────────────────────

export interface CachedDelegation {
  delegationId: string;
  agentId: string;
  delegatorId: string;
  delegatorMembershipId: string;
  orgId: string;
  scopes: string[];
  constraints: Record<string, unknown>;
  maxUses: number | null;
  useCount: number;
  status: string;
  expiresAt: Date;
  syncedAt: Date;
}

// ─── Resolved Permission ───────────────────────────────────────────

export interface ResolvedPermission {
  membershipId: string;
  permission: string;
  source: string;
}

// ─── Permission Check Result ───────────────────────────────────────

export interface PermissionCheckResult {
  allowed: boolean;
  source: string | null;
}

// ─── Events ────────────────────────────────────────────────────────

export interface GatehouseEvent {
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export type EventHandler = (event: GatehouseEvent) => Promise<void>;

export interface EventBusAdapter {
  subscribe(topics: string[], handler: EventHandler): Promise<void>;
  publish(topic: string, event: GatehouseEvent): Promise<void>;
  disconnect(): Promise<void>;
}

// ─── Policy ────────────────────────────────────────────────────────

export type PolicyFunction = (
  ctx: GatedContext,
  resource: Record<string, unknown>,
) => boolean | Promise<boolean>;

// ─── Audit ─────────────────────────────────────────────────────────

export interface AuditEntry {
  action: string;
  result: 'allowed' | 'denied';
  ctx: GatedContext;
  resource?: { type: string; id: string };
  reason?: string;
}

// ─── Metrics ───────────────────────────────────────────────────────

export interface MetricsCollector {
  increment(metric: string, labels?: Record<string, string>): void;
  observe(metric: string, value: number, labels?: Record<string, string>): void;
}

// ─── Custom Role Source ────────────────────────────────────────────

export type RoleSource = (
  membershipId: string,
  orgId: string,
) => Promise<string[]>;
