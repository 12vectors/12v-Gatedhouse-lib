/**
 * Gatedhouse — the main orchestrator class.
 *
 * This is the primary entry point for consuming services. It wires together
 * all internal modules and exposes a clean public API for:
 *   - Express middleware integration
 *   - Permission checks
 *   - Role management
 *   - Policy registration
 *   - Event handling
 *   - Admin API routing
 */

import type { Router, RequestHandler } from 'express';
import { GatehouseConfig, ResolvedConfig, resolveConfig } from './config';
import { DatabaseConnection } from './database/connection';
import { MigrationRunner } from './database/migrations';
import { JwksClient } from './jwt/jwks';
import { JwtVerifier } from './jwt/verifier';
import { PermissionChecker } from './permissions/checker';
import { PermissionRegistry } from './permissions/registry';
import { RoleRepository } from './roles/repository';
import { RoleAssignmentManager } from './roles/assignment';
import { PermissionResolver } from './roles/resolver';
import { MembershipCache } from './membership/cache';
import { MembershipResolver } from './membership/resolver';
import { DelegationCache } from './delegation/cache';
import { DelegationResolver } from './delegation/resolver';
import { PolicyEngine } from './policies/engine';
import { EventHandlerRegistry } from './events/handler';
import { InMemoryEventBus } from './events/adapters/in-memory';
import { NoopEventBus } from './events/adapters/noop';
import { AuditLogger } from './audit/logger';
import { DefaultMetricsCollector } from './metrics/collector';
import { createMiddleware, createOptionalMiddleware, MiddlewareDeps } from './middleware/express';
import {
  requireAuth,
  requirePermission,
  requireAllPermissions,
  requireAnyPermission,
  requireOwner,
  requireIdentityType,
  requirePolicy,
  GuardDeps,
} from './middleware/guards';
import { createAdminRouter } from './admin/router';
import {
  GatedContext,
  RoleDefinition,
  IdentityType,
  MetricsCollector,
  EventBusAdapter,
  GatehouseEvent,
  PolicyFunction,
  RoleSource,
} from './types';
import { createLogger } from './logger';

const logger = createLogger('gatedhouse');

export class Gatedhouse {
  // ─── Configuration ───────────────────────────────────────────
  private config: ResolvedConfig;

  // ─── Infrastructure ──────────────────────────────────────────
  private db: DatabaseConnection;
  private eventBus: EventBusAdapter;
  private metricsCollector: MetricsCollector;

  // ─── Core Modules ────────────────────────────────────────────
  private jwksClient: JwksClient;
  private jwtVerifier: JwtVerifier;
  private permissionChecker: PermissionChecker;
  private permissionRegistry: PermissionRegistry;
  private roleRepo: RoleRepository;
  private roleAssignments: RoleAssignmentManager;
  private permissionResolver: PermissionResolver;
  private membershipCache: MembershipCache;
  private membershipResolver: MembershipResolver;
  private delegationCache: DelegationCache;
  private delegationResolver: DelegationResolver;
  private policyEngine: PolicyEngine;
  private eventHandler: EventHandlerRegistry;
  private auditLogger: AuditLogger;

  // ─── State ───────────────────────────────────────────────────
  private initialized = false;

  constructor(config: GatehouseConfig) {
    this.config = resolveConfig(config);

    // Infrastructure
    this.db = new DatabaseConnection(this.config);
    this.metricsCollector = new DefaultMetricsCollector();

    // Event bus
    switch (this.config.eventBus.adapter) {
      case 'in_memory':
        this.eventBus = new InMemoryEventBus();
        break;
      case 'noop':
      default:
        this.eventBus = new NoopEventBus();
        break;
    }

    // JWT
    this.jwksClient = new JwksClient(
      this.config.jwksUrl,
      this.config.jwksCacheTtl * 1000,
    );
    this.jwtVerifier = new JwtVerifier(this.jwksClient);

    // Permissions
    this.permissionChecker = new PermissionChecker(this.metricsCollector);
    this.permissionRegistry = new PermissionRegistry(this.db);

    // Roles
    this.roleRepo = new RoleRepository(this.db);
    this.roleAssignments = new RoleAssignmentManager(this.db);
    this.permissionResolver = new PermissionResolver(
      this.db,
      this.roleRepo,
      this.roleAssignments,
    );

    // Membership
    this.membershipCache = new MembershipCache(this.db);
    this.membershipResolver = new MembershipResolver(
      this.membershipCache,
      this.config,
      this.metricsCollector,
    );

    // Delegation
    this.delegationCache = new DelegationCache(this.db);
    this.delegationResolver = new DelegationResolver(
      this.delegationCache,
      this.metricsCollector,
    );

    // Policy engine
    this.policyEngine = new PolicyEngine(this.metricsCollector);

    // Audit
    this.auditLogger = new AuditLogger(this.config, this.eventBus);

    // Event handler
    this.eventHandler = new EventHandlerRegistry(
      this.membershipCache,
      this.delegationCache,
      this.roleRepo,
      this.roleAssignments,
      this.permissionResolver,
      this.config,
      this.metricsCollector,
    );
  }

  // ─── Lifecycle ─────────────────────────────────────────────────

  /**
   * Initialize Gatedhouse: run migrations, set up event subscriptions.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    logger.info({ service: this.config.service }, 'Initializing Gatedhouse');

    // Verify database connectivity
    const healthy = await this.db.healthCheck();
    if (!healthy) {
      throw new Error('Gatedhouse: database is not reachable');
    }

    // Run migrations
    await this.runMigrations();

    // Subscribe to events
    const topics = this.config.eventBus.topics ?? ['citadel.*', 'sphinx.*'];
    await this.eventBus.subscribe(topics, (event) =>
      this.eventHandler.handle(event),
    );

    this.initialized = true;
    logger.info({ service: this.config.service }, 'Gatedhouse initialized');
  }

  /**
   * Run database migrations.
   */
  async runMigrations(): Promise<void> {
    const runner = new MigrationRunner(
      this.db,
      this.config.database.migrationsTable,
    );
    await runner.run();
  }

  /**
   * Gracefully shut down Gatedhouse.
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down Gatedhouse');
    await this.eventBus.disconnect();
    await this.db.close();
    this.initialized = false;
  }

  // ─── Middleware ────────────────────────────────────────────────

  /**
   * Create Express middleware that populates req.gatedContext.
   */
  middleware(): RequestHandler {
    return createMiddleware(this.getMiddlewareDeps());
  }

  /**
   * Create optional auth middleware — passes through unauthenticated requests.
   */
  optional(): RequestHandler {
    return createOptionalMiddleware(this.getMiddlewareDeps());
  }

  /**
   * Require authentication guard.
   */
  requireAuth(): RequestHandler {
    return requireAuth();
  }

  /**
   * Require a specific permission.
   */
  requirePermission(permission: string): RequestHandler {
    return requirePermission(permission, this.getGuardDeps());
  }

  /**
   * Require all specified permissions.
   */
  requireAllPermissions(permissions: string[]): RequestHandler {
    return requireAllPermissions(permissions, this.getGuardDeps());
  }

  /**
   * Require any of the specified permissions.
   */
  requireAnyPermission(permissions: string[]): RequestHandler {
    return requireAnyPermission(permissions, this.getGuardDeps());
  }

  /**
   * Require organization owner.
   */
  requireOwner(): RequestHandler {
    return requireOwner();
  }

  /**
   * Require a specific identity type.
   */
  requireIdentityType(type: IdentityType): RequestHandler {
    return requireIdentityType(type);
  }

  /**
   * Require a custom ABAC policy evaluation.
   */
  requirePolicy(
    policyName: string,
    resourceFn: (req: import('express').Request) => Promise<Record<string, unknown>> | Record<string, unknown>,
  ): RequestHandler {
    return requirePolicy(policyName, resourceFn, this.getGuardDeps());
  }

  // ─── Permission Checks ────────────────────────────────────────

  /**
   * Check if context has a permission.
   */
  check(ctx: GatedContext, permission: string): boolean {
    return this.permissionChecker.check(ctx, permission).allowed;
  }

  /**
   * Check multiple permissions, returning a map.
   */
  checkMany(
    ctx: GatedContext,
    permissions: string[],
  ): Map<string, { allowed: boolean; source: string | null }> {
    return this.permissionChecker.checkMany(ctx, permissions);
  }

  // ─── Roles ────────────────────────────────────────────────────

  /**
   * Role management interface.
   */
  get roles() {
    const self = this;
    return {
      /**
       * Define service-specific roles.
       */
      async define(roles: RoleDefinition[]): Promise<void> {
        // Define with __system__ org for service-wide roles
        await self.roleRepo.define('__system__', roles);
      },

      /**
       * Define roles for a specific org.
       */
      async defineForOrg(orgId: string, roles: RoleDefinition[]): Promise<void> {
        await self.roleRepo.define(orgId, roles);
      },

      /**
       * Assign a role to a membership.
       */
      async assign(
        membershipId: string,
        roleId: string,
        orgId?: string,
      ): Promise<void> {
        const resolvedOrgId = orgId ?? (await self.resolveOrgForMembership(membershipId));
        if (!resolvedOrgId) throw new Error('Could not resolve org for membership');
        await self.roleAssignments.assign(membershipId, roleId, resolvedOrgId);

        // Rebuild permissions
        const cached = await self.membershipCache.findById(membershipId);
        if (cached) {
          await self.permissionResolver.rebuildForMembership(
            membershipId,
            resolvedOrgId,
            cached.groups,
          );
        }
      },

      /**
       * Revoke a role from a membership.
       */
      async revoke(membershipId: string, roleId: string): Promise<boolean> {
        const result = await self.roleAssignments.revoke(membershipId, roleId);

        // Rebuild permissions
        const cached = await self.membershipCache.findById(membershipId);
        if (cached) {
          await self.permissionResolver.rebuildForMembership(
            membershipId,
            cached.orgId,
            cached.groups,
          );
        }

        return result;
      },

      /**
       * List roles for a membership.
       */
      async forMembership(membershipId: string): Promise<string[]> {
        return self.roleAssignments.getRoleIds(membershipId);
      },

      /**
       * List memberships with a specific role in an org.
       */
      async membershipsWithRole(orgId: string, roleId: string): Promise<string[]> {
        return self.roleAssignments.membershipsWithRole(orgId, roleId);
      },

      /**
       * Check if a membership has a specific role.
       */
      async has(membershipId: string, roleId: string): Promise<boolean> {
        return self.roleAssignments.has(membershipId, roleId);
      },

      /**
       * Resolve all effective permissions for a membership.
       */
      async resolvePermissions(membershipId: string): Promise<string[]> {
        const cached = await self.membershipCache.findById(membershipId);
        if (!cached) return [];
        return self.permissionResolver.resolvePermissions(
          membershipId,
          cached.orgId,
          cached.groups,
        );
      },

      /**
       * Assign a role to a group.
       */
      async assignToGroup(
        groupId: string,
        roleId: string,
        orgId: string,
      ): Promise<void> {
        await self.roleAssignments.assignToGroup(groupId, roleId, orgId);
      },

      /**
       * Revoke a role from a group.
       */
      async revokeFromGroup(groupId: string, roleId: string): Promise<boolean> {
        return self.roleAssignments.revokeFromGroup(groupId, roleId);
      },

      /**
       * List roles for a group.
       */
      async forGroup(groupId: string): Promise<string[]> {
        return self.roleAssignments.getGroupRoleIds(groupId);
      },

      /**
       * Register a custom role source.
       */
      addSource(name: string, source: RoleSource): void {
        self.permissionResolver.addSource(name, source);
      },
    };
  }

  // ─── Policies ─────────────────────────────────────────────────

  /**
   * Policy engine interface.
   */
  get policies() {
    return {
      register: (name: string, fn: PolicyFunction): void => {
        this.policyEngine.register(name, fn);
      },
      unregister: (name: string): boolean => {
        return this.policyEngine.unregister(name);
      },
      evaluate: (
        ctx: GatedContext,
        policyName: string,
        resource?: Record<string, unknown>,
      ): Promise<boolean> => {
        return this.policyEngine.evaluate(ctx, policyName, resource);
      },
      has: (name: string): boolean => {
        return this.policyEngine.has(name);
      },
      list: (): string[] => {
        return this.policyEngine.list();
      },
    };
  }

  // ─── Permissions Registry ─────────────────────────────────────

  /**
   * Register service permissions.
   */
  async registerPermissions(
    permissions: Array<{ key: string; description?: string }>,
  ): Promise<void> {
    await this.permissionRegistry.register(permissions);
  }

  // ─── Events ───────────────────────────────────────────────────

  /**
   * Manually feed an event into Gatedhouse (for noop adapter or custom event sources).
   */
  async handleEvent(event: GatehouseEvent): Promise<void> {
    await this.eventHandler.handle(event);
  }

  /**
   * Publish an event (e.g., audit events).
   */
  async publishEvent(topic: string, event: GatehouseEvent): Promise<void> {
    await this.eventBus.publish(topic, event);
  }

  // ─── Audit ────────────────────────────────────────────────────

  /**
   * Audit logger interface.
   */
  get audit() {
    return {
      log: (entry: import('./types').AuditEntry): Promise<void> => {
        return this.auditLogger.log(entry);
      },
    };
  }

  // ─── Admin Router ─────────────────────────────────────────────

  /**
   * Create the admin REST API router.
   */
  adminRouter(createRouter: () => Router): Router {
    return createAdminRouter(createRouter, {
      roleRepo: this.roleRepo,
      roleAssignments: this.roleAssignments,
      permissionResolver: this.permissionResolver,
      permissionChecker: this.permissionChecker,
      membershipCache: this.membershipCache,
    }, this.config.service);
  }

  // ─── Health ───────────────────────────────────────────────────

  /**
   * Health check — returns true if database is reachable.
   */
  async healthCheck(): Promise<boolean> {
    return this.db.healthCheck();
  }

  /**
   * Readiness check — returns true if fully initialized.
   */
  async readinessCheck(): Promise<{
    ready: boolean;
    database: boolean;
    initialized: boolean;
  }> {
    const database = await this.db.healthCheck();
    return {
      ready: database && this.initialized,
      database,
      initialized: this.initialized,
    };
  }

  // ─── Metrics ──────────────────────────────────────────────────

  /**
   * Replace the default metrics collector with a custom one.
   */
  setMetricsCollector(collector: MetricsCollector): void {
    // Replace in all modules that use it
    this.metricsCollector = collector;
    this.permissionChecker = new PermissionChecker(collector);
    this.membershipResolver = new MembershipResolver(
      this.membershipCache,
      this.config,
      collector,
    );
    this.delegationResolver = new DelegationResolver(
      this.delegationCache,
      collector,
    );
  }

  /**
   * Get the current metrics collector.
   */
  getMetrics(): MetricsCollector {
    return this.metricsCollector;
  }

  // ─── Internal Helpers ─────────────────────────────────────────

  private getMiddlewareDeps(): MiddlewareDeps {
    return {
      jwtVerifier: this.jwtVerifier,
      membershipResolver: this.membershipResolver,
      permissionResolver: this.permissionResolver,
      delegationResolver: this.delegationResolver,
      permissionChecker: this.permissionChecker,
      policyEngine: this.policyEngine,
      auditLogger: this.auditLogger,
      config: this.config,
      metrics: this.metricsCollector,
    };
  }

  private getGuardDeps(): GuardDeps {
    return {
      permissionChecker: this.permissionChecker,
      policyEngine: this.policyEngine,
      auditLogger: this.auditLogger,
    };
  }

  private async resolveOrgForMembership(membershipId: string): Promise<string | null> {
    const cached = await this.membershipCache.findById(membershipId);
    return cached?.orgId ?? null;
  }
}
