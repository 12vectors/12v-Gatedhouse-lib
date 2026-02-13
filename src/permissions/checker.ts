/**
 * Permission checker — the core authorization decision point.
 *
 * Evaluates whether a GatedContext has a required permission,
 * respecting identity type, delegation constraints, and wildcards.
 */

import {
  GatedContext,
  PermissionCheckResult,
  MetricsCollector,
} from '../types';
import { hasPermission, intersectPermissions } from './matcher';
import { createLogger } from '../logger';

const logger = createLogger('permission-checker');

export class PermissionChecker {
  constructor(private metrics?: MetricsCollector) {}

  /**
   * Check a single permission against the context.
   */
  check(ctx: GatedContext, required: string): PermissionCheckResult {
    const start = Date.now();

    try {
      // Suspended memberships always fail
      if (ctx.membership.status === 'suspended') {
        return { allowed: false, source: null };
      }

      // Delegated agent: three-way intersection
      if (ctx.delegation) {
        return this.checkDelegated(ctx, required);
      }

      // Scoped identity (API key or client credentials): intersect with scopes
      if (ctx.scopes && ctx.scopes.length > 0) {
        return this.checkScoped(ctx, required);
      }

      // Standard RBAC check
      return this.checkStandard(ctx, required);
    } finally {
      const duration = Date.now() - start;
      this.metrics?.observe('gatedhouse_permission_check_duration_ms', duration);
    }
  }

  /**
   * Check multiple permissions, returning a map of results.
   */
  checkMany(
    ctx: GatedContext,
    required: string[],
  ): Map<string, PermissionCheckResult> {
    const results = new Map<string, PermissionCheckResult>();
    for (const perm of required) {
      results.set(perm, this.check(ctx, perm));
    }
    return results;
  }

  /**
   * Check that all required permissions are satisfied.
   */
  checkAll(ctx: GatedContext, required: string[]): boolean {
    return required.every((perm) => this.check(ctx, perm).allowed);
  }

  /**
   * Check that any of the required permissions are satisfied.
   */
  checkAny(ctx: GatedContext, required: string[]): boolean {
    return required.some((perm) => this.check(ctx, perm).allowed);
  }

  private checkStandard(
    ctx: GatedContext,
    required: string,
  ): PermissionCheckResult {
    if (hasPermission(ctx.permissions, required)) {
      const source = this.findSource(ctx.permissions, required);
      this.metrics?.increment('gatedhouse_permission_checks_total', {
        result: 'allowed',
      });
      return { allowed: true, source };
    }

    this.metrics?.increment('gatedhouse_permission_checks_total', {
      result: 'denied',
    });
    return { allowed: false, source: null };
  }

  private checkScoped(
    ctx: GatedContext,
    required: string,
  ): PermissionCheckResult {
    // Effective = RolePermissions ∩ APIKeyScopes
    const effective = intersectPermissions(ctx.permissions, ctx.scopes!);

    if (hasPermission(effective, required)) {
      this.metrics?.increment('gatedhouse_permission_checks_total', {
        result: 'allowed',
      });
      return { allowed: true, source: 'scoped' };
    }

    this.metrics?.increment('gatedhouse_permission_checks_total', {
      result: 'denied',
    });
    return { allowed: false, source: null };
  }

  private checkDelegated(
    ctx: GatedContext,
    required: string,
  ): PermissionCheckResult {
    const delegation = ctx.delegation!;

    // Check delegation expiry
    if (new Date(delegation.expiresAt) < new Date()) {
      logger.debug(
        { delegationId: delegation.id },
        'Delegation expired',
      );
      this.metrics?.increment('gatedhouse_delegation_checks_total', {
        result: 'expired',
      });
      return { allowed: false, source: null };
    }

    // Check uses remaining
    if (
      delegation.usesRemaining !== undefined &&
      delegation.usesRemaining <= 0
    ) {
      logger.debug(
        { delegationId: delegation.id },
        'Delegation uses exhausted',
      );
      this.metrics?.increment('gatedhouse_delegation_checks_total', {
        result: 'exhausted',
      });
      return { allowed: false, source: null };
    }

    // Three-way intersection:
    // Effective = DelegationScopes ∩ AgentPermissions(ctx.permissions) ∩ DelegatorPermissions
    // Note: ctx.permissions should already reflect the agent's max scope ceiling
    // DelegatorCurrentPermissions are resolved at request time
    const effective = intersectPermissions(
      delegation.scopes,
      ctx.permissions,
    );

    if (hasPermission(effective, required)) {
      this.metrics?.increment('gatedhouse_delegation_checks_total', {
        result: 'allowed',
      });
      return {
        allowed: true,
        source: `delegation:${delegation.id}`,
      };
    }

    this.metrics?.increment('gatedhouse_delegation_checks_total', {
      result: 'denied',
    });
    return { allowed: false, source: null };
  }

  private findSource(permissions: string[], required: string): string {
    for (const perm of permissions) {
      if (perm === required) return `permission:${perm}`;
    }
    // Wildcard match
    return `wildcard`;
  }
}
