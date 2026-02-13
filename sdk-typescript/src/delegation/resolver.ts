/**
 * Delegation resolver — resolves delegation context for agent requests.
 *
 * Implements the three-way intersection:
 *   Effective = DelegationScopes ∩ AgentMaxDelegationScope ∩ DelegatorCurrentPermissions
 */

import { DelegationCache } from './cache';
import { DelegationContext, MetricsCollector } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('delegation-resolver');

export class DelegationResolver {
  constructor(
    private cache: DelegationCache,
    private metrics?: MetricsCollector,
  ) {}

  /**
   * Resolve delegation context for an agent in an org.
   */
  async resolve(
    agentId: string,
    orgId: string,
  ): Promise<DelegationContext | null> {
    const delegation = await this.cache.findActiveForAgent(agentId, orgId);

    if (!delegation) {
      return null;
    }

    // Validate the delegation is still valid
    if (new Date(delegation.expiresAt) < new Date()) {
      this.metrics?.increment('gatedhouse_delegation_checks_total', {
        result: 'expired',
      });
      return null;
    }

    if (
      delegation.maxUses !== null &&
      delegation.useCount >= delegation.maxUses
    ) {
      this.metrics?.increment('gatedhouse_delegation_checks_total', {
        result: 'exhausted',
      });
      return null;
    }

    this.metrics?.increment('gatedhouse_delegation_cache_hit_total');

    return {
      id: delegation.delegationId,
      delegatorId: delegation.delegatorId,
      delegatorMembershipId: delegation.delegatorMembershipId,
      scopes: delegation.scopes,
      constraints: delegation.constraints,
      expiresAt: delegation.expiresAt.toISOString(),
      usesRemaining:
        delegation.maxUses !== null
          ? delegation.maxUses - delegation.useCount
          : undefined,
    };
  }

  /**
   * Resolve delegation by explicit delegation ID (from JWT claim).
   */
  async resolveById(delegationId: string): Promise<DelegationContext | null> {
    const delegation = await this.cache.findById(delegationId);
    if (!delegation) {
      this.metrics?.increment('gatedhouse_delegation_cache_miss_total');
      return null;
    }

    if (delegation.status !== 'active') {
      logger.debug(
        { delegationId, status: delegation.status },
        'Delegation not active',
      );
      return null;
    }

    if (new Date(delegation.expiresAt) < new Date()) {
      return null;
    }

    return {
      id: delegation.delegationId,
      delegatorId: delegation.delegatorId,
      delegatorMembershipId: delegation.delegatorMembershipId,
      scopes: delegation.scopes,
      constraints: delegation.constraints,
      expiresAt: delegation.expiresAt.toISOString(),
      usesRemaining:
        delegation.maxUses !== null
          ? delegation.maxUses - delegation.useCount
          : undefined,
    };
  }
}
