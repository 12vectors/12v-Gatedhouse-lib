/**
 * ABAC Policy Engine — custom authorization policies beyond RBAC.
 *
 * Services register domain-specific policies that evaluate
 * GatedContext + resource attributes to make authorization decisions.
 */

import { GatedContext, PolicyFunction, MetricsCollector } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('policy-engine');

export class PolicyEngine {
  private policies: Map<string, PolicyFunction> = new Map();

  constructor(private metrics?: MetricsCollector) {}

  /**
   * Register a named policy function.
   */
  register(name: string, fn: PolicyFunction): void {
    if (this.policies.has(name)) {
      logger.warn({ policy: name }, 'Overwriting existing policy');
    }
    this.policies.set(name, fn);
    logger.info({ policy: name }, 'Policy registered');
  }

  /**
   * Unregister a policy.
   */
  unregister(name: string): boolean {
    return this.policies.delete(name);
  }

  /**
   * Evaluate a named policy against context and resource attributes.
   */
  async evaluate(
    ctx: GatedContext,
    policyName: string,
    resource: Record<string, unknown> = {},
  ): Promise<boolean> {
    const policy = this.policies.get(policyName);
    if (!policy) {
      logger.error({ policy: policyName }, 'Policy not found');
      this.metrics?.increment('gatedhouse_policy_evaluations_total', {
        result: 'not_found',
      });
      return false;
    }

    try {
      const result = await policy(ctx, resource);

      this.metrics?.increment('gatedhouse_policy_evaluations_total', {
        result: result ? 'allowed' : 'denied',
        policy: policyName,
      });

      return result;
    } catch (err) {
      logger.error({ err, policy: policyName }, 'Policy evaluation failed');
      this.metrics?.increment('gatedhouse_policy_evaluations_total', {
        result: 'error',
        policy: policyName,
      });
      // Fail closed on policy errors
      return false;
    }
  }

  /**
   * Check if a policy is registered.
   */
  has(name: string): boolean {
    return this.policies.has(name);
  }

  /**
   * List all registered policy names.
   */
  list(): string[] {
    return Array.from(this.policies.keys());
  }
}
