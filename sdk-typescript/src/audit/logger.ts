/**
 * Audit logger — records authorization decisions for compliance.
 *
 * Publishes audit events that can be consumed by the Audit & Compliance service.
 */

import { AuditEntry, EventBusAdapter, GatehouseEvent } from '../types';
import { ResolvedConfig } from '../config';
import { createLogger } from '../logger';

const logger = createLogger('audit');

export class AuditLogger {
  constructor(
    private config: ResolvedConfig,
    private eventBus?: EventBusAdapter,
  ) {}

  /**
   * Log an authorization decision.
   */
  async log(entry: AuditEntry): Promise<void> {
    if (!this.config.audit.enabled) return;

    // Skip allowed decisions unless logAllowed is true
    if (entry.result === 'allowed' && !this.config.audit.logAllowed) return;

    // Skip denied decisions unless logDenied is true
    if (entry.result === 'denied' && !this.config.audit.logDenied) return;

    const auditEvent: GatehouseEvent = {
      type: `authz.decision.${entry.result}`,
      timestamp: new Date().toISOString(),
      data: {
        service: this.config.service,
        action: entry.action,
        identity_type: entry.ctx.identity.type,
        identity_id: entry.ctx.identity.id,
        membership_id: entry.ctx.membership.id,
        org_id: entry.ctx.org.id,
        resource: entry.resource,
        roles: entry.ctx.roles,
        reason: entry.reason,
        ...(entry.ctx.delegation
          ? {
              delegation: {
                delegation_id: entry.ctx.delegation.id,
                delegator_id: entry.ctx.delegation.delegatorId,
              },
            }
          : {}),
      },
    };

    // Log locally
    if (entry.result === 'denied') {
      logger.warn(
        {
          action: entry.action,
          identityId: entry.ctx.identity.id,
          orgId: entry.ctx.org.id,
          reason: entry.reason,
        },
        'Access denied',
      );
    } else {
      logger.debug(
        {
          action: entry.action,
          identityId: entry.ctx.identity.id,
          orgId: entry.ctx.org.id,
        },
        'Access allowed',
      );
    }

    // Publish to event bus
    if (this.eventBus) {
      try {
        await this.eventBus.publish(auditEvent.type, auditEvent);
      } catch (err) {
        logger.error({ err }, 'Failed to publish audit event');
      }
    }
  }
}
