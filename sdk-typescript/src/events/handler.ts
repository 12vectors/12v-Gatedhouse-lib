/**
 * Event handler — processes Citadel and Sphinx events to keep
 * local caches in sync.
 */

import { MembershipCache } from '../membership/cache';
import { DelegationCache } from '../delegation/cache';
import { RoleRepository } from '../roles/repository';
import { RoleAssignmentManager } from '../roles/assignment';
import { PermissionResolver } from '../roles/resolver';
import { GatehouseEvent, MetricsCollector, EntityType } from '../types';
import { ResolvedConfig } from '../config';
import * as EventTypes from './types';
import { createLogger } from '../logger';

const logger = createLogger('event-handler');

export class EventHandlerRegistry {
  constructor(
    private membershipCache: MembershipCache,
    private delegationCache: DelegationCache,
    private roleRepo: RoleRepository,
    private roleAssignments: RoleAssignmentManager,
    private permissionResolver: PermissionResolver,
    private config: ResolvedConfig,
    private metrics?: MetricsCollector,
  ) {}

  /**
   * Process an incoming event. Idempotent by design.
   */
  async handle(event: GatehouseEvent): Promise<void> {
    const start = Date.now();

    try {
      switch (event.type) {
        // ─── Organization Events ────────────────────────────────
        case EventTypes.ORG_CREATED:
          await this.handleOrgCreated(event);
          break;
        case EventTypes.ORG_DELETED:
          await this.handleOrgDeleted(event);
          break;
        case EventTypes.ORG_SUSPENDED:
          await this.handleOrgSuspended(event);
          break;
        case EventTypes.ORG_REACTIVATED:
          await this.handleOrgReactivated(event);
          break;

        // ─── Membership Events ──────────────────────────────────
        case EventTypes.MEMBERSHIP_CREATED:
          await this.handleMembershipCreated(event);
          break;
        case EventTypes.MEMBERSHIP_UPDATED:
          await this.handleMembershipUpdated(event);
          break;
        case EventTypes.MEMBERSHIP_SUSPENDED:
          await this.handleMembershipSuspended(event);
          break;
        case EventTypes.MEMBERSHIP_REACTIVATED:
          await this.handleMembershipReactivated(event);
          break;
        case EventTypes.MEMBERSHIP_REMOVED:
          await this.handleMembershipRemoved(event);
          break;

        // ─── Group Events ───────────────────────────────────────
        case EventTypes.GROUP_MEMBER_ADDED:
          await this.handleGroupMemberAdded(event);
          break;
        case EventTypes.GROUP_MEMBER_REMOVED:
          await this.handleGroupMemberRemoved(event);
          break;
        case EventTypes.GROUP_DELETED:
          await this.handleGroupDeleted(event);
          break;

        // ─── Delegation Events ──────────────────────────────────
        case EventTypes.DELEGATION_CREATED:
          await this.handleDelegationCreated(event);
          break;
        case EventTypes.DELEGATION_REVOKED:
          await this.handleDelegationRevoked(event);
          break;
        case EventTypes.DELEGATION_EXPIRED:
          await this.handleDelegationExpired(event);
          break;
        case EventTypes.DELEGATION_EXHAUSTED:
          await this.handleDelegationExhausted(event);
          break;
        case EventTypes.AGENT_DEACTIVATED:
          await this.handleAgentDeactivated(event);
          break;

        default:
          logger.debug({ type: event.type }, 'Unknown event type, ignoring');
      }

      this.metrics?.increment('gatedhouse_event_processed_total', {
        type: event.type,
      });
    } catch (err) {
      logger.error({ err, event: event.type }, 'Event handling failed');
      throw err;
    } finally {
      const duration = Date.now() - start;
      this.metrics?.observe('gatedhouse_event_processing_lag_ms', duration, {
        type: event.type,
      });
    }
  }

  // ─── Organization Handlers ──────────────────────────────────────

  private async handleOrgCreated(event: GatehouseEvent): Promise<void> {
    const orgId = event.data.org_id as string;
    logger.info({ orgId }, 'Handling org.created');
    await this.roleRepo.seedBaseRoles(orgId, this.config.baseRoles);
  }

  private async handleOrgDeleted(event: GatehouseEvent): Promise<void> {
    const orgId = event.data.org_id as string;
    logger.info({ orgId }, 'Handling org.deleted — purging all data');

    await this.membershipCache.removeAllForOrg(orgId);
    await this.roleAssignments.deleteAllForOrg(orgId);
    await this.roleAssignments.deleteAllGroupRolesForOrg(orgId);
    await this.roleRepo.deleteAllForOrg(orgId);
    await this.delegationCache.removeAllForOrg(orgId);
  }

  private async handleOrgSuspended(event: GatehouseEvent): Promise<void> {
    const orgId = event.data.org_id as string;
    logger.info({ orgId }, 'Handling org.suspended');
    await this.membershipCache.suspendAllForOrg(orgId);
  }

  private async handleOrgReactivated(event: GatehouseEvent): Promise<void> {
    const orgId = event.data.org_id as string;
    logger.info({ orgId }, 'Handling org.reactivated');
    await this.membershipCache.reactivateAllForOrg(orgId);
  }

  // ─── Membership Handlers ───────────────────────────────────────

  private async handleMembershipCreated(event: GatehouseEvent): Promise<void> {
    const data = event.data;
    const membershipId = data.membership_id as string;
    const orgId = data.org_id as string;

    logger.info({ membershipId, orgId }, 'Handling membership.created');

    await this.membershipCache.upsert({
      membershipId,
      orgId,
      entityType: data.entity_type as EntityType,
      entityId: data.entity_id as string,
      isOwner: (data.is_owner as boolean) ?? false,
      status: (data.status as string) ?? 'active',
      groups: (data.groups as string[]) ?? [],
    });

    // Assign default role
    if (this.config.defaultRole) {
      await this.roleAssignments.assign(
        membershipId,
        this.config.defaultRole,
        orgId,
      );
    }

    // If owner, also assign owner role
    if (data.is_owner) {
      await this.roleAssignments.assign(membershipId, 'owner', orgId);
    }

    // Build initial resolved permissions
    await this.permissionResolver.rebuildForMembership(
      membershipId,
      orgId,
      (data.groups as string[]) ?? [],
    );
  }

  private async handleMembershipUpdated(event: GatehouseEvent): Promise<void> {
    const data = event.data;
    const membershipId = data.membership_id as string;
    const orgId = data.org_id as string;

    logger.info({ membershipId }, 'Handling membership.updated');

    await this.membershipCache.upsert({
      membershipId,
      orgId,
      entityType: data.entity_type as EntityType,
      entityId: data.entity_id as string,
      isOwner: (data.is_owner as boolean) ?? false,
      status: (data.status as string) ?? 'active',
      groups: (data.groups as string[]) ?? [],
    });

    // Rebuild permissions in case owner status changed
    await this.permissionResolver.rebuildForMembership(
      membershipId,
      orgId,
      (data.groups as string[]) ?? [],
    );
  }

  private async handleMembershipSuspended(event: GatehouseEvent): Promise<void> {
    const membershipId = event.data.membership_id as string;
    logger.info({ membershipId }, 'Handling membership.suspended');
    await this.membershipCache.updateStatus(membershipId, 'suspended');
  }

  private async handleMembershipReactivated(event: GatehouseEvent): Promise<void> {
    const membershipId = event.data.membership_id as string;
    logger.info({ membershipId }, 'Handling membership.reactivated');
    await this.membershipCache.updateStatus(membershipId, 'active');
  }

  private async handleMembershipRemoved(event: GatehouseEvent): Promise<void> {
    const membershipId = event.data.membership_id as string;
    logger.info({ membershipId }, 'Handling membership.removed');

    await this.membershipCache.remove(membershipId);
    await this.roleAssignments.deleteAllForMembership(membershipId);
    await this.permissionResolver.clearForMembership(membershipId);
  }

  // ─── Group Handlers ────────────────────────────────────────────

  private async handleGroupMemberAdded(event: GatehouseEvent): Promise<void> {
    const membershipId = event.data.membership_id as string;
    const groupId = event.data.group_id as string;
    const orgId = event.data.org_id as string;

    logger.info({ membershipId, groupId }, 'Handling group.member.added');

    await this.membershipCache.addGroup(membershipId, groupId);

    // Rebuild permissions to include group roles
    const cached = await this.membershipCache.findById(membershipId);
    if (cached) {
      await this.permissionResolver.rebuildForMembership(
        membershipId,
        orgId,
        cached.groups,
      );
    }
  }

  private async handleGroupMemberRemoved(event: GatehouseEvent): Promise<void> {
    const membershipId = event.data.membership_id as string;
    const groupId = event.data.group_id as string;
    const orgId = event.data.org_id as string;

    logger.info({ membershipId, groupId }, 'Handling group.member.removed');

    await this.membershipCache.removeGroup(membershipId, groupId);

    // Rebuild permissions without group roles
    const cached = await this.membershipCache.findById(membershipId);
    if (cached) {
      await this.permissionResolver.rebuildForMembership(
        membershipId,
        orgId,
        cached.groups,
      );
    }
  }

  private async handleGroupDeleted(event: GatehouseEvent): Promise<void> {
    const groupId = event.data.group_id as string;
    const orgId = event.data.org_id as string;

    logger.info({ groupId }, 'Handling group.deleted');

    // Remove group from all membership caches
    await this.membershipCache.removeGroupFromAll(groupId);

    // Remove group role assignments
    await this.roleAssignments.deleteAllForGroup(groupId);

    // Rebuild permissions for all affected memberships
    const memberships = await this.membershipCache.listByOrg(orgId);
    for (const m of memberships) {
      await this.permissionResolver.rebuildForMembership(
        m.membershipId,
        orgId,
        m.groups,
      );
    }
  }

  // ─── Delegation Handlers ───────────────────────────────────────

  private async handleDelegationCreated(event: GatehouseEvent): Promise<void> {
    const data = event.data;
    logger.info(
      { delegationId: data.delegation_id },
      'Handling delegation.created',
    );

    await this.delegationCache.upsert({
      delegationId: data.delegation_id as string,
      agentId: data.agent_id as string,
      delegatorId: data.delegator_id as string,
      delegatorMembershipId: data.delegator_membership_id as string,
      orgId: data.org_id as string,
      scopes: (data.scopes as string[]) ?? [],
      constraints: (data.constraints as Record<string, unknown>) ?? {},
      maxUses: (data.max_uses as number) ?? null,
      useCount: 0,
      status: 'active',
      expiresAt: new Date(data.expires_at as string),
    });
  }

  private async handleDelegationRevoked(event: GatehouseEvent): Promise<void> {
    const delegationId = event.data.delegation_id as string;
    logger.info({ delegationId }, 'Handling delegation.revoked');
    await this.delegationCache.updateStatus(delegationId, 'revoked');
  }

  private async handleDelegationExpired(event: GatehouseEvent): Promise<void> {
    const delegationId = event.data.delegation_id as string;
    logger.info({ delegationId }, 'Handling delegation.expired');
    await this.delegationCache.updateStatus(delegationId, 'expired');
  }

  private async handleDelegationExhausted(event: GatehouseEvent): Promise<void> {
    const delegationId = event.data.delegation_id as string;
    logger.info({ delegationId }, 'Handling delegation.exhausted');
    await this.delegationCache.updateStatus(delegationId, 'exhausted');
  }

  private async handleAgentDeactivated(event: GatehouseEvent): Promise<void> {
    const agentId = event.data.agent_id as string;
    logger.info({ agentId }, 'Handling agent.deactivated');
    await this.delegationCache.revokeAllForAgent(agentId);
  }
}
