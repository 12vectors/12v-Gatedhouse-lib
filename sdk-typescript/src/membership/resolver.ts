/**
 * Membership resolver — resolves identity + org to membership context.
 *
 * Uses the local cache first, falls back to Citadel API on cache miss.
 */

import { MembershipCache } from './cache';
import { CachedMembership, MembershipContext, MetricsCollector, EntityType } from '../types';
import { ResolvedConfig } from '../config';
import { createLogger } from '../logger';

const logger = createLogger('membership-resolver');

export class MembershipResolver {
  constructor(
    private cache: MembershipCache,
    private config: ResolvedConfig,
    private metrics?: MetricsCollector,
  ) {}

  /**
   * Resolve a membership for a given identity and organization.
   */
  async resolve(
    entityType: EntityType,
    entityId: string,
    orgId: string,
  ): Promise<MembershipContext | null> {
    // Try local cache first
    const cached = await this.cache.findByEntityAndOrg(entityType, entityId, orgId);
    if (cached) {
      this.metrics?.increment('gatedhouse_cache_hit_total');
      return this.toMembershipContext(cached);
    }

    this.metrics?.increment('gatedhouse_cache_miss_total');

    // Cache miss: fetch from Citadel or deny
    if (this.config.cacheMissStrategy === 'deny') {
      logger.warn(
        { entityType, entityId, orgId },
        'Membership cache miss with deny strategy',
      );
      return null;
    }

    return this.fetchFromCitadel(entityType, entityId, orgId);
  }

  /**
   * Resolve membership by membership ID directly.
   */
  async resolveById(membershipId: string): Promise<MembershipContext | null> {
    const cached = await this.cache.findById(membershipId);
    if (cached) {
      this.metrics?.increment('gatedhouse_cache_hit_total');
      return this.toMembershipContext(cached);
    }

    this.metrics?.increment('gatedhouse_cache_miss_total');
    return null;
  }

  private async fetchFromCitadel(
    entityType: EntityType,
    entityId: string,
    orgId: string,
  ): Promise<MembershipContext | null> {
    if (!this.config.citadelBaseUrl) {
      logger.error(
        'Citadel base URL not configured, cannot resolve cache miss',
      );
      return null;
    }

    try {
      const url = `${this.config.citadelBaseUrl}/api/citadel/v1/orgs/${orgId}/members`;
      logger.info({ url, entityId }, 'Fetching membership from Citadel');

      const response = await fetch(url);
      if (!response.ok) {
        logger.error(
          { status: response.status, orgId },
          'Citadel API request failed',
        );
        return null;
      }

      const data = (await response.json()) as {
        data: Array<{
          id: string;
          entity_type: EntityType;
          entity_id: string;
          is_owner: boolean;
          status: string;
          groups: string[];
        }>;
      };

      // Cache all memberships for the org
      for (const member of data.data) {
        await this.cache.upsert({
          membershipId: member.id,
          orgId,
          entityType: member.entity_type,
          entityId: member.entity_id,
          isOwner: member.is_owner,
          status: member.status,
          groups: member.groups ?? [],
        });
      }

      // Find the requested membership
      const match = data.data.find(
        (m) => m.entity_type === entityType && m.entity_id === entityId,
      );

      if (!match) {
        logger.warn(
          { entityType, entityId, orgId },
          'Membership not found in Citadel response',
        );
        return null;
      }

      return {
        id: match.id,
        entityType: match.entity_type,
        isOwner: match.is_owner,
        status: match.status,
        groups: match.groups ?? [],
      };
    } catch (err) {
      // Fail closed: Citadel unreachable means access denied
      logger.error({ err, orgId }, 'Failed to fetch from Citadel');
      return null;
    }
  }

  private toMembershipContext(cached: CachedMembership): MembershipContext {
    return {
      id: cached.membershipId,
      entityType: cached.entityType,
      isOwner: cached.isOwner,
      status: cached.status,
      groups: cached.groups,
    };
  }
}
