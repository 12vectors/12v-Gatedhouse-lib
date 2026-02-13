import { MembershipResolver } from '../../../src/membership/resolver';
import { MembershipCache } from '../../../src/membership/cache';
import { ResolvedConfig } from '../../../src/config';
import { CachedMembership } from '../../../src/types';

class MockMembershipCache {
  private memberships: Map<string, CachedMembership> = new Map();

  async upsert(m: Omit<CachedMembership, 'syncedAt'>): Promise<void> {
    this.memberships.set(m.membershipId, { ...m, syncedAt: new Date() });
  }

  async findById(membershipId: string): Promise<CachedMembership | null> {
    return this.memberships.get(membershipId) ?? null;
  }

  async findByEntityAndOrg(
    entityType: string,
    entityId: string,
    orgId: string,
  ): Promise<CachedMembership | null> {
    for (const m of this.memberships.values()) {
      if (m.entityType === entityType && m.entityId === entityId && m.orgId === orgId) {
        return m;
      }
    }
    return null;
  }
}

function makeConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    jwksUrl: 'http://localhost/jwks',
    jwksCacheTtl: 3600,
    database: {
      connectionString: 'postgresql://localhost/test',
      migrationsTable: 'gatedhouse_migrations',
      tablePrefix: 'gatedhouse_',
      poolMin: 2,
      poolMax: 10,
    },
    eventBus: { adapter: 'noop' },
    service: 'test',
    orgHeader: 'X-Org-Id',
    orgRequired: true,
    cacheMissStrategy: 'deny',
    cacheMissTtl: 60,
    resolvedPermissionsCacheTtl: 300,
    audit: { enabled: true, logDenied: true, logAllowed: false },
    baseRoles: [],
    defaultRole: 'member',
    citadelBaseUrl: null,
    delegation: {
      enabled: true,
      cacheTtl: 60,
      validateLive: false,
      allowedIdentityTypes: ['human', 'agent', 'machine'],
    },
    ...overrides,
  };
}

describe('MembershipResolver', () => {
  let cache: MockMembershipCache;
  let resolver: MembershipResolver;

  beforeEach(() => {
    cache = new MockMembershipCache();
    resolver = new MembershipResolver(
      cache as unknown as MembershipCache,
      makeConfig(),
    );
  });

  it('resolves membership from cache', async () => {
    await cache.upsert({
      membershipId: 'mbr_01',
      orgId: 'org_01',
      entityType: 'person',
      entityId: 'per_01',
      isOwner: false,
      status: 'active',
      groups: ['grp_01'],
    });

    const result = await resolver.resolve('person', 'per_01', 'org_01');
    expect(result).not.toBeNull();
    expect(result!.id).toBe('mbr_01');
    expect(result!.groups).toEqual(['grp_01']);
  });

  it('returns null on cache miss with deny strategy', async () => {
    const result = await resolver.resolve('person', 'per_nonexistent', 'org_01');
    expect(result).toBeNull();
  });

  it('resolves membership by ID', async () => {
    await cache.upsert({
      membershipId: 'mbr_02',
      orgId: 'org_01',
      entityType: 'agent',
      entityId: 'agt_01',
      isOwner: false,
      status: 'active',
      groups: [],
    });

    const result = await resolver.resolveById('mbr_02');
    expect(result).not.toBeNull();
    expect(result!.entityType).toBe('agent');
  });

  it('returns null for unknown membership ID', async () => {
    const result = await resolver.resolveById('mbr_nonexistent');
    expect(result).toBeNull();
  });
});
