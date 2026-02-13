import { DelegationResolver } from '../../../src/delegation/resolver';
import { DelegationCache } from '../../../src/delegation/cache';
import { CachedDelegation } from '../../../src/types';

// Mock the DelegationCache
class MockDelegationCache {
  private delegations: Map<string, CachedDelegation> = new Map();

  async upsert(d: Omit<CachedDelegation, 'syncedAt'>): Promise<void> {
    this.delegations.set(d.delegationId, { ...d, syncedAt: new Date() });
  }

  async findActiveForAgent(agentId: string, orgId: string): Promise<CachedDelegation | null> {
    for (const d of this.delegations.values()) {
      if (
        d.agentId === agentId &&
        d.orgId === orgId &&
        d.status === 'active' &&
        new Date(d.expiresAt) > new Date() &&
        (d.maxUses === null || d.useCount < d.maxUses)
      ) {
        return d;
      }
    }
    return null;
  }

  async findById(delegationId: string): Promise<CachedDelegation | null> {
    return this.delegations.get(delegationId) ?? null;
  }
}

describe('DelegationResolver', () => {
  let cache: MockDelegationCache;
  let resolver: DelegationResolver;

  beforeEach(() => {
    cache = new MockDelegationCache();
    resolver = new DelegationResolver(cache as unknown as DelegationCache);
  });

  it('resolves an active delegation for an agent', async () => {
    await cache.upsert({
      delegationId: 'dlg_01',
      agentId: 'agt_01',
      delegatorId: 'per_01',
      delegatorMembershipId: 'mbr_01',
      orgId: 'org_01',
      scopes: ['files:documents:read'],
      constraints: {},
      maxUses: null,
      useCount: 0,
      status: 'active',
      expiresAt: new Date(Date.now() + 3600000),
    });

    const result = await resolver.resolve('agt_01', 'org_01');
    expect(result).not.toBeNull();
    expect(result!.id).toBe('dlg_01');
    expect(result!.scopes).toEqual(['files:documents:read']);
  });

  it('returns null for expired delegation', async () => {
    await cache.upsert({
      delegationId: 'dlg_02',
      agentId: 'agt_01',
      delegatorId: 'per_01',
      delegatorMembershipId: 'mbr_01',
      orgId: 'org_01',
      scopes: ['files:documents:read'],
      constraints: {},
      maxUses: null,
      useCount: 0,
      status: 'active',
      expiresAt: new Date(Date.now() - 1000),
    });

    const result = await resolver.resolve('agt_01', 'org_01');
    expect(result).toBeNull();
  });

  it('returns null for exhausted delegation', async () => {
    await cache.upsert({
      delegationId: 'dlg_03',
      agentId: 'agt_01',
      delegatorId: 'per_01',
      delegatorMembershipId: 'mbr_01',
      orgId: 'org_01',
      scopes: ['files:documents:read'],
      constraints: {},
      maxUses: 5,
      useCount: 5,
      status: 'active',
      expiresAt: new Date(Date.now() + 3600000),
    });

    const result = await resolver.resolve('agt_01', 'org_01');
    expect(result).toBeNull();
  });

  it('returns null when no delegation exists', async () => {
    const result = await resolver.resolve('agt_nonexistent', 'org_01');
    expect(result).toBeNull();
  });

  it('resolves delegation by ID', async () => {
    await cache.upsert({
      delegationId: 'dlg_04',
      agentId: 'agt_01',
      delegatorId: 'per_01',
      delegatorMembershipId: 'mbr_01',
      orgId: 'org_01',
      scopes: ['files:*:*'],
      constraints: { max_cost: 100 },
      maxUses: 10,
      useCount: 3,
      status: 'active',
      expiresAt: new Date(Date.now() + 3600000),
    });

    const result = await resolver.resolveById('dlg_04');
    expect(result).not.toBeNull();
    expect(result!.usesRemaining).toBe(7);
    expect(result!.constraints).toEqual({ max_cost: 100 });
  });

  it('returns null for revoked delegation by ID', async () => {
    await cache.upsert({
      delegationId: 'dlg_05',
      agentId: 'agt_01',
      delegatorId: 'per_01',
      delegatorMembershipId: 'mbr_01',
      orgId: 'org_01',
      scopes: ['files:*:*'],
      constraints: {},
      maxUses: null,
      useCount: 0,
      status: 'revoked',
      expiresAt: new Date(Date.now() + 3600000),
    });

    const result = await resolver.resolveById('dlg_05');
    expect(result).toBeNull();
  });
});
