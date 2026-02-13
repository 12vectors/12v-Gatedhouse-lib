import { PermissionChecker } from '../../../src/permissions/checker';
import { GatedContext } from '../../../src/types';

function makeContext(overrides: Partial<GatedContext> = {}): GatedContext {
  return {
    identity: {
      id: 'per_01H8X',
      type: 'human',
      email: 'test@example.com',
      authMethod: 'password',
    },
    org: { id: 'org_01H8X' },
    membership: {
      id: 'mbr_01H8X',
      entityType: 'person',
      isOwner: false,
      status: 'active',
      groups: [],
    },
    roles: ['member'],
    permissions: ['files:documents:read', 'files:documents:write'],
    ...overrides,
  };
}

describe('PermissionChecker', () => {
  let checker: PermissionChecker;

  beforeEach(() => {
    checker = new PermissionChecker();
  });

  describe('check', () => {
    it('allows when permission exists', () => {
      const ctx = makeContext();
      const result = checker.check(ctx, 'files:documents:read');
      expect(result.allowed).toBe(true);
    });

    it('denies when permission missing', () => {
      const ctx = makeContext();
      const result = checker.check(ctx, 'files:documents:delete');
      expect(result.allowed).toBe(false);
      expect(result.source).toBeNull();
    });

    it('denies suspended membership', () => {
      const ctx = makeContext({
        membership: {
          id: 'mbr_01H8X',
          entityType: 'person',
          isOwner: false,
          status: 'suspended',
          groups: [],
        },
      });
      const result = checker.check(ctx, 'files:documents:read');
      expect(result.allowed).toBe(false);
    });

    it('respects wildcard permissions', () => {
      const ctx = makeContext({ permissions: ['files:*:*'] });
      const result = checker.check(ctx, 'files:documents:delete');
      expect(result.allowed).toBe(true);
    });

    it('handles superadmin wildcard', () => {
      const ctx = makeContext({ permissions: ['*:*:*'] });
      expect(checker.check(ctx, 'any:resource:action').allowed).toBe(true);
    });
  });

  describe('checkAll', () => {
    it('returns true when all permissions present', () => {
      const ctx = makeContext();
      expect(checker.checkAll(ctx, ['files:documents:read', 'files:documents:write'])).toBe(true);
    });

    it('returns false when any permission missing', () => {
      const ctx = makeContext();
      expect(checker.checkAll(ctx, ['files:documents:read', 'files:documents:delete'])).toBe(false);
    });
  });

  describe('checkAny', () => {
    it('returns true when any permission matches', () => {
      const ctx = makeContext();
      expect(checker.checkAny(ctx, ['files:documents:read', 'billing:invoices:read'])).toBe(true);
    });

    it('returns false when no permissions match', () => {
      const ctx = makeContext();
      expect(checker.checkAny(ctx, ['billing:invoices:read', 'billing:invoices:write'])).toBe(false);
    });
  });

  describe('scoped check', () => {
    it('intersects permissions with scopes', () => {
      const ctx = makeContext({
        permissions: ['files:documents:read', 'files:documents:write', 'billing:invoices:read'],
        scopes: ['files:documents:read', 'billing:*:*'],
      });

      // files:documents:read is in both perms and scopes
      expect(checker.check(ctx, 'files:documents:read').allowed).toBe(true);

      // billing:invoices:read matches via scope wildcard
      expect(checker.check(ctx, 'billing:invoices:read').allowed).toBe(true);
    });
  });

  describe('delegated check', () => {
    it('allows when permission in delegation scope and context permissions', () => {
      const ctx = makeContext({
        permissions: ['files:*:*'],
        delegation: {
          id: 'dlg_01H8X',
          delegatorId: 'per_delegator',
          delegatorMembershipId: 'mbr_delegator',
          scopes: ['files:documents:write'],
          constraints: {},
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      });

      expect(checker.check(ctx, 'files:documents:write').allowed).toBe(true);
    });

    it('denies expired delegation', () => {
      const ctx = makeContext({
        permissions: ['files:*:*'],
        delegation: {
          id: 'dlg_01H8X',
          delegatorId: 'per_delegator',
          delegatorMembershipId: 'mbr_delegator',
          scopes: ['files:documents:write'],
          constraints: {},
          expiresAt: new Date(Date.now() - 1000).toISOString(),
        },
      });

      expect(checker.check(ctx, 'files:documents:write').allowed).toBe(false);
    });

    it('denies exhausted delegation', () => {
      const ctx = makeContext({
        permissions: ['files:*:*'],
        delegation: {
          id: 'dlg_01H8X',
          delegatorId: 'per_delegator',
          delegatorMembershipId: 'mbr_delegator',
          scopes: ['files:documents:write'],
          constraints: {},
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          usesRemaining: 0,
        },
      });

      expect(checker.check(ctx, 'files:documents:write').allowed).toBe(false);
    });

    it('denies when permission outside delegation scope', () => {
      const ctx = makeContext({
        permissions: ['files:*:*'],
        delegation: {
          id: 'dlg_01H8X',
          delegatorId: 'per_delegator',
          delegatorMembershipId: 'mbr_delegator',
          scopes: ['files:documents:read'],
          constraints: {},
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      });

      expect(checker.check(ctx, 'files:documents:write').allowed).toBe(false);
    });
  });

  describe('checkMany', () => {
    it('returns results for all requested permissions', () => {
      const ctx = makeContext();
      const results = checker.checkMany(ctx, [
        'files:documents:read',
        'files:documents:write',
        'files:documents:delete',
      ]);

      expect(results.get('files:documents:read')?.allowed).toBe(true);
      expect(results.get('files:documents:write')?.allowed).toBe(true);
      expect(results.get('files:documents:delete')?.allowed).toBe(false);
    });
  });
});
