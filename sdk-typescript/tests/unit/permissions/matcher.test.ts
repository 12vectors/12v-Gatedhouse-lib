import {
  matchPermission,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  expandWildcards,
  intersectPermissions,
} from '../../../src/permissions/matcher';

describe('matchPermission', () => {
  it('matches exact permissions', () => {
    expect(matchPermission('files:documents:read', 'files:documents:read')).toBe(true);
  });

  it('rejects non-matching permissions', () => {
    expect(matchPermission('files:documents:read', 'files:documents:write')).toBe(false);
  });

  it('matches wildcard in service segment', () => {
    expect(matchPermission('*:documents:read', 'files:documents:read')).toBe(true);
  });

  it('matches wildcard in resource segment', () => {
    expect(matchPermission('files:*:read', 'files:documents:read')).toBe(true);
    expect(matchPermission('files:*:read', 'files:storage:read')).toBe(true);
  });

  it('matches wildcard in action segment', () => {
    expect(matchPermission('files:documents:*', 'files:documents:read')).toBe(true);
    expect(matchPermission('files:documents:*', 'files:documents:write')).toBe(true);
    expect(matchPermission('files:documents:*', 'files:documents:delete')).toBe(true);
  });

  it('matches full wildcard (superadmin)', () => {
    expect(matchPermission('*:*:*', 'files:documents:read')).toBe(true);
    expect(matchPermission('*:*:*', 'billing:invoices:write')).toBe(true);
    expect(matchPermission('*:*:*', 'workflow:instances:execute')).toBe(true);
  });

  it('matches multiple wildcards', () => {
    expect(matchPermission('files:*:*', 'files:documents:read')).toBe(true);
    expect(matchPermission('*:documents:*', 'files:documents:write')).toBe(true);
  });

  it('rejects partial mismatches with wildcards', () => {
    expect(matchPermission('files:*:read', 'billing:invoices:read')).toBe(false);
    expect(matchPermission('files:documents:*', 'files:storage:read')).toBe(false);
  });

  it('handles non-standard format gracefully', () => {
    expect(matchPermission('simple', 'simple')).toBe(true);
    expect(matchPermission('simple', 'other')).toBe(false);
  });
});

describe('hasPermission', () => {
  it('returns true when permission set contains exact match', () => {
    const perms = ['files:documents:read', 'files:documents:write'];
    expect(hasPermission(perms, 'files:documents:read')).toBe(true);
  });

  it('returns true when permission set contains wildcard match', () => {
    const perms = ['files:*:read', 'billing:invoices:write'];
    expect(hasPermission(perms, 'files:documents:read')).toBe(true);
  });

  it('returns false when no match found', () => {
    const perms = ['files:documents:read'];
    expect(hasPermission(perms, 'files:documents:delete')).toBe(false);
  });

  it('returns false for empty permission set', () => {
    expect(hasPermission([], 'files:documents:read')).toBe(false);
  });
});

describe('hasAllPermissions', () => {
  it('returns true when all permissions are satisfied', () => {
    const perms = ['files:*:*', 'billing:invoices:read'];
    expect(hasAllPermissions(perms, ['files:documents:read', 'files:documents:write'])).toBe(true);
  });

  it('returns false when any permission is missing', () => {
    const perms = ['files:documents:read'];
    expect(hasAllPermissions(perms, ['files:documents:read', 'files:documents:write'])).toBe(false);
  });

  it('returns true for empty required set', () => {
    expect(hasAllPermissions(['files:documents:read'], [])).toBe(true);
  });
});

describe('hasAnyPermission', () => {
  it('returns true when any permission matches', () => {
    const perms = ['files:documents:read'];
    expect(hasAnyPermission(perms, ['files:documents:read', 'files:documents:write'])).toBe(true);
  });

  it('returns false when no permissions match', () => {
    const perms = ['billing:invoices:read'];
    expect(hasAnyPermission(perms, ['files:documents:read', 'files:documents:write'])).toBe(false);
  });

  it('returns false for empty required set', () => {
    expect(hasAnyPermission(['files:documents:read'], [])).toBe(false);
  });
});

describe('expandWildcards', () => {
  const knownPerms = [
    'files:documents:read',
    'files:documents:write',
    'files:documents:delete',
    'files:storage:read',
    'billing:invoices:read',
  ];

  it('expands service wildcard', () => {
    const result = expandWildcards(['files:*:read'], knownPerms);
    expect(result).toContain('files:documents:read');
    expect(result).toContain('files:storage:read');
    expect(result).not.toContain('billing:invoices:read');
    // Also keeps the wildcard
    expect(result).toContain('files:*:read');
  });

  it('passes through non-wildcard permissions', () => {
    const result = expandWildcards(['files:documents:read'], knownPerms);
    expect(result).toEqual(['files:documents:read']);
  });

  it('expands full wildcard to all known', () => {
    const result = expandWildcards(['*:*:*'], knownPerms);
    for (const p of knownPerms) {
      expect(result).toContain(p);
    }
  });
});

describe('intersectPermissions', () => {
  it('computes intersection of two permission sets', () => {
    const setA = ['files:documents:read', 'files:documents:write', 'billing:*:*'];
    const setB = ['files:documents:write', 'workflow:*:*'];
    const result = intersectPermissions(setA, setB);
    expect(result).toContain('files:documents:write');
    expect(result).not.toContain('files:documents:read');
  });

  it('handles wildcard matching in intersection', () => {
    const setA = ['files:*:*'];
    const setB = ['files:documents:read', 'billing:invoices:read'];
    const result = intersectPermissions(setA, setB);
    expect(result).toContain('files:documents:read');
    expect(result).not.toContain('billing:invoices:read');
  });

  it('returns empty for disjoint sets', () => {
    const setA = ['files:documents:read'];
    const setB = ['billing:invoices:write'];
    const result = intersectPermissions(setA, setB);
    expect(result).toHaveLength(0);
  });

  it('handles empty sets', () => {
    expect(intersectPermissions([], ['files:documents:read'])).toHaveLength(0);
    expect(intersectPermissions(['files:documents:read'], [])).toHaveLength(0);
  });

  it('computes three-way delegation intersection correctly', () => {
    // Simulates: DelegationScopes ∩ AgentMaxScope ∩ DelegatorPermissions
    const delegationScopes = ['files:documents:write', 'workflow:*:*'];
    const agentMaxScope = ['files:*:*', 'workflow:instances:*'];
    const delegatorPerms = ['files:documents:read', 'files:documents:write', 'billing:*:*'];

    const step1 = intersectPermissions(delegationScopes, agentMaxScope);
    const step2 = intersectPermissions(step1, delegatorPerms);

    expect(step2).toContain('files:documents:write');
    // workflow:*:* ∩ workflow:instances:* = workflow:instances:* but delegator doesn't have it
    expect(step2).not.toContain('billing:*:*');
  });
});
