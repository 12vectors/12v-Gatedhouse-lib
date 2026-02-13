import { resolveConfig } from '../../src/config';

describe('resolveConfig', () => {
  const validConfig = {
    jwksUrl: 'https://sphinx.internal/jwks',
    database: { connectionString: 'postgresql://localhost/test' },
    service: 'files',
  };

  it('resolves minimal config with defaults', () => {
    const resolved = resolveConfig(validConfig);
    expect(resolved.jwksUrl).toBe('https://sphinx.internal/jwks');
    expect(resolved.service).toBe('files');
    expect(resolved.orgHeader).toBe('X-Org-Id');
    expect(resolved.orgRequired).toBe(true);
    expect(resolved.cacheMissStrategy).toBe('fetch');
    expect(resolved.defaultRole).toBe('member');
    expect(resolved.audit.enabled).toBe(true);
    expect(resolved.audit.logDenied).toBe(true);
    expect(resolved.audit.logAllowed).toBe(false);
    expect(resolved.delegation.enabled).toBe(true);
    expect(resolved.database.tablePrefix).toBe('gatedhouse_');
    expect(resolved.database.migrationsTable).toBe('gatedhouse_migrations');
    expect(resolved.baseRoles).toHaveLength(4);
  });

  it('respects custom config values', () => {
    const resolved = resolveConfig({
      ...validConfig,
      orgHeader: 'X-Custom-Org',
      orgRequired: false,
      cacheMissStrategy: 'deny',
      defaultRole: 'viewer',
      jwksCacheTtl: 7200,
    });
    expect(resolved.orgHeader).toBe('X-Custom-Org');
    expect(resolved.orgRequired).toBe(false);
    expect(resolved.cacheMissStrategy).toBe('deny');
    expect(resolved.defaultRole).toBe('viewer');
    expect(resolved.jwksCacheTtl).toBe(7200);
  });

  it('throws for missing jwksUrl', () => {
    expect(() =>
      resolveConfig({ jwksUrl: '', database: { connectionString: 'x' }, service: 'test' }),
    ).toThrow('jwksUrl is required');
  });

  it('throws for missing database connection', () => {
    expect(() =>
      resolveConfig({ jwksUrl: 'http://x', database: { connectionString: '' }, service: 'test' }),
    ).toThrow('database.connectionString is required');
  });

  it('throws for missing service name', () => {
    expect(() =>
      resolveConfig({ jwksUrl: 'http://x', database: { connectionString: 'x' }, service: '' }),
    ).toThrow('service name is required');
  });

  it('includes base roles with correct structure', () => {
    const resolved = resolveConfig(validConfig);
    const owner = resolved.baseRoles.find((r) => r.key === 'owner');
    expect(owner).toBeDefined();
    expect(owner!.permissions).toEqual(['*:*:*']);
    expect(owner!.isSystem).toBe(true);

    const viewer = resolved.baseRoles.find((r) => r.key === 'viewer');
    expect(viewer).toBeDefined();
    expect(viewer!.isSystem).toBe(true);
  });
});
