import { PolicyEngine } from '../../../src/policies/engine';
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
    permissions: ['files:documents:read'],
    ...overrides,
  };
}

describe('PolicyEngine', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  describe('register/has/list', () => {
    it('registers and tracks policies', () => {
      engine.register('test:policy', () => true);
      expect(engine.has('test:policy')).toBe(true);
      expect(engine.list()).toContain('test:policy');
    });

    it('unregisters policies', () => {
      engine.register('test:policy', () => true);
      engine.unregister('test:policy');
      expect(engine.has('test:policy')).toBe(false);
    });
  });

  describe('evaluate', () => {
    it('evaluates a simple allow policy', async () => {
      engine.register('always:allow', () => true);
      const result = await engine.evaluate(makeContext(), 'always:allow');
      expect(result).toBe(true);
    });

    it('evaluates a simple deny policy', async () => {
      engine.register('always:deny', () => false);
      const result = await engine.evaluate(makeContext(), 'always:deny');
      expect(result).toBe(false);
    });

    it('evaluates context-based policy', async () => {
      engine.register('owner:only', (ctx) => ctx.membership.isOwner);

      expect(await engine.evaluate(makeContext(), 'owner:only')).toBe(false);
      expect(
        await engine.evaluate(
          makeContext({
            membership: { id: 'mbr_01', entityType: 'person', isOwner: true, status: 'active', groups: [] },
          }),
          'owner:only',
        ),
      ).toBe(true);
    });

    it('evaluates resource attribute policy', async () => {
      engine.register('document:edit', (ctx, resource) => {
        return resource.createdBy === ctx.membership.id;
      });

      const ctx = makeContext();
      expect(await engine.evaluate(ctx, 'document:edit', { createdBy: 'mbr_01H8X' })).toBe(true);
      expect(await engine.evaluate(ctx, 'document:edit', { createdBy: 'mbr_other' })).toBe(false);
    });

    it('evaluates async policies', async () => {
      engine.register('async:policy', async (_ctx, resource) => {
        await new Promise((r) => setTimeout(r, 10));
        return resource.allowed === true;
      });

      expect(await engine.evaluate(makeContext(), 'async:policy', { allowed: true })).toBe(true);
      expect(await engine.evaluate(makeContext(), 'async:policy', { allowed: false })).toBe(false);
    });

    it('returns false for non-existent policy', async () => {
      const result = await engine.evaluate(makeContext(), 'nonexistent');
      expect(result).toBe(false);
    });

    it('fails closed on policy error', async () => {
      engine.register('error:policy', () => {
        throw new Error('Policy crashed');
      });
      const result = await engine.evaluate(makeContext(), 'error:policy');
      expect(result).toBe(false);
    });
  });
});
