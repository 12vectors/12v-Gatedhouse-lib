/**
 * Admin REST API router — exposes role management endpoints.
 *
 * Each service mounts this router to expose standard authorization
 * management endpoints under /api/{service}/v1/authz/.
 */

import type { Router, Request, Response } from 'express';
import { RoleRepository } from '../roles/repository';
import { RoleAssignmentManager } from '../roles/assignment';
import { PermissionResolver } from '../roles/resolver';
import { PermissionChecker } from '../permissions/checker';
import { MembershipCache } from '../membership/cache';
import { GatedContext, RoleDefinition } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('admin-router');

export interface AdminRouterDeps {
  roleRepo: RoleRepository;
  roleAssignments: RoleAssignmentManager;
  permissionResolver: PermissionResolver;
  permissionChecker: PermissionChecker;
  membershipCache: MembershipCache;
}

/**
 * Create the admin router with authorization management endpoints.
 * Requires Express Router to be passed in (no direct express dependency).
 */
export function createAdminRouter(
  createRouter: () => Router,
  deps: AdminRouterDeps,
  service: string,
): Router {
  const router = createRouter();
  const authzPermission = `${service}:authz:manage`;

  // Helper to enforce authz management permission
  function requireAuthzManage(req: Request, res: Response): GatedContext | null {
    const ctx = req.gatedContext;
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return null;
    }
    const result = deps.permissionChecker.check(ctx, authzPermission);
    if (!result.allowed) {
      res.status(403).json({ error: 'Forbidden' });
      return null;
    }
    return ctx;
  }

  // ─── Role Endpoints ──────────────────────────────────────────

  // List available roles
  router.get('/roles', async (req: Request, res: Response) => {
    const ctx = requireAuthzManage(req, res);
    if (!ctx) return;

    try {
      const roles = await deps.roleRepo.listForOrg(ctx.org.id);
      res.json({ data: roles });
    } catch (err) {
      logger.error({ err }, 'Failed to list roles');
      res.status(500).json({ error: 'Internal error' });
    }
  });

  // Get role details
  router.get('/roles/:roleId', async (req: Request, res: Response) => {
    const ctx = requireAuthzManage(req, res);
    if (!ctx) return;

    try {
      const role = await deps.roleRepo.resolve(ctx.org.id, req.params.roleId);
      if (!role) {
        res.status(404).json({ error: 'Role not found' });
        return;
      }
      res.json({ data: role });
    } catch (err) {
      logger.error({ err }, 'Failed to get role');
      res.status(500).json({ error: 'Internal error' });
    }
  });

  // Create custom role
  router.post('/roles', async (req: Request, res: Response) => {
    const ctx = requireAuthzManage(req, res);
    if (!ctx) return;

    try {
      const { key, name, description, permissions, inherits } = req.body as RoleDefinition;
      if (!key || !name) {
        res.status(400).json({ error: 'key and name are required' });
        return;
      }

      const role = await deps.roleRepo.create(ctx.org.id, {
        key,
        name,
        description,
        permissions: permissions ?? [],
        inherits: inherits ?? [],
      });
      res.status(201).json({ data: role });
    } catch (err) {
      logger.error({ err }, 'Failed to create role');
      res.status(500).json({ error: 'Internal error' });
    }
  });

  // Update custom role
  router.patch('/roles/:roleId', async (req: Request, res: Response) => {
    const ctx = requireAuthzManage(req, res);
    if (!ctx) return;

    try {
      const role = await deps.roleRepo.update(
        ctx.org.id,
        req.params.roleId,
        req.body,
      );
      if (!role) {
        res.status(404).json({ error: 'Role not found or is a system role' });
        return;
      }
      res.json({ data: role });
    } catch (err) {
      logger.error({ err }, 'Failed to update role');
      res.status(500).json({ error: 'Internal error' });
    }
  });

  // Delete custom role
  router.delete('/roles/:roleId', async (req: Request, res: Response) => {
    const ctx = requireAuthzManage(req, res);
    if (!ctx) return;

    try {
      const deleted = await deps.roleRepo.delete(ctx.org.id, req.params.roleId);
      if (!deleted) {
        res.status(404).json({ error: 'Role not found or is a system role' });
        return;
      }
      res.status(204).send();
    } catch (err) {
      logger.error({ err }, 'Failed to delete role');
      res.status(500).json({ error: 'Internal error' });
    }
  });

  // ─── Member Role Endpoints ───────────────────────────────────

  // List roles for a member
  router.get(
    '/members/:membershipId/roles',
    async (req: Request, res: Response) => {
      const ctx = requireAuthzManage(req, res);
      if (!ctx) return;

      try {
        const assignments = await deps.roleAssignments.forMembership(
          req.params.membershipId,
        );
        res.json({ data: assignments });
      } catch (err) {
        logger.error({ err }, 'Failed to list member roles');
        res.status(500).json({ error: 'Internal error' });
      }
    },
  );

  // Assign a role to a member
  router.post(
    '/members/:membershipId/roles',
    async (req: Request, res: Response) => {
      const ctx = requireAuthzManage(req, res);
      if (!ctx) return;

      try {
        const { role_id } = req.body as { role_id: string };
        if (!role_id) {
          res.status(400).json({ error: 'role_id is required' });
          return;
        }

        // Verify role exists
        const role = await deps.roleRepo.resolve(ctx.org.id, role_id);
        if (!role) {
          res.status(404).json({ error: 'Role not found' });
          return;
        }

        await deps.roleAssignments.assign(
          req.params.membershipId,
          role_id,
          ctx.org.id,
          ctx.identity.id,
        );

        // Rebuild permissions
        const cached = await deps.membershipCache.findById(
          req.params.membershipId,
        );
        if (cached) {
          await deps.permissionResolver.rebuildForMembership(
            req.params.membershipId,
            ctx.org.id,
            cached.groups,
          );
        }

        res.status(201).json({ data: { membership_id: req.params.membershipId, role_id } });
      } catch (err) {
        logger.error({ err }, 'Failed to assign role');
        res.status(500).json({ error: 'Internal error' });
      }
    },
  );

  // Revoke a role from a member
  router.delete(
    '/members/:membershipId/roles/:roleId',
    async (req: Request, res: Response) => {
      const ctx = requireAuthzManage(req, res);
      if (!ctx) return;

      try {
        const revoked = await deps.roleAssignments.revoke(
          req.params.membershipId,
          req.params.roleId,
        );
        if (!revoked) {
          res.status(404).json({ error: 'Role assignment not found' });
          return;
        }

        // Rebuild permissions
        const cached = await deps.membershipCache.findById(
          req.params.membershipId,
        );
        if (cached) {
          await deps.permissionResolver.rebuildForMembership(
            req.params.membershipId,
            ctx.org.id,
            cached.groups,
          );
        }

        res.status(204).send();
      } catch (err) {
        logger.error({ err }, 'Failed to revoke role');
        res.status(500).json({ error: 'Internal error' });
      }
    },
  );

  // ─── Group Role Endpoints ────────────────────────────────────

  // List roles for a group
  router.get(
    '/groups/:groupId/roles',
    async (req: Request, res: Response) => {
      const ctx = requireAuthzManage(req, res);
      if (!ctx) return;

      try {
        const assignments = await deps.roleAssignments.forGroup(
          req.params.groupId,
        );
        res.json({ data: assignments });
      } catch (err) {
        logger.error({ err }, 'Failed to list group roles');
        res.status(500).json({ error: 'Internal error' });
      }
    },
  );

  // Assign a role to a group
  router.post(
    '/groups/:groupId/roles',
    async (req: Request, res: Response) => {
      const ctx = requireAuthzManage(req, res);
      if (!ctx) return;

      try {
        const { role_id } = req.body as { role_id: string };
        if (!role_id) {
          res.status(400).json({ error: 'role_id is required' });
          return;
        }

        await deps.roleAssignments.assignToGroup(
          req.params.groupId,
          role_id,
          ctx.org.id,
          ctx.identity.id,
        );

        res.status(201).json({ data: { group_id: req.params.groupId, role_id } });
      } catch (err) {
        logger.error({ err }, 'Failed to assign role to group');
        res.status(500).json({ error: 'Internal error' });
      }
    },
  );

  // Revoke a role from a group
  router.delete(
    '/groups/:groupId/roles/:roleId',
    async (req: Request, res: Response) => {
      const ctx = requireAuthzManage(req, res);
      if (!ctx) return;

      try {
        const revoked = await deps.roleAssignments.revokeFromGroup(
          req.params.groupId,
          req.params.roleId,
        );
        if (!revoked) {
          res.status(404).json({ error: 'Group role assignment not found' });
          return;
        }

        res.status(204).send();
      } catch (err) {
        logger.error({ err }, 'Failed to revoke role from group');
        res.status(500).json({ error: 'Internal error' });
      }
    },
  );

  // ─── Permission Check Endpoint ───────────────────────────────

  // Check permissions (for admin UIs)
  router.post('/check', async (req: Request, res: Response) => {
    const ctx = requireAuthzManage(req, res);
    if (!ctx) return;

    try {
      const { membership_id, permissions } = req.body as {
        membership_id: string;
        permissions: string[];
      };

      if (!membership_id || !permissions?.length) {
        res.status(400).json({
          error: 'membership_id and permissions are required',
        });
        return;
      }

      // Resolve the target membership's permissions
      const cached = await deps.membershipCache.findById(membership_id);
      if (!cached) {
        res.status(404).json({ error: 'Membership not found' });
        return;
      }

      const resolvedPerms = await deps.permissionResolver.resolvePermissions(
        membership_id,
        ctx.org.id,
        cached.groups,
      );

      const results: Record<string, { allowed: boolean; source: string | null }> = {};
      for (const perm of permissions) {
        const check = deps.permissionChecker.check(
          { ...ctx, membership: { ...ctx.membership, id: membership_id }, permissions: resolvedPerms },
          perm,
        );
        results[perm] = check;
      }

      res.json({
        data: {
          [membership_id]: results,
        },
      });
    } catch (err) {
      logger.error({ err }, 'Failed to check permissions');
      res.status(500).json({ error: 'Internal error' });
    }
  });

  return router;
}
