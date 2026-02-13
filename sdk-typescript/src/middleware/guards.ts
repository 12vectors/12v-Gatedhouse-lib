/**
 * Permission guard middleware — route-level authorization enforcement.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { GatedContext, IdentityType } from '../types';
import { PermissionChecker } from '../permissions/checker';
import { PolicyEngine } from '../policies/engine';
import { AuditLogger } from '../audit/logger';

export interface GuardDeps {
  permissionChecker: PermissionChecker;
  policyEngine: PolicyEngine;
  auditLogger: AuditLogger;
}

function getContext(req: Request): GatedContext | null {
  return req.gatedContext ?? null;
}

/**
 * Require that the request is authenticated (GatedContext must be present).
 */
export function requireAuth(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx || !ctx.identity.id) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }
    if (ctx.membership.status === 'suspended') {
      res.status(403).json({ error: 'Membership suspended' });
      return;
    }
    next();
  };
}

/**
 * Require a specific permission.
 */
export function requirePermission(
  permission: string,
  deps: GuardDeps,
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const result = deps.permissionChecker.check(ctx, permission);
    if (!result.allowed) {
      await deps.auditLogger.log({
        action: permission,
        result: 'denied',
        ctx,
        reason: 'Missing required permission',
      });
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Require all of the specified permissions.
 */
export function requireAllPermissions(
  permissions: string[],
  deps: GuardDeps,
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!deps.permissionChecker.checkAll(ctx, permissions)) {
      await deps.auditLogger.log({
        action: permissions.join(','),
        result: 'denied',
        ctx,
        reason: 'Missing one or more required permissions',
      });
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Require any one of the specified permissions.
 */
export function requireAnyPermission(
  permissions: string[],
  deps: GuardDeps,
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!deps.permissionChecker.checkAny(ctx, permissions)) {
      await deps.auditLogger.log({
        action: permissions.join(','),
        result: 'denied',
        ctx,
        reason: 'None of the required permissions found',
      });
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Require the authenticated identity to be the organization owner.
 */
export function requireOwner(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!ctx.membership.isOwner) {
      res.status(403).json({ error: 'Owner access required' });
      return;
    }

    next();
  };
}

/**
 * Require a specific identity type.
 */
export function requireIdentityType(
  type: IdentityType,
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (ctx.identity.type !== type) {
      res.status(403).json({
        error: `This action requires ${type} identity`,
      });
      return;
    }

    next();
  };
}

/**
 * Require a custom policy evaluation to pass.
 */
export function requirePolicy(
  policyName: string,
  resourceFn: (req: Request) => Promise<Record<string, unknown>> | Record<string, unknown>,
  deps: GuardDeps,
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ctx = getContext(req);
    if (!ctx) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    try {
      const resource = await resourceFn(req);
      const allowed = await deps.policyEngine.evaluate(
        ctx,
        policyName,
        resource,
      );

      if (!allowed) {
        await deps.auditLogger.log({
          action: `policy:${policyName}`,
          result: 'denied',
          ctx,
          reason: 'Policy evaluation denied',
        });
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      next();
    } catch (err) {
      res.status(500).json({ error: 'Policy evaluation error' });
    }
  };
}
