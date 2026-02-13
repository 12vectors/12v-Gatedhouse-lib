/**
 * Express middleware — integrates Gatedhouse into Express request lifecycle.
 *
 * Populates req.gatedContext with identity, org, membership, roles,
 * and permissions for every authenticated request.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { GatedContext } from '../types';
import { JwtVerifier, JwtVerificationError } from '../jwt/verifier';
import { MembershipResolver } from '../membership/resolver';
import { PermissionResolver } from '../roles/resolver';
import { DelegationResolver } from '../delegation/resolver';
import { PermissionChecker } from '../permissions/checker';
import { PolicyEngine } from '../policies/engine';
import { AuditLogger } from '../audit/logger';
import { ResolvedConfig } from '../config';
import { MetricsCollector } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('middleware');

// Extend Express Request to include GatedContext
declare global {
  namespace Express {
    interface Request {
      gatedContext?: GatedContext;
    }
  }
}

export interface MiddlewareDeps {
  jwtVerifier: JwtVerifier;
  membershipResolver: MembershipResolver;
  permissionResolver: PermissionResolver;
  delegationResolver: DelegationResolver;
  permissionChecker: PermissionChecker;
  policyEngine: PolicyEngine;
  auditLogger: AuditLogger;
  config: ResolvedConfig;
  metrics?: MetricsCollector;
}

/**
 * Create the core Gatedhouse middleware that populates request context.
 */
export function createMiddleware(deps: MiddlewareDeps): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Extract JWT from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Missing or invalid Authorization header' });
        return;
      }

      const token = authHeader.slice(7);

      // Verify JWT and extract identity
      let verificationResult;
      try {
        verificationResult = await deps.jwtVerifier.verify(token);
      } catch (err) {
        if (err instanceof JwtVerificationError) {
          deps.metrics?.increment('gatedhouse_jwt_verification_total', {
            result: 'failed',
          });
          res.status(401).json({ error: 'Invalid token' });
          return;
        }
        throw err;
      }

      deps.metrics?.increment('gatedhouse_jwt_verification_total', {
        result: 'success',
      });
      deps.metrics?.increment('gatedhouse_identity_type_requests_total', {
        type: verificationResult.identity.type,
      });

      const { identity, claims } = verificationResult;

      // Extract org context
      const orgId = req.headers[deps.config.orgHeader.toLowerCase()] as
        | string
        | undefined;

      if (!orgId && deps.config.orgRequired) {
        res.status(400).json({
          error: `Missing required header: ${deps.config.orgHeader}`,
        });
        return;
      }

      if (!orgId) {
        // No org context but it's optional — set minimal context
        req.gatedContext = {
          identity,
          org: { id: '' },
          membership: {
            id: '',
            entityType: 'person',
            isOwner: false,
            status: 'none',
            groups: [],
          },
          roles: [],
          permissions: [],
          scopes: verificationResult.scopes,
        };
        next();
        return;
      }

      // Map identity type to entity type
      const entityType =
        identity.type === 'human'
          ? 'person'
          : identity.type === 'agent'
            ? 'agent'
            : 'service_account';

      // Resolve membership
      const membership = await deps.membershipResolver.resolve(
        entityType,
        identity.id,
        orgId,
      );

      if (!membership) {
        res.status(403).json({ error: 'Not a member of this organization' });
        return;
      }

      // Resolve delegation if present in claims
      let delegation;
      if (claims.delegation && deps.config.delegation.enabled) {
        delegation = await deps.delegationResolver.resolveById(
          claims.delegation.id,
        );

        // If delegation claim present but delegation not found/invalid, use claim data
        if (!delegation) {
          delegation = {
            id: claims.delegation.id,
            delegatorId: claims.delegation.delegator_id,
            delegatorMembershipId: claims.delegation.delegator_membership_id,
            scopes: claims.delegation.scopes,
            constraints: claims.delegation.constraints,
            expiresAt: claims.delegation.expires_at,
            usesRemaining: claims.delegation.uses_remaining,
          };
        }
      }

      // Resolve permissions
      const permissions = await deps.permissionResolver.resolvePermissions(
        membership.id,
        orgId,
        membership.groups,
      );

      // Resolve roles
      const roles = await deps.permissionResolver.resolveRoles(
        membership.id,
        orgId,
        membership.groups,
      );

      // Build GatedContext
      const ctx: GatedContext = {
        identity,
        org: { id: orgId },
        membership,
        roles,
        permissions,
        scopes: verificationResult.scopes,
        delegation: delegation ?? undefined,
      };

      req.gatedContext = ctx;
      next();
    } catch (err) {
      logger.error({ err }, 'Middleware error');
      res.status(500).json({ error: 'Internal authorization error' });
    }
  };
}

/**
 * Optional auth middleware — populates context if token present, passes through otherwise.
 */
export function createOptionalMiddleware(deps: MiddlewareDeps): RequestHandler {
  const mainMiddleware = createMiddleware(deps);

  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      next();
      return;
    }
    mainMiddleware(req, res, next);
  };
}
