/**
 * JWT verification using JWKS from Sphinx.
 *
 * Extracts identity claims from verified tokens to populate
 * the GatedContext identity fields.
 */

import * as jose from 'jose';
import { JwksClient } from './jwks';
import { Identity, AuthMethod, IdentityType } from '../types';
import { createLogger } from '../logger';

const logger = createLogger('jwt-verifier');

export interface JwtClaims {
  sub: string;
  email?: string;
  name?: string;
  identity_type: IdentityType;
  auth_method: AuthMethod;
  mfa_verified?: boolean;
  scopes?: string[];
  delegation?: {
    id: string;
    delegator_id: string;
    delegator_membership_id: string;
    scopes: string[];
    constraints: Record<string, unknown>;
    expires_at: string;
    uses_remaining?: number;
  };
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string | string[];
}

export interface VerificationResult {
  identity: Identity;
  claims: JwtClaims;
  scopes?: string[];
}

export class JwtVerifier {
  constructor(private jwksClient: JwksClient) {}

  async verify(token: string): Promise<VerificationResult> {
    const { protectedHeader } = jose.decodeProtectedHeader
      ? { protectedHeader: jose.decodeProtectedHeader(token) }
      : { protectedHeader: this.decodeHeader(token) };

    const kid = protectedHeader.kid;
    if (!kid) {
      throw new JwtVerificationError('JWT missing kid in header');
    }

    const key = await this.jwksClient.getKey(kid);

    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(token, key);
      payload = result.payload;
    } catch (err) {
      logger.warn({ err }, 'JWT verification failed');
      throw new JwtVerificationError(
        err instanceof Error ? err.message : 'JWT verification failed',
      );
    }

    const claims = payload as unknown as JwtClaims;

    if (!claims.sub) {
      throw new JwtVerificationError('JWT missing sub claim');
    }

    if (!claims.identity_type) {
      throw new JwtVerificationError('JWT missing identity_type claim');
    }

    const identity: Identity = {
      id: claims.sub,
      type: claims.identity_type,
      email: claims.email,
      name: claims.name,
      authMethod: claims.auth_method ?? 'password',
      mfaVerified: claims.mfa_verified,
    };

    return {
      identity,
      claims,
      scopes: claims.scopes,
    };
  }

  private decodeHeader(token: string): jose.ProtectedHeaderParameters {
    const [headerB64] = token.split('.');
    if (!headerB64) {
      throw new JwtVerificationError('Invalid JWT format');
    }
    try {
      const decoded = Buffer.from(headerB64, 'base64url').toString('utf-8');
      return JSON.parse(decoded) as jose.ProtectedHeaderParameters;
    } catch {
      throw new JwtVerificationError('Failed to decode JWT header');
    }
  }
}

export class JwtVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwtVerificationError';
  }
}
