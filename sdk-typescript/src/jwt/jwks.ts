/**
 * JWKS fetching and caching.
 *
 * Retrieves JSON Web Key Sets from the Sphinx auth service
 * and caches them locally to avoid per-request network calls.
 */

import * as jose from 'jose';
import { createLogger } from '../logger';

const logger = createLogger('jwks');

export class JwksClient {
  private jwks: jose.JSONWebKeySet | null = null;
  private lastFetch: number = 0;
  private fetchPromise: Promise<jose.JSONWebKeySet> | null = null;

  constructor(
    private jwksUrl: string,
    private cacheTtlMs: number,
  ) {}

  async getKeySet(): Promise<jose.JSONWebKeySet> {
    const now = Date.now();

    if (this.jwks && now - this.lastFetch < this.cacheTtlMs) {
      return this.jwks;
    }

    // Coalesce concurrent fetches
    if (this.fetchPromise) {
      return this.fetchPromise;
    }

    this.fetchPromise = this.fetchJwks();
    try {
      const jwks = await this.fetchPromise;
      this.jwks = jwks;
      this.lastFetch = now;
      return jwks;
    } finally {
      this.fetchPromise = null;
    }
  }

  async getKey(kid: string): Promise<jose.KeyLike | Uint8Array> {
    let keySet = await this.getKeySet();

    // If kid not found, force refresh in case keys rotated
    const key = keySet.keys.find((k) => k.kid === kid);
    if (!key) {
      logger.info({ kid }, 'Key ID not found in cache, forcing JWKS refresh');
      this.lastFetch = 0;
      keySet = await this.getKeySet();
      const refreshedKey = keySet.keys.find((k) => k.kid === kid);
      if (!refreshedKey) {
        throw new JwksKeyNotFoundError(kid);
      }
      return jose.importJWK(refreshedKey);
    }

    return jose.importJWK(key);
  }

  private async fetchJwks(): Promise<jose.JSONWebKeySet> {
    logger.info({ url: this.jwksUrl }, 'Fetching JWKS');
    const response = await fetch(this.jwksUrl);
    if (!response.ok) {
      throw new JwksFetchError(
        `Failed to fetch JWKS: ${response.status} ${response.statusText}`,
      );
    }
    const data = (await response.json()) as jose.JSONWebKeySet;
    logger.info(
      { keyCount: data.keys?.length ?? 0 },
      'JWKS fetched successfully',
    );
    return data;
  }

  clearCache(): void {
    this.jwks = null;
    this.lastFetch = 0;
  }
}

export class JwksFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwksFetchError';
  }
}

export class JwksKeyNotFoundError extends Error {
  constructor(kid: string) {
    super(`Key ID '${kid}' not found in JWKS`);
    this.name = 'JwksKeyNotFoundError';
  }
}
