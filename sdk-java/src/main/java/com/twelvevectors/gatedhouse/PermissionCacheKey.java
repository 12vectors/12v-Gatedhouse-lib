// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Cache key used by {@link JCachePermissionCache} when adapting a
 * {@link javax.cache.Cache} to {@link PermissionCache}. The native
 * {@code PermissionCache} interface uses two-string parameters; JCache
 * requires a single key type, so we wrap them in this record.
 *
 * <p>Implements {@link Serializable} so distributed JCache providers can
 * serialize keys across the network.
 */
public record PermissionCacheKey(String identityId, String orgId)
        implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    public PermissionCacheKey {
        Objects.requireNonNull(identityId, "identityId");
        Objects.requireNonNull(orgId, "orgId");
    }
}
