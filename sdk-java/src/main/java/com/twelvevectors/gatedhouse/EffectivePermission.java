// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.io.Serial;
import java.io.Serializable;

/**
 * A single permission tuple as it appears on a role grant. Any of the three
 * components may be null, denoting a wildcard at that level.
 *
 * <p>Implements {@link Serializable} so distributed JCache providers
 * (Redisson for Redis, Hazelcast, Infinispan, …) can persist cached
 * values across the network.
 */
public record EffectivePermission(String service, String resource, String action)
        implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
}
