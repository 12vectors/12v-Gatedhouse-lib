// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

/**
 * Default {@link GroupSource}: the host application owns group lifecycle and
 * calls {@code gh.groupManager()} write methods directly. Holds no listeners
 * and no resources.
 */
public final class LocalGroupSource implements GroupSource {

    @Override
    public void start(Gatedhouse gatedhouse) {
        // no-op: host writes via Gatedhouse.groupManager() directly
    }

    @Override
    public void close() {
        // no-op
    }
}
