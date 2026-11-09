// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/** No database needed. */
class InMemoryPermissionCacheTest {

    /** A clock the test moves forward. */
    static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    static final List<EffectivePermission> PERMS = List.of(new EffectivePermission("s", "r", "a"));

    @Test
    void neverGrowsBeyondItsBoundEvenWithEndlesslyNewKeys() {
        InMemoryPermissionCache cache = new InMemoryPermissionCache(Duration.ofMinutes(1), 100);
        for (int i = 0; i < 10_000; i++) {
            cache.put("user", "org-" + i, PERMS);   // e.g. org IDs taken from request paths
            assertTrue(cache.size() <= 100, "size " + cache.size() + " after " + i);
        }
        assertTrue(cache.evictionCount() > 0);
        assertTrue(cache.get("user", "org-9999").isPresent(), "the newest entry is kept");
    }

    @Test
    void expiredEntriesAreSweptBeforeLiveOnesAreEvicted() {
        TestClock clock = new TestClock();
        InMemoryPermissionCache cache = new InMemoryPermissionCache(Duration.ofSeconds(60), 10, clock);
        for (int i = 0; i < 5; i++) {
            cache.put("old", "org" + i, PERMS);
        }
        clock.now = clock.now.plusSeconds(61);   // the five "old" entries expire
        for (int i = 0; i < 5; i++) {
            cache.put("live", "org" + i, PERMS);
        }
        cache.put("one", "more", PERMS);          // full: sweep instead of evicting live ones
        for (int i = 0; i < 5; i++) {
            assertTrue(cache.get("live", "org" + i).isPresent(), "live entry evicted");
        }
        assertEquals(6, cache.size());
    }

    @Test
    void rejectsAnEmptyBound() {
        assertThrows(IllegalArgumentException.class,
            () -> new InMemoryPermissionCache(Duration.ofSeconds(1), 0));
        assertEquals(10_000, new InMemoryPermissionCache().maxEntries());
    }
}
