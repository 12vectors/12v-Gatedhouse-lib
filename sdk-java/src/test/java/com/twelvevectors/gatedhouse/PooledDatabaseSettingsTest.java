// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.SQLException;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** No database needed. */
class PooledDatabaseSettingsTest {

    @Test
    void defaults() {
        PooledDatabase.Settings s = PooledDatabase.Settings.defaults();
        assertEquals(10, s.maximumPoolSize());
        assertEquals(Duration.ofSeconds(10), s.connectionTimeout());
        assertEquals(Duration.ofMinutes(30), s.maxLifetime());
    }

    @Test
    void rejectsValuesHikariWouldRejectOrSilentlyChange() {
        var b = PooledDatabase.Settings.builder();
        assertThrows(IllegalArgumentException.class, () -> b.maximumPoolSize(0));
        assertThrows(IllegalArgumentException.class, () -> b.connectionTimeout(Duration.ofMillis(249)));
        assertThrows(IllegalArgumentException.class, () -> b.maxLifetime(Duration.ofSeconds(29)));
        assertThrows(NullPointerException.class, () -> b.connectionTimeout(null));
    }

    @Test
    void connectionLossIsUnavailableAndEverythingElseIsQuery() {
        for (String state : new String[] {"08001", "08006", "57P01", "57P03"}) {
            assertEquals(GatedhouseDatabaseException.Kind.UNAVAILABLE,
                GatedhouseDatabaseException.classify("x", new SQLException("m", state)).kind(), state);
        }
        for (String state : new String[] {"23505", "42P01", "40001", null}) {
            assertEquals(GatedhouseDatabaseException.Kind.QUERY,
                GatedhouseDatabaseException.classify("x", new SQLException("m", state)).kind(), state);
        }
        assertEquals(GatedhouseDatabaseException.Kind.QUERY,
            new GatedhouseDatabaseException("m", null).kind(), "legacy constructor");
    }
}
