package com.twelvevectors.gatedhouse;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Objects;

public final class GatedhouseFactory {

    private GatedhouseFactory() {
        throw new AssertionError("GatedhouseFactory is not instantiable");
    }

    public static Gatedhouse create(GatedhouseConfig config) {
        Objects.requireNonNull(config, "config");
        try {
            SchemaCheck.verify(config.database());
        } catch (SQLException e) {
            throw new GatedhouseInitializationException(
                "Failed to verify Gatedhouse schema against the configured database.", e);
        }

        DefaultGatedhouse gatedhouse = new DefaultGatedhouse(config);
        try {
            config.groupSource().start(gatedhouse);
        } catch (RuntimeException e) {
            // Best-effort cleanup before propagating the failure.
            try {
                config.groupSource().close();
            } catch (RuntimeException ignored) {
                // suppress: original failure is more informative
            }
            throw new GatedhouseInitializationException(
                "GroupSource.start failed during Gatedhouse initialization.", e);
        }
        return gatedhouse;
    }

    public static void migrate(GatedhouseConfig config) {
        Objects.requireNonNull(config, "config");
        try {
            Migrator.migrate(config.database());
        } catch (SQLException | IOException e) {
            throw new GatedhouseInitializationException(
                "Gatedhouse migration failed against the configured database.", e);
        }
    }
}
