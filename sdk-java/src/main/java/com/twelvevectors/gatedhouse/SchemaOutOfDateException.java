package com.twelvevectors.gatedhouse;

public final class SchemaOutOfDateException extends RuntimeException {

    private final int currentVersion;
    private final int expectedVersion;

    public SchemaOutOfDateException(int currentVersion, int expectedVersion) {
        super(String.format(
            "Gatedhouse schema is at version %d but this library requires version %d.%n"
            + "%n"
            + "Run the migration tool against the same database, e.g.:%n"
            + "    java -cp gatedhouse-<version>.jar com.twelvevectors.gatedhouse.cli.Migrate \\%n"
            + "         <jdbc-url> <user> <password>%n"
            + "%n"
            + "Or, from your application's bootstrap, call:%n"
            + "    GatedhouseFactory.migrate(config);%n",
            currentVersion, expectedVersion));
        this.currentVersion = currentVersion;
        this.expectedVersion = expectedVersion;
    }

    public int currentVersion() {
        return currentVersion;
    }

    public int expectedVersion() {
        return expectedVersion;
    }
}
