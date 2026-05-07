package com.twelvevectors.gatedhouse;

import java.util.Objects;

public final class GatedhouseConfig {

    private final Database database;
    private final GroupSource groupSource;
    private final TokenVerifierConfig tokenVerifier;
    private final PermissionCache permissionCache;

    private GatedhouseConfig(Builder builder) {
        this.database = Objects.requireNonNull(builder.database,
            "database must be set on GatedhouseConfig");
        this.groupSource = builder.groupSource != null
            ? builder.groupSource
            : new LocalGroupSource();
        this.tokenVerifier = builder.tokenVerifier;
        this.permissionCache = builder.permissionCache != null
            ? builder.permissionCache
            : new InMemoryPermissionCache();
    }

    public Database database() {
        return database;
    }

    public GroupSource groupSource() {
        return groupSource;
    }

    /**
     * @return the configured token-verification settings, or {@code null}
     *     if the host did not opt in. {@code Gatedhouse.verifyToken(...)}
     *     will throw if invoked without configuration.
     */
    public TokenVerifierConfig tokenVerifier() {
        return tokenVerifier;
    }

    public PermissionCache permissionCache() {
        return permissionCache;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private Database database;
        private GroupSource groupSource;
        private TokenVerifierConfig tokenVerifier;
        private PermissionCache permissionCache;

        private Builder() {
        }

        public Builder database(Database database) {
            this.database = database;
            return this;
        }

        /**
         * Optional. Defaults to {@link LocalGroupSource} (host owns group
         * writes via {@code gh.groupManager()}).
         */
        public Builder groupSource(GroupSource groupSource) {
            this.groupSource = groupSource;
            return this;
        }

        /**
         * Optional. When set, {@code Gatedhouse.tokenVerifier()} returns a
         * Nimbus-backed verifier configured against the supplied JWKS URI,
         * issuer, and audience. When unset, accessing
         * {@code Gatedhouse.tokenVerifier()} throws.
         */
        public Builder tokenVerifier(TokenVerifierConfig tokenVerifier) {
            this.tokenVerifier = tokenVerifier;
            return this;
        }

        /**
         * Optional. Defaults to a process-local
         * {@link InMemoryPermissionCache} with a 60-second TTL. Pass a
         * custom implementation to back the cache with Memcached, Redis,
         * or any other shared store.
         */
        public Builder permissionCache(PermissionCache permissionCache) {
            this.permissionCache = permissionCache;
            return this;
        }

        public GatedhouseConfig build() {
            return new GatedhouseConfig(this);
        }
    }
}
