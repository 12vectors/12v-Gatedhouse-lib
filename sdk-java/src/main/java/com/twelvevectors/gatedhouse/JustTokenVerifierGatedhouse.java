// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.List;
import java.util.Objects;

final class JustTokenVerifierGatedhouse implements Gatedhouse {

    private final JwtVerification jwtVerification;

    JustTokenVerifierGatedhouse(TokenVerifierConfig config) {
        this.jwtVerification = new JwtVerification(Objects.requireNonNull(config, "config"));
    }

    @Override
    public void close() {}

    @Override
    public PermissionCatalog permissionCatalog() {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public RoleManager roleManager() {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public MembershipManager membershipManager() {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public GroupManager groupManager() {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public AuthenticatedSubject verifyToken(String jwt) {
        return jwtVerification.verify(jwt);
    }

    @Override
    public boolean hasPermission(String identityId, String orgId, String service, String resource, String action) {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public List<EffectivePermission> getEffectivePermissions(String identityId, String orgId) {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public List<String> getRoles(String identityId, String orgId) {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public List<String> getGroups(String identityId, String orgId) {
        throw new UnsupportedOperationException("Database operations not supported on token-verifier-only instance");
    }

    @Override
    public void invalidateCache(String identityId, String orgId) {}

    @Override
    public void invalidateAllCache() {}

    @Override
    public void setCacheBypass(boolean bypass) {}

    @Override
    public boolean isCacheBypassed() {
        return false;
    }
}
