// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.Optional;

public interface MembershipManager {

    void createMembership(String identityId, String orgId, EntityType entityType);

    void deleteMembership(String identityId, String orgId);

    boolean hasMembership(String identityId, String orgId);

    void setStatus(String identityId, String orgId, MembershipStatus status);

    Optional<MembershipStatus> getStatus(String identityId, String orgId);

    Optional<EntityType> getEntityType(String identityId, String orgId);
}
