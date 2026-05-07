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
