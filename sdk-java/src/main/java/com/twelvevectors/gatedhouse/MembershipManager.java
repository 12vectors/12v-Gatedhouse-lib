// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.Optional;

/**
 * Manages an identity's membership of an org: the gate that lets its grants in
 * that org count. Memberships are never deleted; see docs/MODEL.md, "The
 * membership lifecycle".
 */
public interface MembershipManager {

    /**
     * Creates an {@link MembershipStatus#ACTIVE ACTIVE} membership.
     *
     * <p>If the identity has a {@link MembershipStatus#REMOVED REMOVED}
     * membership in the org, it is revived instead: any grants left in that
     * org are cleared, then the same row becomes ACTIVE with the given entity
     * type. If a membership in any other status exists, the insert fails with
     * a {@link GatedhouseDatabaseException} caused by the unique violation.
     */
    void createMembership(String identityId, String orgId, EntityType entityType);

    /**
     * Removes the identity from the org: in one transaction, sets the status
     * to {@link MembershipStatus#REMOVED REMOVED} and revokes the identity's
     * direct role assignments and group memberships in that org. The
     * membership row is kept as history.
     *
     * <p>If no membership exists, grants the identity holds in the org are
     * still revoked, so afterwards it holds nothing there.
     */
    void removeMembership(String identityId, String orgId);

    /**
     * Removes the identity from the org.
     *
     * @deprecated Memberships are no longer deleted. This now performs
     *     {@link #removeMembership(String, String)} and keeps the row.
     */
    @Deprecated(since = "0.4.0", forRemoval = true)
    default void deleteMembership(String identityId, String orgId) {
        removeMembership(identityId, orgId);
    }

    /**
     * True if the identity is a member of the org in any status other than
     * {@link MembershipStatus#REMOVED REMOVED}.
     */
    boolean hasMembership(String identityId, String orgId);

    /**
     * Changes the membership's status. Does nothing if no membership exists
     * (except for {@code REMOVED}, which behaves as
     * {@link #removeMembership(String, String)}).
     *
     * <ul>
     *   <li>To {@code REMOVED}: same as {@link #removeMembership(String, String)}.</li>
     *   <li>From {@code REMOVED} to {@code ACTIVE} or {@code PENDING}: revives
     *       the membership, clearing any grants left in the org first.</li>
     *   <li>From {@code REMOVED} to {@code SUSPENDED}: rejected with
     *       {@link IllegalStateException}; a removed identity has nothing to
     *       suspend.</li>
     * </ul>
     */
    void setStatus(String identityId, String orgId, MembershipStatus status);

    Optional<MembershipStatus> getStatus(String identityId, String orgId);

    Optional<EntityType> getEntityType(String identityId, String orgId);
}
