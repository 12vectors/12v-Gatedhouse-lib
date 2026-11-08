// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.List;
import java.util.Objects;

/**
 * Why a permission is granted or denied, as reported by
 * {@link Gatedhouse#explainPermission}.
 *
 * @param outcome          the decision and its reason
 * @param membershipStatus the identity's membership status in the org, or
 *                         {@code null} if it has no membership there
 * @param paths            every path that would grant the permission, reported
 *                         even when the decision is a denial
 */
public record PermissionExplanation(Outcome outcome, MembershipStatus membershipStatus,
                                    List<GrantPath> paths) {

    /** The decision, and for a denial, why. */
    public enum Outcome {
        /** An active membership and at least one granting path. */
        ALLOWED,
        /** No membership in the org. Any paths are grants with no effect. */
        NO_MEMBERSHIP,
        /** The membership is not ACTIVE. The paths show what would apply if it were. */
        MEMBERSHIP_NOT_ACTIVE,
        /** An active membership, but nothing grants the permission. */
        NO_MATCHING_GRANT
    }

    public PermissionExplanation {
        Objects.requireNonNull(outcome, "outcome");
        paths = List.copyOf(paths);
    }

    /** True iff the permission is granted; agrees with {@link Gatedhouse#hasPermission}. */
    public boolean allowed() {
        return outcome == Outcome.ALLOWED;
    }
}
