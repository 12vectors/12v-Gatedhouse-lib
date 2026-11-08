// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

/**
 * Lifecycle status of a membership. Only {@link #ACTIVE} lets the identity's
 * grants in the org count. See docs/MODEL.md, "The membership lifecycle".
 */
public enum MembershipStatus {

    /** A member in good standing: grants apply. */
    ACTIVE("active"),
    /** Temporarily barred: grants are kept but ignored until reactivated. */
    SUSPENDED("suspended"),
    /** Invited or being provisioned: grants may be prepared but are ignored. */
    PENDING("pending"),
    /** Has left the org: grants were revoked; the row remains as history. */
    REMOVED("removed");

    private final String dbValue;

    MembershipStatus(String dbValue) {
        this.dbValue = dbValue;
    }

    public String dbValue() {
        return dbValue;
    }

    public static MembershipStatus fromDbValue(String value) {
        for (MembershipStatus s : values()) {
            if (s.dbValue.equals(value)) {
                return s;
            }
        }
        throw new IllegalArgumentException("Unknown membership_status value: " + value);
    }
}
