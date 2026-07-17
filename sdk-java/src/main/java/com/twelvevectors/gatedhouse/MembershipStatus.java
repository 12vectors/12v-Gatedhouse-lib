// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

public enum MembershipStatus {

    ACTIVE("active"),
    SUSPENDED("suspended"),
    PENDING("pending");

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
