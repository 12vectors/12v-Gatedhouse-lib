// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.List;
import java.util.Objects;

/**
 * One path through which an identity holds a permission, as reported by
 * {@link Gatedhouse#explainPermission}.
 *
 * @param source    whether the first role in the chain is assigned directly or to a group
 * @param groupId   the group the role is assigned to, or {@code null} for {@link Source#DIRECT}
 * @param roleChain the assigned role first, then each inherited parent, ending
 *                  with the role that holds {@code grant}; never empty
 * @param grant     the matching grant held by the last role in the chain;
 *                  components may be {@code null} (wildcards)
 */
public record GrantPath(Source source, String groupId, List<String> roleChain,
                        EffectivePermission grant) {

    /** Where the first role in the chain comes from. */
    public enum Source {
        /** Assigned directly to the identity. */
        DIRECT,
        /** Assigned to a group the identity belongs to. */
        GROUP
    }

    public GrantPath {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(grant, "grant");
        roleChain = List.copyOf(roleChain);
        if (roleChain.isEmpty()) {
            throw new IllegalArgumentException("roleChain must not be empty");
        }
    }

    /** The role assigned to the identity, or to its group. */
    public String assignedRole() {
        return roleChain.get(0);
    }

    /** The role that holds the matching grant. */
    public String grantingRole() {
        return roleChain.get(roleChain.size() - 1);
    }
}
