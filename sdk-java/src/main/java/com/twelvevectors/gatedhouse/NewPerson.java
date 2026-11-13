// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A person to create in Sphinx with {@link SphinxClient#createPerson(NewPerson)}.
 * Only {@code email} is required; a {@code null} optional field is left out of
 * the request, so Sphinx applies its default.
 *
 * @param email         the person's identifier in Sphinx; must not be blank
 * @param displayName   optional
 * @param phone         optional, E.164 ({@code +35799123456}); spaces and dashes
 *                      are allowed. Stored unverified.
 * @param emailVerified optional, Sphinx default {@code false}: {@code true} means
 *                      the app vouches for the address and the account is active
 *                      at once
 * @param allowAutoLink optional, Sphinx default {@code true}: {@code false} means a
 *                      federated sign-in with the same email is never linked
 *                      without the user's confirmation
 */
public record NewPerson(String email, String displayName, String phone,
                        Boolean emailVerified, Boolean allowAutoLink) {

    /** @throws IllegalArgumentException if {@code email} is null or blank */
    public NewPerson {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required");
        }
    }

    public static Builder builder(String email) {
        return new Builder(email);
    }

    /** The JSON request body: snake_case keys, unset fields omitted. */
    Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("email", email);
        if (displayName != null) {
            json.put("display_name", displayName);
        }
        if (phone != null) {
            json.put("phone", phone);
        }
        if (emailVerified != null) {
            json.put("email_verified", emailVerified);
        }
        if (allowAutoLink != null) {
            json.put("allow_auto_link", allowAutoLink);
        }
        return json;
    }

    public static final class Builder {
        private final String email;
        private String displayName;
        private String phone;
        private Boolean emailVerified;
        private Boolean allowAutoLink;

        private Builder(String email) {
            this.email = email;
        }

        public Builder displayName(String displayName) {
            this.displayName = displayName;
            return this;
        }

        public Builder phone(String phone) {
            this.phone = phone;
            return this;
        }

        public Builder emailVerified(boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }

        public Builder allowAutoLink(boolean allowAutoLink) {
            this.allowAutoLink = allowAutoLink;
            return this;
        }

        /** @throws IllegalArgumentException if the email is null or blank */
        public NewPerson build() {
            return new NewPerson(email, displayName, phone, emailVerified, allowAutoLink);
        }
    }
}
