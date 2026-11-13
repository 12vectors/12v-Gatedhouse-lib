// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.time.Instant;

/**
 * A person created by {@link SphinxClient#createPerson(NewPerson)}, as Sphinx
 * reports it.
 *
 * @param id                Sphinx's person id ({@code per_…})
 * @param displayName       {@code null} if none
 * @param phone             normalised E.164, or {@code null}
 * @param status            e.g. {@code pending_verification} until the person
 *                          sets a password, or {@code active}
 * @param passwordResetSent whether Sphinx emailed the set-password link; if
 *                          {@code false} the person can use "Forgot password"
 */
public record ProvisionedPerson(String id, String email, boolean emailVerified,
                                String displayName, String phone, boolean phoneVerified,
                                boolean allowAutoLink, String status, Instant createdAt,
                                boolean passwordResetSent) {}
