package com.jrobertgardzinski.persistence;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;

/**
 * Row of the {@code email_verifications} table, keyed by e-mail. Holds the SHA-256 hash of the
 * pending verification token (cleared once used — hence nullable, or reading a verified row blows
 * up) and whether the address has been verified. Raw tokens are never stored.
 */
@MappedEntity("email_verifications")
record EmailVerificationEntity(
        @Id String email,
        @Nullable String pendingTokenHash,
        boolean verified,
        java.time.LocalDateTime requestedAt) {
}
