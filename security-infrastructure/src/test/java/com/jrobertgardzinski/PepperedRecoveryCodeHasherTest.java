package com.jrobertgardzinski;

import io.micronaut.context.env.Environment;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the database holds for a recovery code, and what it is worth to somebody who steals it.
 *
 * <p>Recovery codes were stored as an unsalted single-round SHA-256. Ten characters out of
 * thirty-one is about 2^49 candidates — hours on one GPU — so a stolen table handed over every
 * user's break-glass keys, each of which stands in for the whole factor chain. Keyed, not salted,
 * because a code is SPENT by looking its hash up: the hash must be stable, and the secret that
 * makes it unguessable lives outside the database.
 */
@Epic("Use case")
@Feature("MFA — recovery codes")
class PepperedRecoveryCodeHasherTest {

    private static final String CODE = "a1b2c3d4e5";

    @Test
    @DisplayName("the same code hashes the same way, so a code can still be spent by lookup")
    void the_hash_is_stable() {
        PepperedRecoveryCodeHasher hasher = new PepperedRecoveryCodeHasher("pepper-one", dev());

        assertEquals(hasher.hash(CODE), hasher.hash(CODE));
        assertNotEquals(hasher.hash(CODE), hasher.hash("f6g7h8i9j0"));
        assertEquals(64, hasher.hash(CODE).length(), "HMAC-SHA256, hex");
    }

    @Test
    @DisplayName("the pepper is what makes the digest unguessable: another key, another table")
    void the_digest_depends_on_the_key() {
        String underOnePepper = new PepperedRecoveryCodeHasher("pepper-one", dev()).hash(CODE);
        String underAnother = new PepperedRecoveryCodeHasher("pepper-two", dev()).hash(CODE);

        assertNotEquals(underOnePepper, underAnother,
                "a stolen table is worth nothing without the key — and rotating the key retires"
                        + " every code already issued, which is the trade this makes");
    }

    @Test
    @DisplayName("a production deployment without a pepper refuses to start, by name")
    void prod_without_a_pepper_does_not_start() {
        Environment prod = Mockito.mock(Environment.class);
        Mockito.when(prod.getActiveNames()).thenReturn(Set.of("prod"));

        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> new PepperedRecoveryCodeHasher("", prod));
        assertTrue(refused.getMessage().contains("security.mfa.recovery.pepper"),
                "the operator must be told which key to set: " + refused.getMessage());
    }

    @Test
    @DisplayName("dev and test start with nothing configured, and say so in the value they use")
    void dev_starts_without_configuration() {
        assertEquals(64, new PepperedRecoveryCodeHasher(null, dev()).hash(CODE).length());
    }

    private static Environment dev() {
        Environment environment = Mockito.mock(Environment.class);
        Mockito.when(environment.getActiveNames()).thenReturn(Set.of("dev"));
        return environment;
    }
}
