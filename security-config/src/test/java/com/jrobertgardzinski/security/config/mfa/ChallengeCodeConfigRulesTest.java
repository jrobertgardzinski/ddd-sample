package com.jrobertgardzinski.security.config.mfa;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Epic("Config")
@Feature("MFA challenge code")
class ChallengeCodeConfigRulesTest {

    @Test
    @DisplayName("the defaults are a usable 5-minute, 5-attempt, 6-digit code")
    void defaults() {
        ChallengeCodeConfig config = ChallengeCodeConfig.withDefaults();
        assertEquals(5, config.codeTtlMinutes().value());
        assertEquals(5, config.maxAttempts().value());
        assertEquals(6, config.codeLength().value());
    }

    @Test
    @DisplayName("non-positive TTL or attempts, and a code length outside 4..10, are rejected")
    void invalidValuesRejected() {
        assertThrows(IllegalArgumentException.class, () -> new ChallengeCodeConfig(0, 5, 6));
        assertThrows(IllegalArgumentException.class, () -> new ChallengeCodeConfig(5, 0, 6));
        assertThrows(IllegalArgumentException.class, () -> new ChallengeCodeConfig(5, 5, 3));
        assertThrows(IllegalArgumentException.class, () -> new ChallengeCodeConfig(5, 5, 11));
        assertDoesNotThrow(() -> new ChallengeCodeConfig(10, 3, 8));
    }
}
