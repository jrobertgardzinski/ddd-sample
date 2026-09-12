package com.jrobertgardzinski.security.config.mfa.vo;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The accepted/rejected split for the MFA rules a deployment may turn — five value objects that had
 * no test of their own, and two of them had no ceiling either.
 *
 * <p>A range is a claim about what the mechanism still IS at the edges. Five wrong codes per ticket
 * make a six-digit code a second factor; five hundred make it a formality. Five minutes of validity
 * is "check your mail"; five days is a password lying in a mailbox. The numbers below are where
 * those claims stop holding, and the test exists so that moving one is a decision rather than a typo.
 */
@Epic("Security")
@Feature("Security Configuration - MFA value objects")
class MfaValueRangesTest {

    @Test
    @DisplayName("the challenge code's lifetime has both a floor and a ceiling")
    void codeTtlKeepsToItsRange() {
        assertDoesNotThrow(() -> new CodeTtlMinutes(CodeTtlMinutes.MIN));
        assertDoesNotThrow(() -> new CodeTtlMinutes(CodeTtlMinutes.MAX));
        assertThrows(IllegalArgumentException.class, () -> new CodeTtlMinutes(0));
        assertThrows(IllegalArgumentException.class, () -> new CodeTtlMinutes(-1));
        assertThrows(IllegalArgumentException.class, () -> new CodeTtlMinutes(CodeTtlMinutes.MAX + 1));
    }

    @Test
    @DisplayName("the attempt cap has both, because enough tries and the code stops being a factor")
    void maxAttemptsKeepsToItsRange() {
        assertDoesNotThrow(() -> new CodeMaxAttempts(CodeMaxAttempts.MIN));
        assertDoesNotThrow(() -> new CodeMaxAttempts(CodeMaxAttempts.MAX));
        assertThrows(IllegalArgumentException.class, () -> new CodeMaxAttempts(0));
        assertThrows(IllegalArgumentException.class, () -> new CodeMaxAttempts(CodeMaxAttempts.MAX + 1));
    }

    @Test
    @DisplayName("a code is 4 to 10 digits: shorter is guessable, longer is not typed correctly")
    void codeLengthKeepsToItsRange() {
        assertDoesNotThrow(() -> new CodeLength(4));
        assertDoesNotThrow(() -> new CodeLength(10));
        assertThrows(IllegalArgumentException.class, () -> new CodeLength(3));
        assertThrows(IllegalArgumentException.class, () -> new CodeLength(11));
    }

    @Test
    @DisplayName("recovery codes: how many, and how long each is")
    void recoveryCodesKeepToTheirRanges() {
        assertDoesNotThrow(() -> new RecoveryCodeCount(1));
        assertDoesNotThrow(() -> new RecoveryCodeCount(50));
        assertThrows(IllegalArgumentException.class, () -> new RecoveryCodeCount(0));
        assertThrows(IllegalArgumentException.class, () -> new RecoveryCodeCount(51));

        assertDoesNotThrow(() -> new RecoveryCodeLength(8));
        assertDoesNotThrow(() -> new RecoveryCodeLength(40));
        assertThrows(IllegalArgumentException.class, () -> new RecoveryCodeLength(7),
                "a shorter break-glass key is a sweepable one — it stands in for the whole chain");
        assertThrows(IllegalArgumentException.class, () -> new RecoveryCodeLength(41));
    }

    @Test
    @DisplayName("a role's factor floor is at least one: zero would make the floor mean nothing")
    void minFactorsKeepToTheirFloor() {
        assertDoesNotThrow(() -> new UserMinFactors(1));
        assertDoesNotThrow(() -> new ModeratorMinFactors(2));
        assertDoesNotThrow(() -> new AdminMinFactors(3));
        assertThrows(IllegalArgumentException.class, () -> new UserMinFactors(0));
        assertThrows(IllegalArgumentException.class, () -> new ModeratorMinFactors(0));
        assertThrows(IllegalArgumentException.class, () -> new AdminMinFactors(-1));
        // the CEILING for these is not a constant — it is how many factors the deployment offers,
        // so it lives at wiring time (BeanFactory#factorRegistry) where the registry is known
    }
}
