package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StrongPasswordPolicyAdapterTest {

    private static final String VALID_PASSWORD = "StrongPassword1#";
    private static final String ERR_LENGTH = "12 characters";
    private static final String ERR_UPPERCASE = "uppercase";
    private static final String ERR_DIGIT = "digit";
    private static final String ERR_SPECIAL = "special";

    private final PasswordPolicyPort policy = new StrongPasswordPolicyAdapter();

    private PlainTextPassword password(String value) {
        return new PlainTextPassword(value);
    }

    private boolean hasViolation(List<String> violations, String keyword) {
        return violations.stream().anyMatch(v -> v.contains(keyword));
    }

    @Test
    void shouldAcceptValidPassword() {
        PlainTextPassword pwd = password(VALID_PASSWORD);
        assertTrue(policy.validate(pwd).isEmpty());
        assertTrue(policy.isSatisfiedBy(pwd));
    }

    @Test
    void shouldRejectTooShortPassword() {
        List<String> violations = policy.validate(password("shortPass1#"));
        assertTrue(hasViolation(violations, ERR_LENGTH));
    }

    @Nested
    @DisplayName("Step by step password building")
    class StepByStep {

        @Test
        @DisplayName("Only length satisfied")
        void step1() {
            List<String> violations = policy.validate(password("passwordpassword"));
            assertFalse(hasViolation(violations, ERR_LENGTH));
            assertTrue(hasViolation(violations, ERR_UPPERCASE));
            assertTrue(hasViolation(violations, ERR_DIGIT));
            assertTrue(hasViolation(violations, ERR_SPECIAL));
        }

        @Test
        @DisplayName("Length + uppercase satisfied")
        void step2() {
            List<String> violations = policy.validate(password("Passwordpassword"));
            assertFalse(hasViolation(violations, ERR_LENGTH));
            assertFalse(hasViolation(violations, ERR_UPPERCASE));
            assertTrue(hasViolation(violations, ERR_DIGIT));
        }

        @Test
        @DisplayName("Length + uppercase + digit satisfied")
        void step3() {
            List<String> violations = policy.validate(password("Passwordpassword1"));
            assertFalse(hasViolation(violations, ERR_LENGTH));
            assertFalse(hasViolation(violations, ERR_UPPERCASE));
            assertFalse(hasViolation(violations, ERR_DIGIT));
            assertTrue(hasViolation(violations, ERR_SPECIAL));
        }

        @Test
        @DisplayName("All requirements satisfied")
        void step4() {
            List<String> violations = policy.validate(password("Passwordpassword1#"));
            assertTrue(violations.isEmpty());
        }
    }

    @Test
    void shouldCollectAllViolations() {
        List<String> violations = policy.validate(password("xyzxyzxyzxyz"));

        assertEquals(3, violations.size());
        assertTrue(hasViolation(violations, ERR_UPPERCASE));
        assertTrue(hasViolation(violations, ERR_DIGIT));
        assertTrue(hasViolation(violations, ERR_SPECIAL));
    }
}
