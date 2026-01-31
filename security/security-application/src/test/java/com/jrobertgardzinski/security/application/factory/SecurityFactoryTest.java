package com.jrobertgardzinski.security.application.factory;

import com.jrobertgardzinski.password.policy.domain.StrongPasswordPolicyAdapter;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import org.junit.jupiter.api.Test;

import static com.jrobertgardzinski.security.application.TestData.VALID_PASSWORD;
import static org.junit.jupiter.api.Assertions.*;

class SecurityFactoryTest {

    private final SecurityFactory factory = new SecurityFactory(new StrongPasswordPolicyAdapter());

    @Test
    void shouldThrowWhenEmailAndPasswordInvalid() {
        UserRegistrationValidationException exception = assertThrows(
            UserRegistrationValidationException.class,
            () -> factory.createUserRegistration("blah", "123")
        );

        assertTrue(exception.hasEmailErrors());
        assertTrue(exception.hasPasswordErrors());
        assertTrue(exception.emailErrors().stream().anyMatch(e -> e.contains("does not meet regex")));
        assertTrue(exception.passwordErrors().stream().anyMatch(e -> e.contains("at least 12 characters")));
    }

    @Test
    void shouldReturnUserRegistrationWhenValid() throws UserRegistrationValidationException {
        UserRegistration registration = factory.createUserRegistration("test@example.com", VALID_PASSWORD);

        assertNotNull(registration);
        assertEquals("test@example.com", registration.email().value());
    }

    @Test
    void shouldCollectAllPasswordViolations() {
        UserRegistrationValidationException exception = assertThrows(
            UserRegistrationValidationException.class,
            () -> factory.createUserRegistration("test@example.com", "weak")
        );

        assertFalse(exception.hasEmailErrors());
        assertTrue(exception.hasPasswordErrors());
        assertTrue(exception.passwordErrors().size() >= 4);
    }
}
