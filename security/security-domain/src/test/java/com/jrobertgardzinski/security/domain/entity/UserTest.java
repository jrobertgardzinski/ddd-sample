package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.factory.SecurityFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {
    @Test
    void shouldFail() {
        SecurityFactory factory = new SecurityFactory();
        RuntimeException p = assertThrows(RuntimeException.class, () -> factory.createUserRegistration("blah", "123"));
        assertEquals(
                "[email: blah does not meet regex, passwordHash: Minimum required length is 18]",
                p.getMessage());
    }
}