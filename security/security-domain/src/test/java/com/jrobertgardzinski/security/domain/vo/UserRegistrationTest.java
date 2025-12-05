package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.security.domain.factory.SecurityFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserRegistrationTest {

    @Test
    void shouldFail() {
        SecurityFactory factory = new SecurityFactory();
        RuntimeException p = assertThrows(RuntimeException.class, () -> factory.createUserRegistration("blah", "123"));
        assertEquals(
                "[email: blah does not meet regex, password: [must be at least 12 characters long, must contain a small letter, must contain a capital letter, must contain one of special characters: [#, ?, !]]]",
                p.getMessage());
    }
}