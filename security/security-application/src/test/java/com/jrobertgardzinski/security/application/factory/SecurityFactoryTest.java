package com.jrobertgardzinski.security.application.factory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SecurityFactoryTest {

    @Test
    void shouldFail() {
        SecurityFactory factory = new SecurityFactory();
        RuntimeException p = Assertions.assertThrows(RuntimeException.class, () -> factory.createUserRegistration("blah", "123"));
        Assertions.assertEquals(
                "[email: blah does not meet regex, password: [must be at least 12 characters long, must contain a small letter, must contain a capital letter, must contain one of special characters: [#, ?, !]]]",
                p.getMessage());
    }
}