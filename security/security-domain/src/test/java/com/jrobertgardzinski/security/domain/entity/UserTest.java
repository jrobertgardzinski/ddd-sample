package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {
    @Test
    void shouldFail() {
        RuntimeException p = assertThrows(RuntimeException.class, () -> new User(() -> new Email("blah"), () -> new Password("123")));
        assertEquals(
                "[email: blah does not meet regex, passwordSupplier: [must be at least 12 characters long, must contain a small letter, must contain a capital letter, must contain one of special characters: [#, ?, !]]]",
                p.getMessage());
    }
}