package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EmailTest {

    @Test
    void notNull() {
        Assertions.assertThrows(NullPointerException.class, () -> new Email(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"abc\"", "some-random_string text"})
    void failingRegex(String value) {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Email(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"user@gmail.com", "andrzej@wp.pl"})
    void success(String value) {
        Assertions.assertDoesNotThrow(() -> new Email(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"u.ser@gmail.com", "us.er@gmail.com", "use.r@gmail.com", "u.s.e.r@gmail.com", "user+ddd@gmail.com", "u.s.e.r+ddd@gmail.com"})
    void handlingGmail(String value) {
        Assertions.assertEquals(new Email("user@gmail.com"), new Email(value));
    }
}