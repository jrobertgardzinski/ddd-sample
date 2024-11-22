package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EmailTest {

    @Test
    void notNull() {
        assertThrows(NullPointerException.class, () -> new Email(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"abc\"", "some-random_string text"})
    void failingRegex(String value) {
        assertThrows(IllegalArgumentException.class, () -> new Email(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"user@gmail.com", "andrzej@wp.pl"})
    void success(String value) {
        assertDoesNotThrow(() -> new Email(value));
    }


}