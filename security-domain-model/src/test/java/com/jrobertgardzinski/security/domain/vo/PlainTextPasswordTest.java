package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class PlainTextPasswordTest {

    @Test
    void shouldRejectNull() {
        assertThrows(NullPointerException.class, () -> new PlainTextPassword(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    void shouldRejectBlank(String value) {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new PlainTextPassword(value)
        );
        assertTrue(exception.getMessage().contains("blank"));
    }

    @Test
    void shouldAcceptAnyNonBlankValue() {
        assertDoesNotThrow(() -> new PlainTextPassword("any"));
    }

    @Test
    void shouldHideValueInToString() {
        PlainTextPassword password = new PlainTextPassword("secret");
        assertEquals("<hidden>", password.toString());
    }
}
