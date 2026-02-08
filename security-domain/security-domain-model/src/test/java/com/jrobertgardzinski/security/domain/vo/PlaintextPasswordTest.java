package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class PlaintextPasswordTest {

    @Test
    void shouldRejectNull() {
        assertThrows(NullPointerException.class, () -> new PlaintextPassword(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    void shouldRejectBlank(String value) {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new PlaintextPassword(value)
        );
        assertTrue(exception.getMessage().contains("blank"));
    }

    @Test
    void shouldAcceptAnyNonBlankValue() {
        assertDoesNotThrow(() -> new PlaintextPassword("any"));
    }

    @Test
    void shouldHideValueInToString() {
        PlaintextPassword password = new PlaintextPassword("secret");
        assertEquals("<hidden>", password.toString());
    }
}
