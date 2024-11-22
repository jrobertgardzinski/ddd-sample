package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static com.jrobertgardzinski.security.domain.vo.Password.*;
import static org.junit.jupiter.api.Assertions.*;

class PasswordTest {
    @Test
    void notNull() {
        assertThrows(NullPointerException.class, () -> new Password(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"too short", "secret", "password123"})
    void doesNotMatchSize(String value) {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new Password(value));
        assertTrue(exception.getMessage().contains(EX_1_PASSWORD_LENGTH));
    }

    @Nested
    class StepByStep {

        @Test
        void test1() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new Password("password"));
            assertTrue(exception.getMessage().contains(EX_1_PASSWORD_LENGTH));
        }

        @Test
        @DisplayName("Breaks all but small letter")
        void test2() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new Password("strong password"));
            assertFalse(exception.getMessage().contains(EX_2_SMALL_LETTER));
        }

        @Test
        @DisplayName("Fixed capital letter constraint...")
        void test3() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new Password("strong Password"));
            assertFalse(exception.getMessage().contains(EX_3_CAPITAL_LETTER));
        }

        @Test
        @DisplayName("..then added digit...")
        void test4() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new Password("strong Password1"));
            assertFalse(exception.getMessage().contains(EX_4_DIGIT));
        }

        @Test
        @DisplayName("..and a special character passed validation!")
        void test5() {
            assertDoesNotThrow(() -> new Password("strong Password1#"));
        }
    }
}