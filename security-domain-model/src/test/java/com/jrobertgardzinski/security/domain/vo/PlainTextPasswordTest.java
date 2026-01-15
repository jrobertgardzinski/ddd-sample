package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static com.jrobertgardzinski.security.domain.vo.PlainTextPassword.*;

class PlainTextPasswordTest {
    @Test
    void notNull() {
        Assertions.assertThrows(NullPointerException.class, () -> new PlainTextPassword(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"too short", "secret", "password123"})
    void doesNotMatchSize(String value) {
        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
                () -> new PlainTextPassword(value));
        Assertions.assertTrue(exception.getMessage().contains(EX_1_PASSWORD_LENGTH));
    }

    @Nested
    class StepByStep {

        @Test
        void test1() {
            IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new PlainTextPassword("password"));
            Assertions.assertTrue(exception.getMessage().contains(EX_1_PASSWORD_LENGTH));
        }

        @Test
        @DisplayName("Breaks all but small letter")
        void test2() {
            IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new PlainTextPassword("strong password"));
            Assertions.assertFalse(exception.getMessage().contains(EX_2_SMALL_LETTER));
        }

        @Test
        @DisplayName("Fixed capital letter constraint...")
        void test3() {
            IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new PlainTextPassword("strong Password"));
            Assertions.assertFalse(exception.getMessage().contains(EX_3_CAPITAL_LETTER));
        }

        @Test
        @DisplayName("..then added digit...")
        void test4() {
            IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new PlainTextPassword("strong Password1"));
            Assertions.assertFalse(exception.getMessage().contains(EX_4_DIGIT));
        }

        @Test
        @DisplayName("..and a special character passed validation!")
        void test5() {
            Assertions.assertDoesNotThrow(() -> new PlainTextPassword("strong Password1#"));
        }
    }
}