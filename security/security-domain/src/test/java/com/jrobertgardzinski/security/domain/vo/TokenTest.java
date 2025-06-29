package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Calendar;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenTest {
    public static Stream<Arguments> source() {
        Calendar futureDate = Calendar.getInstance();
        futureDate.add(Calendar.HOUR, 1);

        Calendar pastDate = Calendar.getInstance();
        pastDate.add(Calendar.HOUR, -1);

        return Stream.of(
                Arguments.of(""),
                Arguments.of(" ")
        );
    }

    @ParameterizedTest
    @MethodSource("source")
    void test(String value) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Token(value));
    }
}