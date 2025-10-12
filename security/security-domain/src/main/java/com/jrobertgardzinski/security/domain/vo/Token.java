package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;
import java.util.UUID;

public record Token(String value) {
    public Token {
        if (value == null) {
            throw new IllegalArgumentException("'value' cannot be null");
        }
        else if (value.isBlank()) {
            throw new IllegalArgumentException("'value' cannot be blank");
        }
    }

    public static Token random() {
        return new Token(UUID.randomUUID().toString());
    }
}
