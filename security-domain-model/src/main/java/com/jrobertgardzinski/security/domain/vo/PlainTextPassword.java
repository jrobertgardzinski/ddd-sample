package com.jrobertgardzinski.security.domain.vo;

import java.util.Objects;

public record PlainTextPassword(String value) {

    public PlainTextPassword {
        Objects.requireNonNull(value);
        if (value.isBlank()) {
            throw new IllegalArgumentException("Password cannot be blank");
        }
    }

    @Override
    public String toString() {
        return "<hidden>";
    }
}
