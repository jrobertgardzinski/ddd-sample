package com.jrobertgardzinski.security.domain.vo;

import java.util.Objects;

public record PlaintextPassword(String value) {

    public PlaintextPassword {
        Objects.requireNonNull(value, "Cannot be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("Password cannot be blank");
        }
    }

    @Override
    public String toString() {
        return "<hidden>";
    }
}
