package com.jrobertgardzinski.security.domain.vo;

public record PasswordHash(String value) {
    public PasswordHash {
        int MIN_LENGTH = 18;
        if (value.length() < MIN_LENGTH) {
            throw new IllegalArgumentException("Minimum required length is " + MIN_LENGTH);
        }
    }
}
