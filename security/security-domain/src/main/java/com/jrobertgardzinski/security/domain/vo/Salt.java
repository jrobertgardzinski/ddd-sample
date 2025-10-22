package com.jrobertgardzinski.security.domain.vo;

public record Salt(String value) {
    public Salt {
        int SIZE_LIMIT = 10;
        if (value.length() < SIZE_LIMIT) {
            throw new IllegalArgumentException("Accepts only strings length above " + SIZE_LIMIT);
        }
    }
}
