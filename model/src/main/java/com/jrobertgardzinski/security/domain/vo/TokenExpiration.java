package com.jrobertgardzinski.security.domain.vo;

import java.time.LocalDateTime;

public record TokenExpiration(LocalDateTime value) {
    public TokenExpiration {
        if (value == null) {
            throw new IllegalArgumentException("'expiration' cannot be null");
        }
        else if (value.isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("'expiration' must be the future date");
        }
    }

    public static TokenExpiration validInHours(int i) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime value = now.plusHours(i);
        return new TokenExpiration(value);
    }
}
