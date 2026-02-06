package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.system.SystemTime;

import java.time.LocalDateTime;

public record TokenExpiration(LocalDateTime value) {
    public TokenExpiration {
        if (value == null) {
            throw new IllegalArgumentException("'expiration' cannot be null");
        }
        else if (value.isBefore(LocalDateTime.now(SystemTime.currentClock()))) {
            throw new IllegalArgumentException("'expiration' must be the future date");
        }
    }

    public static TokenExpiration validInHours(int i) {
        LocalDateTime now = LocalDateTime.now(SystemTime.currentClock());
        LocalDateTime value = now.plusHours(i);
        return new TokenExpiration(value);
    }
}
