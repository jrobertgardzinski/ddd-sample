package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record TokenExpiration(Calendar value) {
    public TokenExpiration {
        if (value == null) {
            throw new IllegalArgumentException("'expiration' cannot be null");
        }
        else if (value.before(Calendar.getInstance())) {
            throw new IllegalArgumentException("'expiration' must be the future date");
        }
    }

    public static TokenExpiration validInHours(int i) {
        Calendar now = Calendar.getInstance();
        now.add(Calendar.HOUR_OF_DAY, i);
        return new TokenExpiration(now);
    }
}
