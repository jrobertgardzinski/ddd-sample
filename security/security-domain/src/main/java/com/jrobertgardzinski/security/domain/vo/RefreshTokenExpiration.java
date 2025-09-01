package com.jrobertgardzinski.security.domain.vo;

import java.time.Duration;
import java.util.Calendar;

public record RefreshTokenExpiration(TokenExpiration value) {
    public boolean hasExpired() {
        Calendar now = Calendar.getInstance();
        return now.getTimeInMillis() > value.value().getTimeInMillis() + Duration.ofSeconds(10).toMillis();
    }
}
