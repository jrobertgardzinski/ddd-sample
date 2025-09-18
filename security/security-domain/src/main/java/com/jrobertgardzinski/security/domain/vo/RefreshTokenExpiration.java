package com.jrobertgardzinski.security.domain.vo;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Calendar;

public record RefreshTokenExpiration(TokenExpiration value) {
    public boolean hasExpired() {
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(value.value());
    }
}
