package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.system.SystemTime;

import java.time.LocalDateTime;

public record RefreshTokenExpiration(TokenExpiration value) {
    public boolean hasExpired() {
        LocalDateTime now = LocalDateTime.now(SystemTime.currentClock());
        return now.isAfter(value.value());
    }
}
