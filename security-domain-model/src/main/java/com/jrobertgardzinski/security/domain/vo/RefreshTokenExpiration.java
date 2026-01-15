package com.jrobertgardzinski.security.domain.vo;

import java.time.LocalDateTime;

public record RefreshTokenExpiration(TokenExpiration value) {
    public boolean hasExpired() {
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(value.value());
    }
}
