package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record RefreshTokenExpiration(TokenExpiration value) {
    public boolean hasExpired() {
        return Calendar.getInstance().compareTo(value.value()) < 0;
    }
}
