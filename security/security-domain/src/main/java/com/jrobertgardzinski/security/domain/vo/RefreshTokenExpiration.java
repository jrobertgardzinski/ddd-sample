package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record RefreshTokenExpiration(Calendar value) {
    public static RefreshTokenExpiration validInHours(int i) {
        Calendar now = Calendar.getInstance();
        now.add(Calendar.HOUR_OF_DAY, i);
        return new RefreshTokenExpiration(now);
    }
}
