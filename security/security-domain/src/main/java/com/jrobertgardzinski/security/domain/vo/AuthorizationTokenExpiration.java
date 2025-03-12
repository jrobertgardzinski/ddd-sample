package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record AuthorizationTokenExpiration(Calendar value) {
    public static AuthorizationTokenExpiration validInHours(int i) {
        Calendar now = Calendar.getInstance();
        now.add(Calendar.HOUR_OF_DAY, i);
        return new AuthorizationTokenExpiration(now);
    }
}
