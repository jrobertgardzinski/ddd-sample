package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.IpAddress;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Calendar;

public record AuthenticationBlock (
        IpAddress ipAddress,
        Calendar expiryDate
) {
    public boolean isStillActive() {
        return expiryDate.compareTo(Calendar.getInstance()) < 0;
    }
}
