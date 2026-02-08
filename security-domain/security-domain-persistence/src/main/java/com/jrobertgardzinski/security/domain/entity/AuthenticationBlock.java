package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.system.SystemTime;

import java.time.LocalDateTime;

public record AuthenticationBlock (
        IpAddress ipAddress,
        LocalDateTime expiryDate
) {
    public boolean isStillActive() {
        return expiryDate.isAfter(LocalDateTime.now(SystemTime.currentClock()));
    }
}
