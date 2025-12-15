package com.jrobertgardzinski.security.domain.vo.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.IpAddress;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.Calendar;

public record AuthenticationBlock (
        IpAddress ipAddress,
        LocalDateTime expiryDate
) {
    public boolean isStillActive() {
        return expiryDate.isBefore(LocalDateTime.now());
    }
}
