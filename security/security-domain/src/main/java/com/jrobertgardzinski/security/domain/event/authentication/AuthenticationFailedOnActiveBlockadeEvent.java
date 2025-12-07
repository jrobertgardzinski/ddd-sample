package com.jrobertgardzinski.security.domain.event.authentication;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

public record AuthenticationFailedOnActiveBlockadeEvent(LocalDateTime expiryDate, int retryAfterHeader) implements AuthenticationEvent {
    public AuthenticationFailedOnActiveBlockadeEvent(LocalDateTime expiryDate) {
        this(expiryDate, (int) ChronoUnit.SECONDS.between(expiryDate, LocalDateTime.now()));
    }
}
