package com.jrobertgardzinski.security.domain.vo.security.domain.event.refresh;

import com.jrobertgardzinski.security.domain.vo.Email;

public record RefreshTokenExpiredEvent(Email email) implements RefreshTokenEvent {
    @Override
    public String toString() {
        return String.format("Refresh Token for %s has expired", email);
    }
}
