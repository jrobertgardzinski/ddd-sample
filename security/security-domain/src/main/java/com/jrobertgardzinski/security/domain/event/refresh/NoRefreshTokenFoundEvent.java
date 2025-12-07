package com.jrobertgardzinski.security.domain.event.refresh;

import com.jrobertgardzinski.security.domain.vo.Email;

public record NoRefreshTokenFoundEvent(Email email) implements RefreshTokenEvent {
    @Override
    public String toString() {
        return "No refresh token found for " + email.value();
    }
}
