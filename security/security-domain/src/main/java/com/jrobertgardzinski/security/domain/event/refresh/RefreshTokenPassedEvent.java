package com.jrobertgardzinski.security.domain.event.refresh;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;

public record RefreshTokenPassedEvent(SessionTokens sessionTokens) implements RefreshTokenEvent {
}
