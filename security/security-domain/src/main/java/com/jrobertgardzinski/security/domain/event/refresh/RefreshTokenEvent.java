package com.jrobertgardzinski.security.domain.event.refresh;

public sealed interface RefreshTokenEvent permits NoRefreshTokenFoundEvent, RefreshTokenExpiredEvent, RefreshTokenPassedEvent {
}
