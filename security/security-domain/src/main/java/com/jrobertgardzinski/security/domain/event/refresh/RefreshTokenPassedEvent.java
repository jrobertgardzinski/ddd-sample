package com.jrobertgardzinski.security.domain.event.refresh;

import com.jrobertgardzinski.security.domain.entity.AuthorizationData;

public record RefreshTokenPassedEvent(AuthorizationData authorizationData) implements RefreshTokenEvent {
}
