package com.jrobertgardzinski.security.domain.event.refresh;

import com.jrobertgardzinski.security.domain.vo.Email;

public record RefreshTokenExpiredEvent(Email email) implements RefreshTokenEvent {
}
