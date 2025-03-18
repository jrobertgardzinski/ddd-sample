package com.jrobertgardzinski.security.domain.event.refresh;

import com.jrobertgardzinski.security.domain.vo.Email;

public record NoAuthorizationDataFoundEvent(Email email) implements RefreshTokenEvent {
}
