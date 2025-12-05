package com.jrobertgardzinski.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.Email;

public record UserNotFoundEvent(Email email) implements AuthenticationEvent {
}
