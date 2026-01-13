package com.jrobertgardzinski.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.Email;

public record AuthenticationPassedEvent(Email email) implements AuthenticationEvent {
}
