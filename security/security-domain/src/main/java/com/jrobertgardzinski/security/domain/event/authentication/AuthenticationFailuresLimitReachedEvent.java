package com.jrobertgardzinski.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;

public record AuthenticationFailuresLimitReachedEvent(AuthenticationBlock authenticationBlock) implements AuthenticationEvent {
}
