package com.jrobertgardzinski.security.application.event;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;

public record AuthenticationBlocked(
        AuthenticationBlock authenticationBlock) implements AuthenticationResult {
}
