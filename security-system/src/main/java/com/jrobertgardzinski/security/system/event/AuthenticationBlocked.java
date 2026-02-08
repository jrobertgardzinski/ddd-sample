package com.jrobertgardzinski.security.system.event;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;

public record AuthenticationBlocked(
        AuthenticationBlock authenticationBlock) implements AuthenticationResult {
}
