package com.jrobertgardzinski.security.domain.event.brute.force.protection;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;

public record Blocked(AuthenticationBlock authenticationBlock)
        implements BruteForceProtectionEvent {
}
