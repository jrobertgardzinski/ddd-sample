package com.jrobertgardzinski.security.system.event;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;

public record AuthenticationPassed(SessionTokens session) implements AuthenticationResult {
}
