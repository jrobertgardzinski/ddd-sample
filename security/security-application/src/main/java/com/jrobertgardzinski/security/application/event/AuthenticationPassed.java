package com.jrobertgardzinski.security.application.event;

public record AuthenticationPassed(com.jrobertgardzinski.security.domain.entity.SessionTokens session) implements AuthenticationResult {
}
