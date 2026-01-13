package com.jrobertgardzinski.security.domain.event.authentication;

public record AuthenticationFailedEvent()
        implements AuthenticationEvent {
    @Override
    public String toString() {
        return "Authentication failed!";
    }
}
