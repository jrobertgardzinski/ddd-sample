package com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication;

public record AuthenticationFailedForTheNthTimeEvent(int minutes) implements AuthenticationEvent {
    @Override
    public String toString() {
        return String.format("Authentication failed too many times. Activating a blockade for %d minutes.", minutes);
    }
}
