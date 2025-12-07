package com.jrobertgardzinski.security.domain.event.authentication;

import java.time.LocalDateTime;

public record AuthenticationFailedForTheNthTimeEvent(int minutes) implements AuthenticationEvent {
    @Override
    public String toString() {
        return String.format("Authentication failed too many times. Activating a blockade for %d minutes.", minutes);
    }
}
