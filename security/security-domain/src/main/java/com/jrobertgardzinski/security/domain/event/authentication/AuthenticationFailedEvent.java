package com.jrobertgardzinski.security.domain.event.authentication;

public record AuthenticationFailedEvent(String message)
        implements AuthenticationEvent { }
