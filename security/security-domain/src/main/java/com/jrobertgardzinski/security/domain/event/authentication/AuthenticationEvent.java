package com.jrobertgardzinski.security.domain.event.authentication;

public sealed interface AuthenticationEvent permits AuthenticationFailedEvent, AuthenticationFailuresLimitReachedEvent, AuthenticationPassedEvent, UserNotFoundEvent {
}
