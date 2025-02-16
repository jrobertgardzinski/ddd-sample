package com.jrobertgardzinski.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockDetails;

public record AuthenticationFailuresLimitReachedEvent(AuthenticationBlockDetails authenticationBlockDetails) implements AuthenticationEvent {
}
