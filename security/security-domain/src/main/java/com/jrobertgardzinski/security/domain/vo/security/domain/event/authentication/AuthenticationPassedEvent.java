package com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication;

import com.jrobertgardzinski.security.domain.vo.security.domain.aggregate.AuthorizedUserAggregate;

public record AuthenticationPassedEvent(AuthorizedUserAggregate authorizedUserAggregate) implements AuthenticationEvent {
}
