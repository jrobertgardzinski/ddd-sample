package com.jrobertgardzinski.security.aggregate;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import io.micronaut.serde.annotation.Serdeable;

@Serdeable
public record AuthorizedUserAggregateRootEntity(
    String email,
    String refreshToken,
    String authorizationToken) {

    public static AuthorizedUserAggregateRootEntity from(AuthorizedUserAggregate authorizedUserAggregate) {
        return new AuthorizedUserAggregateRootEntity(
                authorizedUserAggregate.email().value(),
                authorizedUserAggregate.refreshToken().value().value(),
                authorizedUserAggregate.authorizationToken().value().value()
        );
    }
}