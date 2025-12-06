package com.jrobertgardzinski.security.aggregate;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.vo.AccessToken;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.Token;
import io.micronaut.serde.annotation.Serdeable;

@Serdeable
public record AuthorizedUserAggregateRootEntity(
    String email,
    String refreshToken,
    String accessToken) {

    public static AuthorizedUserAggregateRootEntity fromDomain(AuthorizedUserAggregate authorizedUserAggregate) {
        return new AuthorizedUserAggregateRootEntity(
                authorizedUserAggregate.email().value(),
                authorizedUserAggregate.refreshToken().value().value(),
                authorizedUserAggregate.accessToken().value().value()
        );
    }

    public AuthorizedUserAggregate asDomain() {
        return new AuthorizedUserAggregate(
                new Email(email),
                new RefreshToken(new Token(refreshToken)),
                new AccessToken(new Token(accessToken))
        );
    }
}