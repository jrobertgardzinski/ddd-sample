package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.*;

public record AuthorizationData(
    Email email,
    RefreshToken refreshToken,
    AuthorizationToken authorizationToken,
    RefreshTokenExpiration refreshTokenExpiration,
    AuthorizationTokenExpiration authorizationTokenExpiration) {

    public static AuthorizationData createFor(Email email) {
        return new AuthorizationData(
                email,
                new RefreshToken(Token.random()),
                new AuthorizationToken(Token.random()),
                new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
        );
    }
}
