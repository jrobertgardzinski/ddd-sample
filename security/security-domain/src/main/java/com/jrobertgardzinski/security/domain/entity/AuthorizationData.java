package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.*;

public record AuthorizationData(
    Email email,
    RefreshToken refreshToken,
    AccessToken accessToken,
    RefreshTokenExpiration refreshTokenExpiration,
    AuthorizationTokenExpiration authorizationTokenExpiration) {

    public static AuthorizationData createFor(Email email) {
        return new AuthorizationData(
                email,
                new RefreshToken(Token.random()),
                new AccessToken(Token.random()),
                new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
        );
    }
}
