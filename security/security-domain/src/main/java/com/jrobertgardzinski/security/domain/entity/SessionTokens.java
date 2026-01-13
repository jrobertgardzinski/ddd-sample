package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.*;

import java.time.LocalDateTime;

public record SessionTokens(
    Email email,
    RefreshToken refreshToken,
    AccessToken accessToken,
    RefreshTokenExpiration refreshTokenExpiration,
    AuthorizationTokenExpiration authorizationTokenExpiration) {

    public static SessionTokens createFor(Email email) {
        return new SessionTokens(
                email,
                new RefreshToken(Token.random()),
                new AccessToken(Token.random()),
                new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
        );
    }

    public String plainEmail() {
        return email.value();
    }

    public String plainRefreshToken() {
        return refreshToken.value().value();
    }

    public String plainAccessToken() {
        return accessToken.value().value();
    }

    public LocalDateTime plainRefreshTokenExpiration() {
        return refreshTokenExpiration.value().value();
    }

    public LocalDateTime plainAuthorizationTokenExpiration() {
        return authorizationTokenExpiration.value().value();
    }
}
