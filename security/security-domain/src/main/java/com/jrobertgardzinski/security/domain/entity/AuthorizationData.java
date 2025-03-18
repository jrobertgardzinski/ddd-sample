package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthorizationData {
    @Getter
    private final Email email;
    @Getter
    private final RefreshToken refreshToken;
    @Getter
    private final AuthorizationToken authorizationToken;

    private final RefreshTokenExpiration refreshTokenExpiration;
    private final AuthorizationTokenExpiration authorizationTokenExpiration;

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
