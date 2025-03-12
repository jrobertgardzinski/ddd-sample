package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthorizationData {
    @Getter
    private final RefreshToken refreshToken;
    @Getter
    private final AuthorizationToken authorizationToken;

    private final Email email;
    private final RefreshTokenExpiration refreshTokenExpiration;
    private final AuthorizationTokenExpiration authorizationTokenExpiration;
}
