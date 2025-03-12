package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.*;

public record AuthorizationData(
        AuthorizationId id,
        RefreshToken refreshToken,
        RefreshTokenExpiration refreshTokenExpiration,
        AuthorizationToken authorizationToken,
        AuthorizationTokenExpiration authorizationTokenExpiration
) {
}
