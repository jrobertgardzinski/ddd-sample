package com.jrobertgardzinski.security.domain.feature;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.SessionRefreshRequest;

import java.util.function.Function;

public class SessionRefresh implements Function<SessionRefreshRequest, SessionTokens> {
    private final AuthorizationDataRepository authorizationDataRepository;

    public SessionRefresh(AuthorizationDataRepository authorizationDataRepository) {
        this.authorizationDataRepository = authorizationDataRepository;
    }

    // todo bring back events (like register)
    @Override
    public SessionTokens apply(SessionRefreshRequest sessionRefreshRequest) {
        Email email = sessionRefreshRequest.email();
        RefreshToken refreshToken = sessionRefreshRequest.refreshToken();
        RefreshTokenExpiration refreshTokenExpiration = authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken);
        if (refreshTokenExpiration == null) {
            throw new IllegalArgumentException("No refresh token found for " + email);
        }
        authorizationDataRepository.deleteBy(email);
        if (refreshTokenExpiration.hasExpired()) {
            throw new IllegalArgumentException("Refresh token for " + email + " has expired");
        }
        return authorizationDataRepository.create(SessionTokens.createFor(email));
    }
}
