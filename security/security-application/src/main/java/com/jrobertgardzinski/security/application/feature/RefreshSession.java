package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.event.refresh.NoRefreshTokenFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenExpiredEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenPassedEvent;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.SessionRefreshRequest;

import java.util.function.Function;

public class RefreshSession implements Function<SessionRefreshRequest, RefreshTokenEvent> {
    private final AuthorizationDataRepository authorizationDataRepository;

    public RefreshSession(AuthorizationDataRepository authorizationDataRepository) {
        this.authorizationDataRepository = authorizationDataRepository;
    }

    @Override
    public RefreshTokenEvent apply(SessionRefreshRequest sessionRefreshRequest) {
        Email email = sessionRefreshRequest.email();
        RefreshToken refreshToken = sessionRefreshRequest.refreshToken();
        RefreshTokenExpiration refreshTokenExpiration = authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken);
        if (refreshTokenExpiration == null) {
            return new NoRefreshTokenFoundEvent(email);
        }
        authorizationDataRepository.deleteBy(email);
        if (refreshTokenExpiration.hasExpired()) {
            return new RefreshTokenExpiredEvent(email);
        }
        return new RefreshTokenPassedEvent(
                authorizationDataRepository.create(SessionTokens.createFor(email)));
    }
}
