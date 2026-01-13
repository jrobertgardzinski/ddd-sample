package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;

import java.util.function.Function;

public class SessionGenerator implements Function<AuthenticationPassedEvent, SessionTokens> {
    private final AuthorizationDataRepository authorizationDataRepository;

    public SessionGenerator(AuthorizationDataRepository authorizationDataRepository) {
        this.authorizationDataRepository = authorizationDataRepository;
    }

    @Override
    public SessionTokens apply(AuthenticationPassedEvent authenticationPassedEvent) {
        return authorizationDataRepository.create(
                new SessionTokens(
                        authenticationPassedEvent.email(),
                        new RefreshToken(Token.random()),
                        new AccessToken(Token.random()),
                        new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                        new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
                )
        );
    }
}
