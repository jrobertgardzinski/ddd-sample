package com.jrobertgardzinski.security.application.feature.session.context.dependency;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class StubAuthorizationDataRepository implements AuthorizationDataRepository {

    private final Map<Email, SessionTokens> sessions = new HashMap<>();

    @Override
    public SessionTokens create(SessionTokens sessionTokens) {
        sessions.put(sessionTokens.email(), sessionTokens);
        return sessionTokens;
    }

    @Override
    public void deleteBy(Email email) {
        sessions.remove(email);
    }

    @Override
    public RefreshTokenExpiration findRefreshTokenExpirationBy(Email email, RefreshToken refreshToken) {
        SessionTokens sessionTokens = sessions.get(email);
        if (sessionTokens != null && sessionTokens.refreshToken().equals(refreshToken)) {
            return sessionTokens.refreshTokenExpiration();
        }
        return null;
    }

    @Override
    public Optional<SessionTokens> findBy(Email email) {
        return Optional.ofNullable(sessions.get(email));
    }
}
