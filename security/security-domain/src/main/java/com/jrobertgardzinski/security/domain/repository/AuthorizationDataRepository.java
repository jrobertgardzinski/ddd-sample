package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;

import java.util.Optional;

public interface AuthorizationDataRepository {
    SessionTokens create(SessionTokens sessionTokens);

    void deleteBy(Email email);

    RefreshTokenExpiration findRefreshTokenExpirationBy(Email email, RefreshToken refreshToken);

    Optional<SessionTokens> findBy(Email email);
}
