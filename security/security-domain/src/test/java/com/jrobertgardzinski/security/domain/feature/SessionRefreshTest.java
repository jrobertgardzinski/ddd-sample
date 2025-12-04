package com.jrobertgardzinski.security.domain.feature;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.SessionRefreshRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionRefreshTest {
    @Mock
    AuthorizationDataRepository authorizationDataRepository;

    SessionRefresh sessionRefresh;

    @BeforeEach
    void init() {
        sessionRefresh = new SessionRefresh(authorizationDataRepository);
    }

    // todo compare it to AuthorizationTest - it uses implementations (stubs?) instead of mocks.
    @Mock
    Email email;
    @Mock
    RefreshToken refreshToken;

    @Test
    void NoAuthorizationDataFoundEvent() {
        when(
                authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken))
                .thenReturn(
                        null);

        assertThrows(IllegalArgumentException.class, () -> sessionRefresh.apply(
                new SessionRefreshRequest(email, refreshToken)));
    }

    @Test
    void RefreshTokenExpiredEvent() {
        RefreshTokenExpiration refreshTokenExpiration = mock(RefreshTokenExpiration.class);

        when(
                authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken))
                .thenReturn(
                        refreshTokenExpiration);
        when(
                refreshTokenExpiration.hasExpired())
                .thenReturn(
                        true);

        assertThrows(IllegalArgumentException.class, () -> sessionRefresh.apply(
                new SessionRefreshRequest(email, refreshToken)));
    }

    @Test
    void RefreshTokenPassedEvent() {
        RefreshTokenExpiration refreshTokenExpiration = mock(RefreshTokenExpiration.class);
        SessionTokens sessionTokens = mock(SessionTokens.class);

        when(
                authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken))
                .thenReturn(
                        refreshTokenExpiration);
        when(
                refreshTokenExpiration.hasExpired())
                .thenReturn(
                        false);
        when(
                authorizationDataRepository.create(any()))
                .thenReturn(
                        sessionTokens);

        SessionTokens result = sessionRefresh.apply(
                new SessionRefreshRequest(email, refreshToken));

        assertEquals(sessionTokens, result);
    }
}