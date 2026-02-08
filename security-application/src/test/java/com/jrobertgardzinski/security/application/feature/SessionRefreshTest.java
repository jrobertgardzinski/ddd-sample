package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class SessionRefreshTest {/*
    @Mock
    AuthorizationDataRepository authorizationDataRepository;

    SessionRefresh sessionRefresh;

    @BeforeEach
    void init() {
        sessionRefresh = new SessionRefresh(authorizationDataRepository);
    }

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

        assertEquals(
                new NoRefreshTokenFoundEvent(email),
                sessionRefresh.apply(
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

        assertEquals(
                new RefreshTokenExpiredEvent(email),
                sessionRefresh.apply(
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

        RefreshTokenPassedEvent result = (RefreshTokenPassedEvent) sessionRefresh.apply(
                new SessionRefreshRequest(email, refreshToken));

        assertEquals(sessionTokens, result.sessionTokens());
    }*/
}