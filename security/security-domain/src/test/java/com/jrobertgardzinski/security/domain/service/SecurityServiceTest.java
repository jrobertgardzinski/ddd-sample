package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.*;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailuresLimitReachedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.UserNotFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.NoAuthorizationDataFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenExpiredEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.*;
import com.jrobertgardzinski.security.domain.vo.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    AuthorizationDataRepository authorizationDataRepository;
    @Mock
    FailedAuthenticationRepository failedAuthenticationRepository;
    @Mock
    AuthenticationBlockRepository authenticationBlockRepository;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userRepository, authorizationDataRepository, failedAuthenticationRepository, authenticationBlockRepository);
    }

    @Nested
    class register {
        Password password;
        Email email;

        @BeforeEach
        void init() {
            password = new Password("StrongPassword1!");
            email = new Email("jan.nowak@wp.pl");
        }

        @Test
        void positive() {
            when(
                    userRepository.existsBy(email))
            .thenReturn(
                    false);
            User user = new User(email, password);
            UserEntity userEntity = new UserEntity(user);
            when(
                    userRepository.save(user))
            .thenReturn(
                    userEntity);

            assertEquals(userEntity,
                    securityService.register(email, password));
        }

        @Test
        void negative() {
            when(
                    userRepository.existsBy(email))
                    .thenReturn(
                            true);

            assertThrows(
                    IllegalArgumentException.class,
                    () -> securityService.register(email, password),
                    "User with the e-mail: " + email.value() + " exists!"
            );
        }
    }

    @Nested
    class authenticate {
        IpAddress ipAddress;
        Email email;
        Password correctPassword;
        Password wrongPassword;
        User user;

        @BeforeEach
        void init() {
            ipAddress = new IpAddress("123.123.123.123");
            email = new Email("jrobertgardzinski@gmail.com");
            correctPassword = new Password("PasswordHardToGuessAt1stTime!");
            wrongPassword = new Password("AndEvenHarderAfter2ndTime!");
            user = new User(email, correctPassword);
        }

        @Nested
        class Positive {
            @Mock
            AuthorizationData authorizationData;

            @Test
            void positive() {
                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                user);
                when(
                        authorizationDataRepository.create(any()))
                        .thenReturn(
                                authorizationData);

                assertAll(
                        () -> assertDoesNotThrow(() -> securityService.authenticate(ipAddress, email, correctPassword)),
                        () -> verify(failedAuthenticationRepository, times(1)).removeAllFor(user.email()),
                        () -> verify(authenticationBlockRepository, times(1)).removeAllFor(user.email()),
                        () -> verify(authorizationDataRepository, times(1)).create(any())
                );
            }
        }

        @Nested
        class Negative {
            @Mock
            FailedAuthentication failedAuthentication;

            public static Stream<Arguments> source() {
                return IntStream.range(0, FailuresCount.LIMIT).boxed().map(Arguments::of);
            }

            @ParameterizedTest
            @MethodSource("source")
            void negative(int attempt) {
                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                user);
                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                user);
                when(
                        failedAuthenticationRepository.countFailuresBy(user.email()))
                        .thenReturn(
                                new FailuresCount(attempt));
                when(
                        failedAuthenticationRepository.create(any()))
                        .thenReturn(
                                failedAuthentication);

                assertAll(
                        () -> assertThrows(IllegalArgumentException.class, () -> securityService.authenticate(ipAddress, email, wrongPassword)),
                        () -> verify(failedAuthenticationRepository, times(1)).create(any())
                );
            }

            @Test
            void userNotFound() {
                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                null);

                assertThrows(IllegalArgumentException.class, () -> securityService.authenticate(ipAddress, email, correctPassword));
            }

            @Nested
            class CausingBlockade {
                @Mock
                AuthenticationBlock authenticationBlock;

                @Test
                void activateBlockade() {
                    when(
                            userRepository.findBy(email))
                            .thenReturn(
                                    user);
                    when(
                            failedAuthenticationRepository.countFailuresBy(user.email()))
                            .thenReturn(
                                    new FailuresCount(FailuresCount.LIMIT));
                    when(
                            authenticationBlockRepository.create(any()))
                            .thenReturn(
                                    authenticationBlock);

                    assertAll(
                            () -> assertThrows(IllegalArgumentException.class, () -> securityService.authenticate(ipAddress, email, wrongPassword)),
                            () -> verify(failedAuthenticationRepository, times(1)).removeAllFor(user.email()),
                            () -> verify(authenticationBlockRepository, times(1)).create(any())
                    );
                }
            }

        }

    }

    @Nested
    class refreshToken {
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

            assertThrows(IllegalArgumentException.class, () -> securityService.refreshToken(email, refreshToken));
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

            assertThrows(IllegalArgumentException.class, () -> securityService.refreshToken(email, refreshToken));
        }

        @Test
        void RefreshTokenPassedEvent() {
            RefreshTokenExpiration refreshTokenExpiration = mock(RefreshTokenExpiration.class);
            AuthorizationData authorizationData = mock(AuthorizationData.class);

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
                            authorizationData);

            var result = securityService.refreshToken(email, refreshToken);

            assertEquals(authorizationData, result);
        }
    }
}