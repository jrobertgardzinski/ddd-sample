package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.*;
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

import java.util.Optional;
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
    @Mock
    PasswordSaltRepository passwordSaltRepository;
    @Mock
    PasswordHashAlgorithm passwordHashAlgorithm;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userRepository, authorizationDataRepository, failedAuthenticationRepository, authenticationBlockRepository, passwordSaltRepository, passwordHashAlgorithm);
    }

    @Nested
    class register {
        @Mock PasswordHash passwordHash;
        PlainTextPassword plainTextPassword;
        Email email;

        @BeforeEach
        void init() {
            plainTextPassword = new PlainTextPassword("StrongPassword1!");
            email = new Email("jan.nowak@wp.pl");
        }

        @Test
        void positive() throws Exception {
            when(
                    userRepository.existsBy(email))
            .thenReturn(
                    false);

            UserRegistration userRegistration = new UserRegistration(email, plainTextPassword);

            assertEquals(new RegistrationPassedEvent(userRegistration),
                    securityService.register(userRegistration));
        }

        @Test
        void negative() {
            when(
                    userRepository.existsBy(email))
                    .thenReturn(
                            true);

            assertEquals(new UserAlreadyExistsEvent(),
                    securityService.register(new UserRegistration(email, any())));
        }
    }

    @Nested
    class authenticate {
        IpAddress ipAddress;
        Email email;
        PlainTextPassword correctPlainTextPassword;
        PasswordSalt correctPasswordSalt;
        PlainTextPassword wrongPlainTextPassword;
        PasswordSalt wrongPasswordSalt;
        User user;

        @BeforeEach
        void init() {
            ipAddress = new IpAddress("123.123.123.123");
            email = new Email("jrobertgardzinski@gmail.com");
            correctPlainTextPassword = new PlainTextPassword("PasswordHardToGuessAt1stTime!");
            correctPasswordSalt = new PasswordSalt(email, new Salt("fdjsiofjsdojoiwejriowjofnwifow"));
            wrongPlainTextPassword = new PlainTextPassword("AndEvenHarderAfter2ndTime!");
            correctPasswordSalt = new PasswordSalt(email, new Salt("123siofjsdojoiwejriowjofnwi321"));
            user = new User(email, passwordHashAlgorithm.hash(correctPlainTextPassword, correctPasswordSalt));
        }

        @Nested
        class Positive {
            @Mock
            AuthorizationData authorizationData;

            @Test
            void positive() {
                AuthenticationRequest input = new AuthenticationRequest(ipAddress, email, correctPlainTextPassword);

                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                Optional.of(user));
                when(
                        passwordSaltRepository.findByEmail(email))
                        .thenReturn(
                                correctPasswordSalt);
                when(
                        authorizationDataRepository.create(any()))
                        .thenReturn(
                                authorizationData);
                when(
                        passwordHashAlgorithm.verify(correctPlainTextPassword, correctPasswordSalt, user))
                        .thenReturn(
                                true);

                assertAll(
                        () -> assertDoesNotThrow(() -> securityService.authenticate(
                                input)),
                        () -> verify(failedAuthenticationRepository, times(1)).removeAllFor(ipAddress),
                        () -> verify(authenticationBlockRepository, times(1)).removeAllFor(ipAddress),
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
                                Optional.of(user));
                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                Optional.of(user));
                when(
                        failedAuthenticationRepository.countFailuresBy(ipAddress))
                        .thenReturn(
                                new FailuresCount(attempt));
                when(
                        failedAuthenticationRepository.create(any()))
                        .thenReturn(
                                failedAuthentication);

                assertAll(
                        () -> assertThrows(IllegalArgumentException.class, () -> securityService.authenticate(
                                new AuthenticationRequest(ipAddress, email, wrongPlainTextPassword))),
                        () -> verify(failedAuthenticationRepository, times(1)).create(any())
                );
            }

            @Test
            void userNotFound() {
                when(
                        userRepository.findBy(email))
                        .thenReturn(
                                Optional.empty());

                assertThrows(IllegalArgumentException.class, () -> securityService.authenticate(
                        new AuthenticationRequest(ipAddress, email, correctPlainTextPassword)));
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
                                    Optional.of(user));
                    when(
                            failedAuthenticationRepository.countFailuresBy(ipAddress))
                            .thenReturn(
                                    new FailuresCount(FailuresCount.LIMIT));
                    when(
                            authenticationBlockRepository.create(any()))
                            .thenReturn(
                                    authenticationBlock);

                    assertAll(
                            () -> assertThrows(IllegalArgumentException.class, () -> securityService.authenticate(
                                    new AuthenticationRequest(ipAddress, email, wrongPlainTextPassword))),
                            () -> verify(failedAuthenticationRepository, times(1)).removeAllFor(ipAddress),
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

            assertThrows(IllegalArgumentException.class, () -> securityService.refreshToken(
                    new TokenRefreshRequest(email, refreshToken)));
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

            assertThrows(IllegalArgumentException.class, () -> securityService.refreshToken(
                    new TokenRefreshRequest(email, refreshToken)));
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

            var result = securityService.refreshToken(
                    new TokenRefreshRequest(email, refreshToken));

            assertEquals(authorizationData, result);
        }
    }
}