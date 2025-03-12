package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.*;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailuresLimitReachedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.UserNotFoundEvent;
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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {
    @Mock
    UserLombokRepository userLombokRepository;
    @Mock
    TokenRepository tokenRepository;
    @Mock
    FailedAuthenticationRepository failedAuthenticationRepository;
    @Mock
    AuthenticationBlockRepository authenticationBlockRepository;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userLombokRepository, tokenRepository, failedAuthenticationRepository, authenticationBlockRepository);
    }

    @Nested
    class register {
        @Mock
        Password password;
        @Mock
        Email email;

        @Test
        void positive() {
            when(
                    userLombokRepository.doesExist(email))
            .thenReturn(
                    false);

            assertTrue(securityService.register(email, password).getClass()
                    .isAssignableFrom(RegistrationPassedEvent.class));
        }

        @Test
        void negative() {
            when(
                    userLombokRepository.doesExist(email))
                    .thenReturn(
                            true);

            assertTrue(securityService.register(email, password).getClass()
                    .isAssignableFrom(UserAlreadyExistsEvent.class));
        }
    }

    @Nested
    class authenticate {
        Email email;
        Password correctPassword;
        Password wrongPassword;
        UserLombok userLombok;

        @BeforeEach
        void init() {
            email = new Email("jrobertgardzinski@gmail.com");
            correctPassword = new Password("PasswordHardToGuessAt1stTime!");
            wrongPassword = new Password("AndEvenHarderAfter2ndTime!");
            userLombok = new UserLombok(email, correctPassword);
        }

        @Nested
        class Positive {
            @Mock
            AuthorizationData authorizationData;

            @Test
            void positive() {
                when(
                        userLombokRepository.findBy(email))
                        .thenReturn(
                                userLombok);
                when(
                        tokenRepository.createAuthorizationTokenFor(userLombok.getEmail()))
                        .thenReturn(
                                authorizationData);
                var result = securityService.authenticate(email, correctPassword);

                verify(failedAuthenticationRepository, times(1)).removeAllFor(userLombok.getEmail());
                verify(authenticationBlockRepository, times(1)).removeAllFor(userLombok.getEmail());
                verify(tokenRepository, times(1)).createAuthorizationTokenFor(userLombok.getEmail());
                assertTrue(result.getClass().isAssignableFrom(AuthenticationPassedEvent.class));
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
                        userLombokRepository.findBy(email))
                        .thenReturn(
                                userLombok);
                when(
                        userLombokRepository.findBy(email))
                        .thenReturn(
                                userLombok);
                when(
                        failedAuthenticationRepository.countFailuresBy(userLombok.getEmail()))
                        .thenReturn(
                                new FailuresCount(attempt));
                when(
                        failedAuthenticationRepository.create(any()))
                        .thenReturn(
                                failedAuthentication);


                var result = securityService.authenticate(email, wrongPassword);

                verify(failedAuthenticationRepository, times(1)).create(any());
                assertTrue(result.getClass().isAssignableFrom(AuthenticationFailedEvent.class));
            }

            @Test
            void userNotFound() {
                when(
                        userLombokRepository.findBy(email))
                        .thenReturn(
                                null);

                var result = securityService.authenticate(email, wrongPassword);

                assertTrue(result.getClass().isAssignableFrom(UserNotFoundEvent.class));
            }

            @Nested
            class CausingBlockade {
                @Mock
                AuthenticationBlock authenticationBlock;
                @Mock
                AuthenticationBlockDetails authenticationBlockDetails;

                @Test
                void activateBlockade() {
                    when(
                            userLombokRepository.findBy(email))
                            .thenReturn(
                                    userLombok);
                    when(
                            userLombokRepository.findBy(email))
                            .thenReturn(
                                    userLombok);
                    when(
                            failedAuthenticationRepository.countFailuresBy(userLombok.getEmail()))
                            .thenReturn(
                                    new FailuresCount(FailuresCount.LIMIT));
                    when(
                            authenticationBlockRepository.create(any()))
                            .thenReturn(
                                    authenticationBlock);
                    when(
                            authenticationBlock.details())
                            .thenReturn(
                                    authenticationBlockDetails);

                    var result = securityService.authenticate(email, wrongPassword);

                    verify(failedAuthenticationRepository, times(1)).removeAllFor(userLombok.getEmail());
                    verify(authenticationBlockRepository, times(1)).create(any());
                    assertTrue(result.getClass().isAssignableFrom(AuthenticationFailuresLimitReachedEvent.class));
                }
            }

        }

    }
}