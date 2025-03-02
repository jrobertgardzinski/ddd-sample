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
    UserCredentialsRepository userCredentialsRepository;
    @Mock
    UserDetailsRepository userDetailsRepository;
    @Mock
    TokenRepository tokenRepository;
    @Mock
    FailedAuthenticationRepository failedAuthenticationRepository;
    @Mock
    AuthenticationBlockRepository authenticationBlockRepository;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userDetailsRepository, userCredentialsRepository, tokenRepository, failedAuthenticationRepository, authenticationBlockRepository);
    }

    @Nested
    class register {
        @Mock
        Password password;
        @Mock
        Email email;
        @Mock
        UserDetails userDetails;
        @Mock
        UserCredentials userCredentials;


        @Test
        void positive() {
            when(
                    userDetailsRepository.doesExist(email))
            .thenReturn(
                    false);
            when(
                    userDetailsRepository.create(new UserDetails(email)))
            .thenReturn(
                    userDetails);
            when(
                    userCredentialsRepository.create(new UserCredentials(email, password)))
            .thenReturn(
                    userCredentials);

            assertTrue(securityService.register(email, password).getClass()
                    .isAssignableFrom(RegistrationPassedEvent.class));
        }

        @Test
        void negative() {
            when(
                    userDetailsRepository.doesExist(email))
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
        UserCredentials userCredentials;
        UserDetails userDetails;

        @BeforeEach
        void init() {
            email = new Email("jrobertgardzinski@gmail.com");
            correctPassword = new Password("PasswordHardToGuessAt1stTime!");
            wrongPassword = new Password("AndEvenHarderAfter2ndTime!");
            userCredentials = new UserCredentials(
                    email,
                    correctPassword
            );
            userDetails = new UserDetails(email);
        }

        @Nested
        class Positive {
            @Mock
            AuthorizationData authorizationData;
            @Mock
            TokenDetails tokenDetails;

            @Test
            void positive() {
                when(
                        userCredentialsRepository.findBy(email))
                        .thenReturn(
                                userCredentials);
                when(
                        userDetailsRepository.findBy(email))
                        .thenReturn(
                                userDetails);
                when(
                        tokenRepository.createAuthorizationTokenFor(userCredentials.email()))
                        .thenReturn(
                                authorizationData);
                /*when(
                        authorizationData.)
                        .thenReturn(
                                tokenDetails);*/

                var result = securityService.authenticate(email, correctPassword);

                verify(failedAuthenticationRepository, times(1)).removeAllFor(userCredentials.email());
                verify(authenticationBlockRepository, times(1)).removeAllFor(userCredentials.email());
                verify(tokenRepository, times(1)).createAuthorizationTokenFor(userCredentials.email());
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
                        userCredentialsRepository.findBy(email))
                        .thenReturn(
                                userCredentials);
                when(
                        userDetailsRepository.findBy(email))
                        .thenReturn(
                                userDetails);
                when(
                        failedAuthenticationRepository.countFailuresBy(userCredentials.email()))
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
                        userCredentialsRepository.findBy(email))
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
                            userCredentialsRepository.findBy(email))
                            .thenReturn(
                                    userCredentials);
                    when(
                            userDetailsRepository.findBy(email))
                            .thenReturn(
                                    userDetails);
                    when(
                            failedAuthenticationRepository.countFailuresBy(userCredentials.email()))
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

                    verify(failedAuthenticationRepository, times(1)).removeAllFor(userCredentials.email());
                    verify(authenticationBlockRepository, times(1)).create(any());
                    assertTrue(result.getClass().isAssignableFrom(AuthenticationFailuresLimitReachedEvent.class));
                }
            }

        }

    }
}