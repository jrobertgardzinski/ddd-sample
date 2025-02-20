package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.entity.Token;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailuresLimitReachedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.UserNotFoundEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.TokenRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    TokenRepository tokenRepository;
    @Mock
    FailedAuthenticationRepository failedAuthenticationRepository;
    @Mock
    AuthenticationBlockRepository authenticationBlockRepository;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userRepository, tokenRepository, failedAuthenticationRepository, authenticationBlockRepository);
    }

    @Nested
    class register {
        @Mock
        UserDetails userDetails;

        @Test
        void positive() {
            when(
                    userRepository.createUser(userDetails))
            .thenReturn(
                    Optional.of(new User(new UserId(1L), userDetails)));
            assertTrue(securityService.register(userDetails).getClass()
                    .isAssignableFrom(RegistrationPassedEvent.class));
        }

        @Test
        void negative() {
            when(
                    userRepository.createUser(userDetails))
            .thenReturn(
                    Optional.empty());
            assertTrue(securityService.register(userDetails).getClass()
                    .isAssignableFrom(UserAlreadyExistsEvent.class));
        }
    }

    @Nested
    class authenticate {
        Email email;
        Password correctPassword;
        Password wrongPassword;
        User user;

        @BeforeEach
        void init() {
            email = new Email("jrobertgardzinski@gmail.com");
            correctPassword = new Password("PasswordHardToGuessAt1stTime!");
            wrongPassword = new Password("AndEvenHarderAfter2ndTime!");
            user = new User(
                    new UserId(1),
                    new UserDetails(
                            email,
                            correctPassword
                    )
            );
        }

        @Nested
        class Positive {
            @Mock
            Token token;
            @Mock
            TokenDetails tokenDetails;

            @Test
            void positive() {
                when(
                        userRepository.findUserByEmail(email))
                        .thenReturn(
                                Optional.of(user));
                when(
                        tokenRepository.createAuthorizationToken(user.id()))
                        .thenReturn(
                                token);
                when(
                        token.details())
                        .thenReturn(
                                tokenDetails);

                var result = securityService.authenticate(email, correctPassword);

                verify(failedAuthenticationRepository, times(1)).removeAllFor(user.id());
                verify(authenticationBlockRepository, times(1)).removeAllFor(user.id());
                verify(tokenRepository, times(1)).createAuthorizationToken(user.id());
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
                        userRepository.findUserByEmail(email))
                        .thenReturn(
                                Optional.of(user));
                when(
                        failedAuthenticationRepository.countFailuresBy(user.id()))
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
                        userRepository.findUserByEmail(email))
                        .thenReturn(
                                Optional.empty());

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
                            userRepository.findUserByEmail(email))
                            .thenReturn(
                                    Optional.of(user));
                    when(
                            failedAuthenticationRepository.countFailuresBy(user.id()))
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

                    verify(failedAuthenticationRepository, times(1)).removeAllFor(user.id());
                    verify(authenticationBlockRepository, times(1)).create(any());
                    assertTrue(result.getClass().isAssignableFrom(AuthenticationFailuresLimitReachedEvent.class));
                }
            }

        }

    }
}