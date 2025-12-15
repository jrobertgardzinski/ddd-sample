package com.jrobertgardzinski.security.domain.vo.security.domain.feature;

import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationFailedForTheNthTimeEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.UserRepository;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationTest {
    @Mock
    UserRepository userRepository;
    @Mock
    AuthorizationDataRepository authorizationDataRepository;
    @Mock
    FailedAuthenticationRepository failedAuthenticationRepository;
    @Mock
    AuthenticationBlockRepository authenticationBlockRepository;
    @Mock
    HashAlgorithmPort hashAlgorithmPort;

    Authentication authentication;

    IpAddress ipAddress;
    Email email;
    PlainTextPassword correctPlainTextPassword;
    Salt correctPasswordSalt;
    PlainTextPassword wrongPlainTextPassword;
    Salt wrongPasswordSalt;
    User user;

    @BeforeEach
    void init() {
        authentication = new Authentication(
                userRepository,
                authorizationDataRepository,
                failedAuthenticationRepository,
                authenticationBlockRepository,
                hashAlgorithmPort
        );

        ipAddress = new IpAddress("123.123.123.123");
        email = new Email("jrobertgardzinski@gmail.com");
        correctPlainTextPassword = new PlainTextPassword("PasswordHardToGuessAt1stTime!");
        correctPasswordSalt = Salt.generate();
        wrongPlainTextPassword = new PlainTextPassword("AndEvenHarderAfter2ndTime!");
        wrongPasswordSalt = Salt.generate();
        user = new User(email, hashAlgorithmPort.hash(correctPlainTextPassword, correctPasswordSalt));
    }

    @Nested
    class Positive {
        @Mock
        SessionTokens sessionTokens;

        @Test
        void positive() {
            AuthenticationRequest input = new AuthenticationRequest(ipAddress, email, correctPlainTextPassword);

            when(
                    authenticationBlockRepository.findBy(ipAddress)
                    )
                    .thenReturn(
                            Optional.empty());
            when(
                    failedAuthenticationRepository.countFailuresBy(ipAddress))
                    .thenReturn(
                            new FailuresCount(0));
            when(
                    userRepository.findBy(email))
                    .thenReturn(
                            Optional.of(user));
            when(
                    hashAlgorithmPort.verify(Optional.of(user).get().passwordHash(), correctPlainTextPassword))
                    .thenReturn(
                            true);
            when(
                    authorizationDataRepository.create(any()))
                    .thenReturn(
                            sessionTokens);

            assertTrue(
                    authentication
                            .apply(
                                    new AuthenticationRequest(ipAddress, email, correctPlainTextPassword))
                            .getClass().isAssignableFrom(AuthenticationPassedEvent.class)
            );
        }
    }

    @Nested
    class Negative {
        @Mock
        FailedAuthentication failedAuthentication;

        public static Stream<Arguments> source() {
            return Stream.of(false, true)
                    .flatMap(flag -> IntStream.range(0, FailuresCount.LIMIT)
                            .mapToObj(i -> Arguments.of(i, flag)));
        }

        @ParameterizedTest
        @MethodSource("source")
        void negative(int attempt, boolean isUserPresent) {
            when(
                    authenticationBlockRepository.findBy(ipAddress))
                    .thenReturn(
                            Optional.empty());
            when(
                    failedAuthenticationRepository.countFailuresBy(ipAddress))
                    .thenReturn(
                            new FailuresCount(attempt));
            when(
                    userRepository.findBy(email))
                    .thenReturn(
                            isUserPresent ? Optional.of(user) : Optional.empty());

            assertEquals(
                    new AuthenticationFailedEvent(),
                    authentication
                            .apply(
                                    new AuthenticationRequest(ipAddress, email, correctPlainTextPassword))
            );
        }

        @Nested
        class CausingBlockade {
            @Mock
            AuthenticationBlock authenticationBlock;

            @Test
            void activateBlockade() {
                when(
                        authenticationBlockRepository.findBy(ipAddress))
                        .thenReturn(
                                Optional.empty());
                when(
                        failedAuthenticationRepository.countFailuresBy(ipAddress))
                        .thenReturn(
                                new FailuresCount(FailuresCount.LIMIT));
                when(
                        authenticationBlockRepository.create(any()))
                        .thenReturn(
                                authenticationBlock);

                AuthenticationEvent result = authentication
                        .apply(
                                new AuthenticationRequest(ipAddress, email, correctPlainTextPassword));
                assertTrue(
                        result instanceof AuthenticationFailedForTheNthTimeEvent);
            }
        }

    }

}