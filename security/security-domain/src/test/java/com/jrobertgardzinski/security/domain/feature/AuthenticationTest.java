package com.jrobertgardzinski.security.domain.feature;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.service.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;

import java.util.Optional;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;

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
                    userRepository.findBy(email))
                    .thenReturn(
                            Optional.of(user));
            when(
                    authorizationDataRepository.create(any()))
                    .thenReturn(
                            sessionTokens);

            assertAll(
                    () -> assertDoesNotThrow(() -> authentication.apply(
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
                    () -> assertThrows(IllegalArgumentException.class, () -> authentication.apply(
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

            assertThrows(IllegalArgumentException.class, () -> authentication.apply(
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
                        () -> assertThrows(IllegalArgumentException.class, () -> authentication.apply(
                                new AuthenticationRequest(ipAddress, email, wrongPlainTextPassword))),
                        () -> verify(failedAuthenticationRepository, times(1)).removeAllFor(ipAddress),
                        () -> verify(authenticationBlockRepository, times(1)).create(any())
                );
            }
        }

    }

}