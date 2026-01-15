package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.entity.User;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
class AuthenticationTest {/*
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

    Authenticat authentication;

    @BeforeEach
    void init() {
        authentication = new Authentication(
                userRepository,
                hashAlgorithmPort
        );
    }

    @Mock
    IpAddress ipAddress;
    @Mock
    Email email;
    @Mock
    PlainTextPassword correctPlainTextPassword;
    @Mock
    User user;

    @Nested
    class Positive {
        @Mock
        SessionTokens sessionTokens;

        @Test
        void positive() {

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

            Credentials input = new Credentials(email, correctPlainTextPassword);

            assertTrue(
                    authentication
                            .apply(
                                    input)
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
                                    new Credentials(email, correctPlainTextPassword))
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
                                new Credentials(email, correctPlainTextPassword));
                assertTrue(
                        result instanceof ActivateBlockadeEvent);
            }
        }

    }
*/
}