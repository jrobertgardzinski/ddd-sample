package com.jrobertgardzinski.security.domain.feature;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.service.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.*;
import io.vavr.control.Try;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

public class Authentication implements Function<AuthenticationRequest, AuthenticationEvent> {
    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public Authentication(UserRepository userRepository, AuthorizationDataRepository authorizationDataRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }


    private Supplier<IllegalArgumentException> supplyAuthenticationFailureException(IpAddress ipAddress) {
        failedAuthenticationRepository.create(
                new FailedAuthenticationDetails(ipAddress, LocalDateTime.now())
        );
        return () -> new IllegalArgumentException("Authentication failed!");
    }

    @Override
    public AuthenticationEvent apply(AuthenticationRequest authenticationRequest) {
        IpAddress ipAddress = authenticationRequest.ipAddress();
        Optional<AuthenticationBlock> authenticationBlock = authenticationBlockRepository.findBy(ipAddress);
        if (authenticationBlock.isPresent() && authenticationBlock.get().isStillActive()) {
            return new AuthenticationFailedEvent("The authentication block is still active for machines from your IP address. Please, try again later: " + authenticationBlock.get().expiryDate());
        }
        FailuresCount failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            AuthenticationBlock newAuthenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(ipAddress, LocalDateTime.now()));
            return new AuthenticationFailedEvent("Too many authentication failures! Try again later: " + newAuthenticationBlock.expiryDate());
        }
        PlainTextPassword enteredPassword = authenticationRequest.plainTextPassword();
        Email email = authenticationRequest.email();
        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty() || !hashAlgorithmPort.verify(optionalUser.get().passwordHash(), enteredPassword)) {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(ipAddress, LocalDateTime.now())
            );
            return new AuthenticationFailedEvent("Authentication failed!");
        }
        failedAuthenticationRepository.removeAllFor(ipAddress);
        authenticationBlockRepository.removeAllFor(ipAddress);
        authorizationDataRepository.findBy(email)
                .ifPresent(e -> authorizationDataRepository.deleteBy(e.email()));
        SessionTokens sessionTokens = authorizationDataRepository.create(
                new SessionTokens(
                        email,
                        new RefreshToken(Token.random()),
                        new AccessToken(Token.random()),
                        new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                        new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
                )
        );
        return new AuthenticationPassedEvent(
                new AuthorizedUserAggregate(
                        email,
                        sessionTokens.refreshToken(),
                        sessionTokens.accessToken()));
    }
}
