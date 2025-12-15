package com.jrobertgardzinski.security.domain.vo.security.domain.feature;

import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.function.Function;
import java.util.function.Supplier;

// todo make it a pipeline https://chatgpt.com/share/69336aec-eedc-8005-9095-ea6fd0a14551
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
            return new AuthenticationFailedOnActiveBlockadeEvent(authenticationBlock.get().expiryDate());
        }
        FailuresCount failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            int minutes = new Random().nextInt(8) + 3;
            authenticationBlockRepository.create(
                    new AuthenticationBlock(
                            ipAddress,
                            LocalDateTime.now().plusMinutes(minutes)));
            return new AuthenticationFailedForTheNthTimeEvent(minutes);
        }
        PlainTextPassword enteredPassword = authenticationRequest.plainTextPassword();
        Email email = authenticationRequest.email();
        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty() || !hashAlgorithmPort.verify(optionalUser.get().passwordHash(), enteredPassword)) {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(ipAddress, LocalDateTime.now())
            );
            return new AuthenticationFailedEvent();
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
