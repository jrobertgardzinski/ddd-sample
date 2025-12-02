package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.registration.PossibleRaceCondition;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.*;
import com.jrobertgardzinski.security.domain.vo.*;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.function.Supplier;

// todo split into separate feature classes
public class SecurityService {
    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public SecurityService(UserRepository userRepository, AuthorizationDataRepository authorizationDataRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    public RegistrationEvent register(UserRegistration userRegistration) {
        Email email = userRegistration.email();
        if (userRepository.existsBy(email)) {
            return new UserAlreadyExistsEvent();
        }
        try {
            PlainTextPassword plainTextPassword = userRegistration.plainTextPassword();
            Salt salt = Salt.generate();
            PasswordHash passwordHash = hashAlgorithmPort.hash(plainTextPassword, salt);
            User user = new User(
                    userRegistration.email(),
                    passwordHash
            );
            userRepository.save(user);
            return new RegistrationPassedEvent(email);
        } catch (Exception e) {
            return new PossibleRaceCondition();
        }
    }

    private Supplier<IllegalArgumentException> supplyAuthenticationFailureException(IpAddress ipAddress) {
        failedAuthenticationRepository.create(
                new FailedAuthenticationDetails(ipAddress, LocalDateTime.now())
        );
        return () -> new IllegalArgumentException("Authentication failed!");
    }

    // todo bring back events (like register)
    public AuthorizedUserAggregate authenticate(AuthenticationRequest authenticationRequest) {
        IpAddress ipAddress = authenticationRequest.ipAddress();
        Optional<AuthenticationBlock> authenticationBlock = authenticationBlockRepository.findBy(ipAddress);
        if (authenticationBlock.isPresent() && authenticationBlock.get().isStillActive()) {
            throw new IllegalArgumentException("The authentication block is still active for machines from your IP address. Please, try again later: " + authenticationBlock.get().expiryDate());
        }
        Email email = authenticationRequest.email();
        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty()) {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
        User user = optionalUser.get();
        PlainTextPassword enteredPassword = authenticationRequest.plainTextPassword();
        if (hashAlgorithmPort.verify(user.passwordHash(), enteredPassword)) {
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
            return new AuthorizedUserAggregate(email, sessionTokens.refreshToken(), sessionTokens.accessToken());
        }
        FailuresCount failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            AuthenticationBlock newAuthenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(ipAddress, LocalDateTime.now()));
            throw new IllegalArgumentException("Too many authentication failures! Try again later: " + newAuthenticationBlock.expiryDate());
        }
        else {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
    }

    // todo bring back events (like register)
    public SessionTokens refreshSession(SessionRefreshRequest sessionRefreshRequest) {
        Email email = sessionRefreshRequest.email();
        RefreshToken refreshToken = sessionRefreshRequest.refreshToken();
        RefreshTokenExpiration refreshTokenExpiration = authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken);
        if (refreshTokenExpiration == null) {
            throw new IllegalArgumentException("No refresh token found for " + email);
        }
        authorizationDataRepository.deleteBy(email);
        if (refreshTokenExpiration.hasExpired()) {
            throw new IllegalArgumentException("Refresh token for " + email + " has expired");
        }
        return authorizationDataRepository.create(SessionTokens.createFor(email));
    }
}
