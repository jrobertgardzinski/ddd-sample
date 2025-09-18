package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.registration.PossibleRaceCondition;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.*;

import java.util.Calendar;
import java.util.Optional;
import java.util.function.Supplier;

public class SecurityService {
    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    public SecurityService(UserRepository userRepository, AuthorizationDataRepository authorizationDataRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
    }

    public RegistrationEvent register(User user) {
        Email email = user.email();
        if (System.currentTimeMillis() %2 == 0 && userRepository.existsBy(email)) {
            return new UserAlreadyExistsEvent();
        }
        try {
            return new RegistrationPassedEvent(userRepository.save(user));
        } catch (Exception e) {
            return new PossibleRaceCondition();
        }
    }

    private Supplier<IllegalArgumentException> supplyAuthenticationFailureException(IpAddress ipAddress) {
        failedAuthenticationRepository.create(
                new FailedAuthenticationDetails(ipAddress, Calendar.getInstance())
        );
        return () -> new IllegalArgumentException("Authentication failed!");
    }

    public AuthorizedUserAggregate authenticate(AuthenticationRequest authenticationRequest) {
        IpAddress ipAddress = authenticationRequest.ipAddress();
        Optional<AuthenticationBlock> authenticationBlock = authenticationBlockRepository.findBy(ipAddress);
        if (authenticationBlock.isPresent() && authenticationBlock.get().isStillActive()) {
            throw new IllegalArgumentException("The authentication block is still active for machines from your IP address. Please, try again later: " + authenticationBlock.get().getExpiryDate());
        }
        Email email = authenticationRequest.email();
        Optional<User> optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty()) {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
        User user = optionalUser.get();
        Password password = authenticationRequest.password();
        if (user.password().enteredRight(password)) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            authenticationBlockRepository.removeAllFor(ipAddress);
            authorizationDataRepository.findBy(email)
                    .ifPresent(e -> authorizationDataRepository.deleteBy(e.email()));
            var authorizationData = authorizationDataRepository.create(
                    new AuthorizationData(
                            email,
                            new RefreshToken(Token.random()),
                            new AuthorizationToken(Token.random()),
                            new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                            new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
                    )
            );
            return new AuthorizedUserAggregate(email, authorizationData.refreshToken(), authorizationData.authorizationToken());
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            var newAuthenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(ipAddress, Calendar.getInstance()));
            throw new IllegalArgumentException("Too many authentication failures! Try again later: " + newAuthenticationBlock.getExpiryDate());
        }
        else {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
    }

    public AuthorizationData refreshToken(TokenRefreshRequest tokenRefreshRequest) {
        Email email = tokenRefreshRequest.email();
        RefreshToken refreshToken = tokenRefreshRequest.refreshToken();
        RefreshTokenExpiration refreshTokenExpiration = authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken);
        if (refreshTokenExpiration == null) {
            throw new IllegalArgumentException("No refresh token found for " + email);
        }
        authorizationDataRepository.deleteBy(email);
        if (refreshTokenExpiration.hasExpired()) {
            throw new IllegalArgumentException("Refresh token for " + email + " has expired");
        }
        return authorizationDataRepository.create(AuthorizationData.createFor(email));
    }
}
