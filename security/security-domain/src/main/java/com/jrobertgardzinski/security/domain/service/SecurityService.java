package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.entity.UserEntity;
import com.jrobertgardzinski.security.domain.vo.User;
import com.jrobertgardzinski.security.domain.event.refresh.NoAuthorizationDataFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenExpiredEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenPassedEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
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

    public UserEntity register(Email email, Password password) {
        if (userRepository.existsBy(email)) {
            throw new IllegalArgumentException("User with the e-mail: " + email.value() + " exists!");
        }
        User user = new User(email, password);
        return userRepository.save(user);
    }

    private Supplier<IllegalArgumentException> supplyAuthenticationFailureException(IpAddress ipAddress) {
        failedAuthenticationRepository.create(
                new FailedAuthenticationDetails(ipAddress, Calendar.getInstance())
        );
        return () -> new IllegalArgumentException("Authentication failed!");
    }

    public AuthorizedUserAggregate authenticate(IpAddress ipAddress, Email email, Password password) {
        Optional<AuthenticationBlock> authenticationBlock = authenticationBlockRepository.findBy(ipAddress);
        if (authenticationBlock.isPresent() && authenticationBlock.get().isStillActive()) {
            throw new IllegalArgumentException("The authentication block is still active for machines from your IP address. Please, try again later: " + authenticationBlock.get().getExpiryDate());
        }
        User user = userRepository.findBy(email);
        if (user == null) {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
        if (user.password().enteredRight(password)) {
            failedAuthenticationRepository.removeAllFor(user.email());
            authenticationBlockRepository.removeAllFor(user.email());
            var authorizationData = authorizationDataRepository.create(
                    new AuthorizationData(
                            user.email(),
                            new RefreshToken(Token.random()),
                            new AuthorizationToken(Token.random()),
                            new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                            new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
                    )
            );
            return new AuthorizedUserAggregate(user.email(), authorizationData.getRefreshToken(), authorizationData.getAuthorizationToken());
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(user.email());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(user.email());
            var newAuthenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(ipAddress, Calendar.getInstance()));
            throw new IllegalArgumentException("Too many authentication failures! Try again later: " + newAuthenticationBlock.getExpiryDate());
        }
        else {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
    }

    public AuthorizationData refreshToken(Email email, RefreshToken refreshToken) {
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
