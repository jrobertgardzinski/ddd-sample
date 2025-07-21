package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.entity.UserEntity;
import com.jrobertgardzinski.security.domain.vo.User;
import com.jrobertgardzinski.security.domain.event.authentication.*;
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

    public AuthenticationEvent authenticate(Email email, Password password) {
        User user = userRepository.findBy(email);
        if (user == null) {
            return new UserNotFoundEvent();
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
            return new AuthenticationPassedEvent(
                    new AuthorizedUserAggregate(user.email(), authorizationData.getRefreshToken(), authorizationData.getAuthorizationToken()));
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(user.email());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(user.email());
            var authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(user.email(), Calendar.getInstance()));
            return new AuthenticationFailuresLimitReachedEvent(authenticationBlock);
        }
        else {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(user.email(), Calendar.getInstance())
            );
            return new AuthenticationFailedEvent();
        }
    }

    public RefreshTokenEvent refreshToken(Email email, RefreshToken refreshToken) {
        RefreshTokenExpiration refreshTokenExpiration = authorizationDataRepository.findRefreshTokenExpirationBy(email, refreshToken);
        if (refreshTokenExpiration == null) {
            return new NoAuthorizationDataFoundEvent(email);
        }
        authorizationDataRepository.deleteBy(email);
        if (refreshTokenExpiration.hasExpired()) {
            return new RefreshTokenExpiredEvent(email);
        }
        AuthorizationData authorizationData = authorizationDataRepository.create(AuthorizationData.createFor(email));
        return new RefreshTokenPassedEvent(authorizationData);
    }
}
