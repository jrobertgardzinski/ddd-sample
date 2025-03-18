package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.event.refresh.NoAuthorizationDataFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenExpiredEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
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

    public RegistrationEvent register(Email email, Password password) {
        if (userRepository.doesExist(email)) {
            return new UserAlreadyExistsEvent();
        }

        User user = userRepository.create(new User(email, password));

        return new RegistrationPassedEvent(user);

    }

    public AuthenticationEvent authenticate(Email email, Password password) {
        User user = userRepository.findBy(email);
        if (user == null) {
            return new UserNotFoundEvent();
        }
        if (user.enteredRight(password)) {
            failedAuthenticationRepository.removeAllFor(user.getEmail());
            authenticationBlockRepository.removeAllFor(user.getEmail());
            var authorizationData = authorizationDataRepository.create(
                    new AuthorizationData(
                            user.getEmail(),
                            new RefreshToken(Token.random()),
                            new AuthorizationToken(Token.random()),
                            new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                            new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
                    )
            );
            return new AuthenticationPassedEvent(
                    new AuthorizedUserAggregate(user.getEmail(), authorizationData.getRefreshToken(), authorizationData.getAuthorizationToken()));
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(user.getEmail());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(user.getEmail());
            var authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(user.getEmail(), Calendar.getInstance()));
            return new AuthenticationFailuresLimitReachedEvent(authenticationBlock);
        }
        else {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(user.getEmail(), Calendar.getInstance())
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
