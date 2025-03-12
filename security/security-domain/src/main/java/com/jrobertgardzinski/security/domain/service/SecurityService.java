package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.UserLombok;
import com.jrobertgardzinski.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.TokenRepository;
import com.jrobertgardzinski.security.domain.repository.UserLombokRepository;
import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockDetails;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.Password;

import java.util.Calendar;

public class SecurityService {
    private final UserLombokRepository userLombokRepository;
    private final TokenRepository tokenRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    public SecurityService(UserLombokRepository userLombokRepository, TokenRepository tokenRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.userLombokRepository = userLombokRepository;
        this.tokenRepository = tokenRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
    }

    public RegistrationEvent register(Email email, Password password) {
        if (userLombokRepository.doesExist(email)) {
            return new UserAlreadyExistsEvent();
        }

        UserLombok userLombok = userLombokRepository.create(new UserLombok(email, password));

        return new RegistrationPassedEvent(userLombok);

    }

    public AuthenticationEvent authenticate(Email email, Password password) {
        UserLombok userLombok = userLombokRepository.findBy(email);
        if (userLombok == null) {
            return new UserNotFoundEvent();
        }
        if (userLombok.enteredRight(password)) {
            failedAuthenticationRepository.removeAllFor(userLombok.getEmail());
            authenticationBlockRepository.removeAllFor(userLombok.getEmail());
            var token = tokenRepository.createAuthorizationTokenFor(userLombok.getEmail());
            return new AuthenticationPassedEvent(
                    new AuthorizedUserAggregate(userLombok.getEmail(), token.refreshToken(), token.authorizationToken()));
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(userLombok.getEmail());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(userLombok.getEmail());
            var authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlockDetails(userLombok.getEmail(), Calendar.getInstance()));
            return new AuthenticationFailuresLimitReachedEvent(authenticationBlock.details());
        }
        else {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(userLombok.getEmail(), Calendar.getInstance())
            );
            return new AuthenticationFailedEvent();
        }
    }
}
