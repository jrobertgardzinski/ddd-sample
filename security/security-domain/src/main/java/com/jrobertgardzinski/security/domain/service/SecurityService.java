package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.TokenRepository;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;

import java.util.Calendar;

public class SecurityService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    private final int AUTHENTICATION_FAILURES_LIMIT = 3;

    public SecurityService(UserRepository userRepository, TokenRepository tokenRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
    }

    public RegistrationEvent register(UserDetails userDetails) {
        var user = userRepository.createUser(userDetails);
        return user.isPresent() ?
            new RegistrationPassedEvent(user.get()) :
            new UserAlreadyExistsEvent();
    }

    public AuthenticationEvent authenticate(Email email, Password password) {
        var foundUser = userRepository.findUserByEmail(email);
        if (foundUser.isEmpty()) {
            return new UserNotFoundEvent();
        }
        var user = foundUser.get();
        if (user.enteredRight(password)) {
            failedAuthenticationRepository.removeAllFor(user.id());
            authenticationBlockRepository.removeAllFor(user.id());
            var token = tokenRepository.createAuthorizationToken(user.id());
            return new AuthenticationPassedEvent(
                    new AuthorizedUserAggregate(user.details(), token.details()));
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(user.id());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(user.id());
            var authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlockDetails(user.id(), Calendar.getInstance()));
            return new AuthenticationFailuresLimitReachedEvent(authenticationBlock.details());
        }
        else {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(foundUser.get().id(), Calendar.getInstance())
            );
            return new AuthenticationFailedEvent();
        }
    }
}
