package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.TokenRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockDetails;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.Password;

import java.util.Calendar;

public class SecurityService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    public SecurityService(UserRepository userRepository, TokenRepository tokenRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
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
            var token = tokenRepository.createAuthorizationTokenFor(user.getEmail());
            return new AuthenticationPassedEvent(
                    new AuthorizedUserAggregate(user.getEmail(), token.refreshToken(), token.authorizationToken()));
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(user.getEmail());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(user.getEmail());
            var authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlockDetails(user.getEmail(), Calendar.getInstance()));
            return new AuthenticationFailuresLimitReachedEvent(authenticationBlock.details());
        }
        else {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(user.getEmail(), Calendar.getInstance())
            );
            return new AuthenticationFailedEvent();
        }
    }
}
