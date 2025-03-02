package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.UserCredentials;
import com.jrobertgardzinski.security.domain.entity.UserDetails;
import com.jrobertgardzinski.security.domain.event.authentication.*;
import com.jrobertgardzinski.security.domain.repository.*;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;

import java.util.Calendar;

public class SecurityService {
    private final UserDetailsRepository userDetailsRepository;
    private final UserCredentialsRepository userCredentialsRepository;
    private final TokenRepository tokenRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    private final int AUTHENTICATION_FAILURES_LIMIT = 3;

    public SecurityService(UserDetailsRepository userDetailsRepository, UserCredentialsRepository userCredentialsRepository, TokenRepository tokenRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.userDetailsRepository = userDetailsRepository;
        this.userCredentialsRepository = userCredentialsRepository;
        this.tokenRepository = tokenRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
    }

    public RegistrationEvent register(Email email, Password password) {
        if (userDetailsRepository.doesExist(email)) {
            return new UserAlreadyExistsEvent();
        }

        UserDetails userDetails = userDetailsRepository.create(new UserDetails(email));
        UserCredentials userCredentials = userCredentialsRepository.create(new UserCredentials(email, password));

        return new RegistrationPassedEvent(userDetails);

    }

    public AuthenticationEvent authenticate(Email email, Password password) {
        UserCredentials userCredentials = userCredentialsRepository.findBy(email);
        if (userCredentials == null) {
            return new UserNotFoundEvent();
        }
        UserDetails userDetails = userDetailsRepository.findBy(email);
        if (userCredentials.enteredRight(password)) {
            failedAuthenticationRepository.removeAllFor(userDetails.email());
            authenticationBlockRepository.removeAllFor(userDetails.email());
            var token = tokenRepository.createAuthorizationTokenFor(userDetails.email());
            return new AuthenticationPassedEvent(
                    new AuthorizedUserAggregate(userDetails));
        }
        var failuresCount = failedAuthenticationRepository.countFailuresBy(userDetails.email());
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(userDetails.email());
            var authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlockDetails(userDetails.email(), Calendar.getInstance()));
            return new AuthenticationFailuresLimitReachedEvent(authenticationBlock.details());
        }
        else {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(userDetails.email(), Calendar.getInstance())
            );
            return new AuthenticationFailedEvent();
        }
    }
}
