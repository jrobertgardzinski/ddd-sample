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
import com.jrobertgardzinski.security.domain.service.procedure.AuthenticationProcedure;
import com.jrobertgardzinski.security.domain.vo.*;

import java.time.LocalDateTime;
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
        if (userRepository.existsBy(email)) {
            return new UserAlreadyExistsEvent();
        }
        try {
            return new RegistrationPassedEvent(userRepository.save(user));
        } catch (Exception e) {
            return new PossibleRaceCondition();
        }
    }

    public AuthorizedUserAggregate authenticate(AuthenticationRequest authenticationRequest) {
        AuthenticationProcedure procedure = new AuthenticationProcedure(
                userRepository,
                authorizationDataRepository,
                failedAuthenticationRepository,
                authenticationBlockRepository,
                authenticationRequest
        );
        procedure.checkIfThereIsAnyActiveBlockadeForIpAddress();
        procedure.checkIfTheUserExists();
        if (procedure.hasTheUserEnteredCorrectPassword()) {
            return procedure.handleAuthentication();
        }
        else {
            throw procedure.exception();
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
