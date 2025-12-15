package com.jrobertgardzinski.security.domain.vo.security.service;

import com.jrobertgardzinski.security.domain.vo.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.feature.Authentication;
import com.jrobertgardzinski.security.domain.vo.security.domain.feature.Registration;
import com.jrobertgardzinski.security.domain.vo.security.domain.feature.SessionRefresh;
import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
import com.jrobertgardzinski.security.domain.vo.SessionRefreshRequest;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import com.jrobertgardzinski.security.domain.vo.security.repository.*;
import io.micronaut.core.annotation.Introspected;
import jakarta.inject.Singleton;

@Introspected(
        classNames = {
                "com.jrobertgardzinski.security.domain.vo.Email",
                "com.jrobertgardzinski.security.domain.vo.Password"
        }
)
@Singleton
public class SecurityService {
    private final Registration registration;
    private final Authentication authentication;
    private final SessionRefresh sessionRefresh;

    public SecurityService(UserJpaRepository userJpaRepository,
                           AuthorizationDataJpaRepository authorizationDataJpaRepository,
                           FailedAuthenticationJpaRepository failedAuthenticationJpaRepository,
                           AuthenticationBlockJpaRepository authorizationDataRepositoryAdapter
                                  ) {
        this.registration = new Registration(
                new UserRepositoryAdapter(userJpaRepository),
                new HashAlgorithmAdapter());
        this.authentication = new Authentication(
                new UserRepositoryAdapter(userJpaRepository),
                new AuthorizationDataRepositoryAdapter(authorizationDataJpaRepository),
                new FailedAuthenticationRepositoryAdapter(failedAuthenticationJpaRepository),
                new AuthenticationBlockRepositoryAdapter(authorizationDataRepositoryAdapter),
                new HashAlgorithmAdapter());
        this.sessionRefresh = new SessionRefresh(
                new AuthorizationDataRepositoryAdapter(authorizationDataJpaRepository));
    }

    public RegistrationEvent register(UserRegistration userRegistration) {
        return registration.apply(userRegistration);
    }

    public AuthenticationEvent authenticate(AuthenticationRequest authenticationRequest) {
        return authentication.apply(authenticationRequest);
    }

    public RefreshTokenEvent refreshToken(SessionRefreshRequest sessionRefreshRequest) {
        return sessionRefresh.apply(sessionRefreshRequest);
    }
}
