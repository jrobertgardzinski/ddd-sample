package com.jrobertgardzinski.security.service;

import com.jrobertgardzinski.security.aggregate.AuthorizedUserAggregateRootEntity;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.service.PasswordHashAlgorithm;
import com.jrobertgardzinski.security.domain.service.SecurityService;
import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
import com.jrobertgardzinski.security.domain.vo.SessionRefreshRequest;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import com.jrobertgardzinski.security.entity.AuthorizationDataEntity;
import com.jrobertgardzinski.security.repository.*;
import io.micronaut.core.annotation.Introspected;
import jakarta.inject.Singleton;

@Introspected(
        classNames = {
                "com.jrobertgardzinski.security.domain.vo.Email",
                "com.jrobertgardzinski.security.domain.vo.Password"
        }
)
@Singleton
public class SecurityServiceAdapter {
    private final SecurityService securityService;

    public SecurityServiceAdapter(UserJpaRepository userJpaRepository,
                                  AuthorizationDataJpaRepository authorizationDataJpaRepository,
                                  FailedAuthenticationJpaRepository failedAuthenticationJpaRepository,
                                  AuthenticationBlockJpaRepository authorizationDataRepositoryAdapter,
                                  PasswordSaltRepositoryJpa passwordSaltRepositoryJpa
                                  ) {
        this.securityService = new SecurityService(
                new UserRepositoryAdapter(userJpaRepository),
                new AuthorizationDataRepositoryAdapter(authorizationDataJpaRepository),
                new FailedAuthenticationRepositoryAdapter(failedAuthenticationJpaRepository),
                new AuthenticationBlockRepositoryAdapter(authorizationDataRepositoryAdapter),
                new PasswordSaltRepositoryAdapter(passwordSaltRepositoryJpa),
                new PasswordHashAlgorithm(new HashAlgorithmAdapter())
        );
    }

    public RegistrationEvent register(UserRegistration userRegistration) {
        return securityService.register(userRegistration);
    }

    public AuthorizedUserAggregateRootEntity authenticate(AuthenticationRequest authenticationRequest) {
        return AuthorizedUserAggregateRootEntity.from(securityService.authenticate(authenticationRequest));
    }

    public AuthorizationDataEntity refreshToken(SessionRefreshRequest sessionRefreshRequest) {
        return AuthorizationDataEntity.fromDomain(securityService.refreshSession(sessionRefreshRequest));
    }
}
