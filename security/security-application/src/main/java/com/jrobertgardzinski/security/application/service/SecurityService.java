package com.jrobertgardzinski.security.application.service;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.application.feature.*;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.*;

public class SecurityService {
    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;
    private final HashAlgorithmPort hashAlgorithmPort;

    public SecurityService(UserRepository userRepository, AuthorizationDataRepository authorizationDataRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
        this.hashAlgorithmPort = hashAlgorithmPort;
    }

    public RegistrationEvent register(UserRegistration userRegistration) {
        Registration registration = new Registration(userRepository, hashAlgorithmPort);
        return registration.apply(userRegistration);
    }

    public RefreshTokenEvent refreshSession(SessionRefreshRequest sessionRefreshRequest) {
        SessionRefresh sessionRefresh = new SessionRefresh(authorizationDataRepository);
        return sessionRefresh.apply(sessionRefreshRequest);
    }

    public AuthenticationEvent authenticate(AuthenticationRequest authenticationRequest) {
        Authentication authentication = new Authentication(userRepository, hashAlgorithmPort);
        BruteForceProtection bruteForceProtection = new BruteForceProtection(failedAuthenticationRepository, authenticationBlockRepository);
        SessionGenerator sessionGenerator = new SessionGenerator(authorizationDataRepository);

        IpAddress ipAddress = authenticationRequest.ipAddress();
        Credentials credentials = new Credentials(authenticationRequest.email(), authenticationRequest.plainTextPassword());

        return bruteForceProtection.apply(ipAddress) // todo I don't know how to combine all three.
    }
}
