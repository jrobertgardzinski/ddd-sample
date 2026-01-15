package com.jrobertgardzinski.security.application.service;

import com.jrobertgardzinski.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.application.event.AuthenticationBlocked;
import com.jrobertgardzinski.security.application.event.AuthenticationFailed;
import com.jrobertgardzinski.security.application.event.AuthenticationPassed;
import com.jrobertgardzinski.security.application.event.AuthenticationResult;
import com.jrobertgardzinski.security.application.feature.*;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.UserNotFoundEvent;
import com.jrobertgardzinski.security.domain.event.authentication.WrongPasswordEvent;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Blocked;
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

    public AuthenticationResult authenticate(AuthenticationRequest authenticationRequest) {
        BruteForceGuard bruteForceGuard = new BruteForceGuard(failedAuthenticationRepository, authenticationBlockRepository);

        IpAddress ipAddress = authenticationRequest.ipAddress();
        switch (bruteForceGuard.apply(ipAddress)) {
            case Blocked b -> {
                return new AuthenticationBlocked(b.authenticationBlock());
            }
            default -> {
                Credentials credentials = new Credentials(
                        authenticationRequest.email(),
                        authenticationRequest.plainTextPassword()
                );
                return afterBruteForceProtection(credentials, ipAddress);
            }
        }
    }

    private AuthenticationResult afterBruteForceProtection(Credentials credentials, IpAddress ipAddress) {
        Authenticate authenticate = new Authenticate(userRepository, hashAlgorithmPort);
        GenerateSession generateSession = new GenerateSession(authorizationDataRepository);
        UpdateBruteForceRecords updateBruteForceRecords = new UpdateBruteForceRecords(failedAuthenticationRepository);
        CleanBruteForceRecords cleanBruteForceRecords = new CleanBruteForceRecords(failedAuthenticationRepository, authenticationBlockRepository);

        return switch (authenticate.apply(credentials)) {

            case AuthenticationPassedEvent p -> {
                var session = generateSession.apply(p);
                cleanBruteForceRecords.accept(ipAddress);
                yield new AuthenticationPassed(session);
            }

            case UserNotFoundEvent e -> {
                // todo store it somewhere
                yield anAuthenticationFailure(ipAddress);
            }

            case WrongPasswordEvent e -> {
                yield anAuthenticationFailure(ipAddress);
            }
        };
    }

    private AuthenticationResult anAuthenticationFailure(IpAddress ipAddress) {
        updateBruteForceRecords.accept(ipAddress);
        return new AuthenticationFailed();
    }
}
