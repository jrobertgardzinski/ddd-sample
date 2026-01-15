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
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Passed;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.*;

public class SecurityService {
    private final Register register;
    private final RefreshSession refreshSession;
    private final BruteForceGuard bruteForceGuard;
    private final Authenticate authenticate;
    private final GenerateSession generateSession;
    private final UpdateBruteForceRecords updateBruteForceRecords;
    private final CleanBruteForceRecords cleanBruteForceRecords;

    public SecurityService(UserRepository userRepository, AuthorizationDataRepository authorizationDataRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository, HashAlgorithmPort hashAlgorithmPort) {
        this.register = new Register(userRepository, hashAlgorithmPort);
        this.refreshSession = new RefreshSession(authorizationDataRepository);
        this.bruteForceGuard = new BruteForceGuard(failedAuthenticationRepository, authenticationBlockRepository);
        this.authenticate = new Authenticate(userRepository, hashAlgorithmPort);
        this.generateSession = new GenerateSession(authorizationDataRepository);
        this.updateBruteForceRecords = new UpdateBruteForceRecords(failedAuthenticationRepository);
        this.cleanBruteForceRecords = new CleanBruteForceRecords(failedAuthenticationRepository, authenticationBlockRepository);
    }

    public RegistrationEvent register(UserRegistration userRegistration) {
        return register.apply(userRegistration);
    }

    public RefreshTokenEvent refreshSession(SessionRefreshRequest sessionRefreshRequest) {
        return refreshSession.apply(sessionRefreshRequest);
    }

    public AuthenticationResult authenticate(AuthenticationRequest authenticationRequest) {
        IpAddress ipAddress = authenticationRequest.ipAddress();
        switch (bruteForceGuard.apply(ipAddress)) {
            case Blocked b -> {
                return new AuthenticationBlocked(b.authenticationBlock());
            }
            case Passed p -> {
                Credentials credentials = new Credentials(
                        authenticationRequest.email(),
                        authenticationRequest.plainTextPassword()
                );
                return afterBruteForceProtection(credentials, ipAddress);
            }
        }
    }

    private AuthenticationResult afterBruteForceProtection(Credentials credentials, IpAddress ipAddress) {
        return switch (authenticate.apply(credentials)) {

            case AuthenticationPassedEvent p -> {
                var session = generateSession.apply(p);
                cleanBruteForceRecords.accept(ipAddress);
                yield new AuthenticationPassed(session);
            }

            case UserNotFoundEvent e -> {
                // todo in the future I might need that info
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
