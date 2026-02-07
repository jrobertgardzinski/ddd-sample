package com.jrobertgardzinski.security.application.usecase;

import com.jrobertgardzinski.security.application.event.AuthenticationBlocked;
import com.jrobertgardzinski.security.application.event.AuthenticationFailed;
import com.jrobertgardzinski.security.application.event.AuthenticationPassed;
import com.jrobertgardzinski.security.application.event.AuthenticationResult;
import com.jrobertgardzinski.security.application.feature.BruteForceGuard;
import com.jrobertgardzinski.security.application.feature.GenerateSession;
import com.jrobertgardzinski.security.application.feature.VerifyCredentials;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Blocked;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.BruteForceProtectionEvent;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Passed;
import com.jrobertgardzinski.security.domain.vo.*;

import java.util.function.Function;

public class AuthenticateUseCase implements Function<AuthenticationRequest, AuthenticationResult> {
    private final VerifyCredentials verifyCredentials;
    private final BruteForceGuard bruteForceGuard;
    private final GenerateSession generateSession;

    public AuthenticateUseCase(VerifyCredentials verifyCredentials, BruteForceGuard bruteForceGuard, GenerateSession generateSession) {
        this.verifyCredentials = verifyCredentials;
        this.bruteForceGuard = bruteForceGuard;
        this.generateSession = generateSession;
    }

    @Override
    public AuthenticationResult apply(AuthenticationRequest authenticationRequest) {
        IpAddress ip = authenticationRequest.ipAddress();
        BruteForceProtectionEvent bruteForceProtectionEvent = bruteForceGuard.apply(ip);
        switch (bruteForceProtectionEvent) {
            case Passed passed -> {
                Credentials credentials = new Credentials(
                        authenticationRequest.email(),
                        authenticationRequest.plaintextPassword()
                );
                AuthenticationEvent authenticationEvent = verifyCredentials.apply(credentials);
                switch (authenticationEvent) {
                    case AuthenticationPassedEvent authenticationPassedEvent -> {
                        SessionTokens sessionTokens = generateSession.apply(authenticationPassedEvent);
                        return new AuthenticationPassed(sessionTokens);
                    }
                    case AuthenticationFailedEvent authenticationFailedEvent -> {
                        return new AuthenticationFailed();
                    }
                }
            }
            case Blocked blocked -> {
                return new AuthenticationBlocked(blocked.authenticationBlock());
            }
        }
    }
}
