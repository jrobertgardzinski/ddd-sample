package com.jrobertgardzinski.security.application.feature.authenticate;

import com.jrobertgardzinski.security.application.event.AuthenticationBlocked;
import com.jrobertgardzinski.security.application.event.AuthenticationFailed;
import com.jrobertgardzinski.security.application.event.AuthenticationPassed;
import com.jrobertgardzinski.security.application.event.AuthenticationResult;
import com.jrobertgardzinski.security.application.feature.BruteForceGuard;
import com.jrobertgardzinski.security.application.feature.GenerateSession;
import com.jrobertgardzinski.security.application.feature.VerifyCredentials;
import com.jrobertgardzinski.security.application.feature.bruteforce.context.dependency.StubAuthenticationBlockRepository;
import com.jrobertgardzinski.security.application.feature.bruteforce.context.dependency.StubFailedAuthenticationRepository;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.security.application.feature.session.context.dependency.StubAuthorizationDataRepository;
import com.jrobertgardzinski.security.application.usecase.AuthenticateUseCase;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.*;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class AuthenticateRules {

    private final AuthenticateUseCase authenticateUseCase;
    private final StubUserRepository userRepository;
    private final StubHashAlgorithm hashAlgorithm;
    private final StubFailedAuthenticationRepository failedAuthenticationRepository;
    private final StubAuthenticationBlockRepository authenticationBlockRepository;

    private IpAddress ipAddress;
    private AuthenticationResult result;

    public AuthenticateRules(StubUserRepository userRepository,
                             StubHashAlgorithm hashAlgorithm,
                             StubFailedAuthenticationRepository failedAuthenticationRepository,
                             StubAuthenticationBlockRepository authenticationBlockRepository,
                             StubAuthorizationDataRepository authorizationDataRepository) {
        this.userRepository = userRepository;
        this.hashAlgorithm = hashAlgorithm;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
        VerifyCredentials verifyCredentials = new VerifyCredentials(userRepository, hashAlgorithm);
        BruteForceGuard bruteForceGuard = new BruteForceGuard(failedAuthenticationRepository, authenticationBlockRepository);
        GenerateSession generateSession = new GenerateSession(authorizationDataRepository);
        this.authenticateUseCase = new AuthenticateUseCase(verifyCredentials, bruteForceGuard, generateSession);
    }

    // background

    @Given("a registered user with email {string} and password {string}")
    public void givenRegisteredUser(String email, String password) {
        Email e = new Email(email);
        PlaintextPassword p = new PlaintextPassword(password);
        Salt salt = Salt.generate();
        PasswordHash passwordHash = hashAlgorithm.hash(p, salt);
        try {
            userRepository.save(new User(e, passwordHash));
        } catch (Exception ex) {
            fail("Failed to save user in background setup");
        }
    }

    @Given("the authentication attempt comes from IP {string}")
    public void givenAuthenticationAttemptFromIp(String ip) {
        ipAddress = new IpAddress(ip);
    }

    // given

    @Given("the IP has no blockade")
    public void givenNoBlockade() {
        // default state - no action needed
    }

    @Given("the IP has {int} recorded failures")
    public void givenRecordedFailures(int count) {
        for (int i = 0; i < count; i++) {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(ipAddress, LocalDateTime.now()));
        }
    }

    @Given("the IP has {int} failures recorded {int} minutes ago")
    public void givenOldFailures(int count, int minutesAgo) {
        LocalDateTime time = LocalDateTime.now().minusMinutes(minutesAgo);
        for (int i = 0; i < count; i++) {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(ipAddress, time));
        }
    }

    @Given("the IP has an active blockade")
    public void givenActiveBlockade() {
        authenticationBlockRepository.create(
                new AuthenticationBlock(ipAddress, LocalDateTime.now().plusMinutes(10)));
    }

    // when

    @When("the user authenticates with email {string} and password {string}")
    public void whenUserAuthenticates(String email, String password) {
        AuthenticationRequest request = new AuthenticationRequest(
                ipAddress,
                new Email(email),
                new PlaintextPassword(password)
        );
        result = authenticateUseCase.apply(request);
    }

    // then

    @Then("the authentication result is passed")
    public void thenAuthenticationPassed() {
        assertInstanceOf(AuthenticationPassed.class, result);
    }

    @Then("the authentication result is failed")
    public void thenAuthenticationFailed() {
        assertInstanceOf(AuthenticationFailed.class, result);
    }

    @Then("the authentication result is blocked")
    public void thenAuthenticationBlocked() {
        assertInstanceOf(AuthenticationBlocked.class, result);
    }
}
