package com.jrobertgardzinski.security.system.feature.bruteforce;

import com.jrobertgardzinski.security.system.feature.BruteForceGuard;
import com.jrobertgardzinski.security.system.stub.StubAuthenticationBlockRepository;
import com.jrobertgardzinski.security.system.stub.StubFailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Blocked;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.BruteForceProtectionEvent;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Passed;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class BruteForceGuardRules {

    private final BruteForceGuard bruteForceGuard;
    private final StubFailedAuthenticationRepository failedAuthenticationRepository;
    private final StubAuthenticationBlockRepository authenticationBlockRepository;

    private IpAddress ipAddress;
    private BruteForceProtectionEvent result;

    public BruteForceGuardRules(StubFailedAuthenticationRepository failedAuthenticationRepository,
                                StubAuthenticationBlockRepository authenticationBlockRepository) {
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
        this.bruteForceGuard = new BruteForceGuard(failedAuthenticationRepository, authenticationBlockRepository);
    }

    // background

    @Given("the system receives an authentication request from IP {string}")
    public void givenSystemReceivesRequestFromIp(String ip) {
        ipAddress = new IpAddress(ip);
    }

    // given

    @Given("no blockade is set for the IP")
    public void givenNoBlockade() {
        // default state - no action needed
    }

    @Given("failures count for the IP equals to {int}")
    public void givenFailuresCount(int count) {
        for (int i = 0; i < count; i++) {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(ipAddress, LocalDateTime.now()));
        }
    }

    @Given("{int} failures recorded {int} minutes ago for the IP")
    public void givenOldFailures(int count, int minutesAgo) {
        LocalDateTime time = LocalDateTime.now().minusMinutes(minutesAgo);
        for (int i = 0; i < count; i++) {
            failedAuthenticationRepository.create(
                    new FailedAuthenticationDetails(ipAddress, time));
        }
    }

    @Given("an active blockade exists for the IP")
    public void givenActiveBlockade() {
        authenticationBlockRepository.create(
                new AuthenticationBlock(ipAddress, LocalDateTime.now().plusMinutes(10)));
    }

    // when

    @When("the brute force guard checks the IP")
    public void whenGuardChecks() {
        result = bruteForceGuard.apply(ipAddress);
    }

    // then

    @Then("the guard lets the authentication through")
    public void thenPassed() {
        assertInstanceOf(Passed.class, result);
    }

    @Then("the guard blocks the authentication")
    public void thenBlocked() {
        assertInstanceOf(Blocked.class, result);
    }
}
