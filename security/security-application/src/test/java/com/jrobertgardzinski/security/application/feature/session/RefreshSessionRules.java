package com.jrobertgardzinski.security.application.feature.session;

import com.jrobertgardzinski.security.application.feature.RefreshSession;
import com.jrobertgardzinski.security.application.feature.session.context.dependency.StubAuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.event.refresh.NoRefreshTokenFoundEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenExpiredEvent;
import com.jrobertgardzinski.security.domain.event.refresh.RefreshTokenPassedEvent;
import com.jrobertgardzinski.security.domain.vo.*;
import com.jrobertgardzinski.system.SystemTime;
import io.cucumber.java.en.Given;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.*;

public class RefreshSessionRules {

    private final RefreshSession refreshSession;
    private final StubAuthorizationDataRepository authorizationDataRepository;

    private Email email;
    private RefreshToken refreshToken;
    private RefreshTokenEvent result;

    public RefreshSessionRules(StubAuthorizationDataRepository authorizationDataRepository) {
        this.authorizationDataRepository = authorizationDataRepository;
        this.refreshSession = new RefreshSession(authorizationDataRepository);
    }

    // background

    @Given("a user with email {string}")
    public void givenUserWithEmail(String emailValue) {
        email = new Email(emailValue);
    }

    // given

    @Given("the user has an active session")
    public void givenActiveSession() {
        SessionTokens sessionTokens = SessionTokens.createFor(email);
        authorizationDataRepository.create(sessionTokens);
        refreshToken = sessionTokens.refreshToken();
    }

    @Given("the user has an expired session")
    public void givenExpiredSession() {
        Clock pastClock = Clock.fixed(
                LocalDateTime.now().minusHours(49).atZone(ZoneId.systemDefault()).toInstant(),
                ZoneId.systemDefault());
        SystemTime.setFixedTime(pastClock);
        SessionTokens session = SessionTokens.createFor(email);
        SystemTime.reset();
        authorizationDataRepository.create(session);
        refreshToken = session.refreshToken();
    }

    @Given("the user has no session")
    public void givenNoSession() {
        refreshToken = new RefreshToken(Token.random());
    }

    // when

    @When("the user refreshes the session")
    public void whenRefreshSession() {
        SessionRefreshRequest request = new SessionRefreshRequest(email, refreshToken);
        result = refreshSession.apply(request);
    }

    // then

    @Then("the user receives new session tokens")
    public void thenReceivesNewTokens() {
        assertInstanceOf(RefreshTokenPassedEvent.class, result);
        RefreshTokenPassedEvent passed = (RefreshTokenPassedEvent) result;
        assertNotNull(passed.sessionTokens());
    }

    @Then("the refresh fails due to RefreshTokenExpiredEvent")
    public void thenExpiredEvent() {
        assertInstanceOf(RefreshTokenExpiredEvent.class, result);
    }

    @Then("the refresh fails due to NoRefreshTokenFoundEvent")
    public void thenNotFoundEvent() {
        assertInstanceOf(NoRefreshTokenFoundEvent.class, result);
    }
}
