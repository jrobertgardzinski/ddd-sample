package com.jrobertgardzinski.security.system.feature.session;

import com.jrobertgardzinski.security.system.feature.GenerateSession;
import com.jrobertgardzinski.security.system.stub.StubAuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.vo.Email;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.*;

public class GenerateSessionRules {

    private final GenerateSession generateSession;
    private final StubAuthorizationDataRepository authorizationDataRepository;

    private Email email;
    private SessionTokens result;

    public GenerateSessionRules(StubAuthorizationDataRepository authorizationDataRepository) {
        this.authorizationDataRepository = authorizationDataRepository;
        this.generateSession = new GenerateSession(authorizationDataRepository);
    }

    // background

    @Given("the system has authenticated a user with email {string}")
    public void givenSystemAuthenticated(String emailValue) {
        email = new Email(emailValue);
    }

    // when

    @When("the system generates a session")
    public void whenGenerateSession() {
        AuthenticationPassedEvent event = new AuthenticationPassedEvent(email);
        result = generateSession.apply(event);
    }

    // then

    @Then("the session contains a refresh token")
    public void thenHasRefreshToken() {
        assertNotNull(result.refreshToken());
        assertNotNull(result.refreshToken().value());
    }

    @Then("the session contains an access token")
    public void thenHasAccessToken() {
        assertNotNull(result.accessToken());
        assertNotNull(result.accessToken().value());
    }

    @Then("the session is stored in the repository")
    public void thenStoredInRepository() {
        assertTrue(authorizationDataRepository.findBy(email).isPresent());
    }
}
