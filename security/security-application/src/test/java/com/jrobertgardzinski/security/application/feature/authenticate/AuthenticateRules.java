package com.jrobertgardzinski.security.application.feature.authenticate;

import com.jrobertgardzinski.security.application.feature.Authenticate;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationFailedEvent;
import com.jrobertgardzinski.security.domain.event.authentication.AuthenticationPassedEvent;
import com.jrobertgardzinski.security.domain.vo.*;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.*;

public class AuthenticateRules {

    private final Authenticate authenticate;
    private final StubUserRepository userRepository;
    private final StubHashAlgorithm hashAlgorithm;

    private String storedEmail;
    private AuthenticationEvent result;

    public AuthenticateRules(StubUserRepository userRepository, StubHashAlgorithm hashAlgorithm) {
        this.userRepository = userRepository;
        this.hashAlgorithm = hashAlgorithm;
        this.authenticate = new Authenticate(userRepository, hashAlgorithm);
    }

    // background

    @Given("a user with an email {string}")
    public void givenUserWithEmail(String email) {
        storedEmail = email;
    }

    @Given("a password {string} is registered")
    public void andPasswordIsRegistered(String password) {
        Email email = new Email(storedEmail);
        PlaintextPassword plaintextPassword = new PlaintextPassword(password);
        Salt salt = Salt.generate();
        PasswordHash passwordHash = hashAlgorithm.hash(plaintextPassword, salt);
        try {
            userRepository.save(new User(email, passwordHash));
        } catch (Exception e) {
            fail("Failed to save user in background setup");
        }
    }

    // when

    @When("the user passes the {string} email")
    public void whenUserPassesEmail(String email) {
        storedEmail = email;
    }

    @When("the {string} password")
    public void andPassword(String password) {
        Credentials credentials = new Credentials(
                new Email(storedEmail),
                new PlaintextPassword(password)
        );
        result = authenticate.apply(credentials);
    }

    // then

    @Then("the authentication passes")
    public void thenAuthenticationPasses() {
        assertInstanceOf(AuthenticationPassedEvent.class, result);
    }

    @Then("authentication fails due to AuthenticationFailedEvent")
    public void thenAuthenticationFailsDueToUserNotFound() {
        assertInstanceOf(AuthenticationFailedEvent.class, result);
    }
}
