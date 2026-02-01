package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.security.application.usecase.register.RegisterResult;
import com.jrobertgardzinski.security.application.usecase.register.RegisterUseCase;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationFailedEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static com.jrobertgardzinski.security.application.TestData.VALID_PASSWORD;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RegisterRules {

    private final RegisterUseCase registerUseCase;
    private final UserRepository userRepository;

    private String rawEmail;
    private String rawPassword;
    private RegisterResult result;

    public RegisterRules(StubUserRepository stubUserRepository, StubHashAlgorithm stubHashAlgorithm) {
        this.registerUseCase = new RegisterUseCase(stubUserRepository, stubHashAlgorithm);
        this.userRepository = stubUserRepository;
    }

    // rule 1

    @When("I pass an email {string} and a password {string}")
    public void passCredentials(String email, String password) {
        this.rawEmail = email;
        this.rawPassword = password;
    }

    @When("I pass an email {string} and any other required valid parameters")
    public void passEmailWithValidDefaults(String email) {
        this.rawEmail = email;
        this.rawPassword = VALID_PASSWORD;
    }

    @When("I try to register")
    public void tryRegister() {
        result = registerUseCase.execute(rawEmail, rawPassword);
    }

    @Then("registration passes")
    public void registrationPasses() {
        assertInstanceOf(RegisterResult.Valid.class, result);
        RegisterResult.Valid valid = (RegisterResult.Valid) result;
        RegistrationPassedEvent event = (RegistrationPassedEvent) valid.event();
        assertTrue(userRepository.existsBy(event.email()));
    }

    // rule 2

    @Given("a user with an email {string} has already been registered")
    public void userAlreadyRegistered(String email) {
        registerUseCase.execute(email, VALID_PASSWORD);
    }

    @Then("registration fails")
    public void registrationFails() {
        assertInstanceOf(RegisterResult.Valid.class, result);
        RegisterResult.Valid valid = (RegisterResult.Valid) result;
        assertInstanceOf(RegistrationFailedEvent.class, valid.event());
    }
}
