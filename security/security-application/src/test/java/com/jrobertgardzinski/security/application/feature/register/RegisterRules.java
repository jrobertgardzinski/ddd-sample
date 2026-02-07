package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.register.context.dependency.StubUserRepository;
import com.jrobertgardzinski.security.application.usecase.RegisterResult;
import com.jrobertgardzinski.security.application.usecase.RegisterUseCase;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationFailedEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static com.jrobertgardzinski.security.application.TestData.VALID_PASSWORD;
import static org.junit.jupiter.api.Assertions.*;

public class RegisterRules {

    private final RegisterUseCase registerUseCase;
    private final UserRepository userRepository;

    private RegisterResult result;

    public RegisterRules(StubUserRepository stubUserRepository, StubHashAlgorithm stubHashAlgorithm) {
        this.registerUseCase = new RegisterUseCase(stubUserRepository, stubHashAlgorithm);
        this.userRepository = stubUserRepository;
    }

    public void when(String email, String password) {
        result = registerUseCase.execute(email, password);
    }

    // rule 0

    @Then("registration fails on validating input arguments")
    public void t0() {
        assertInstanceOf(RegisterResult.Invalid.class, result);
    }

    @Then("there are some email errors")
    public void t0emailSome() {
        RegisterResult.Invalid casted = (RegisterResult.Invalid) result;
        assertTrue(casted.exception().hasEmailErrors());
    }

    @Then("there are no email errors")
    public void t0emailNo() {
        RegisterResult.Invalid casted = (RegisterResult.Invalid) result;
        assertFalse(casted.exception().hasEmailErrors());
    }

    @Then("there are some password errors")
    public void t0passwordSome() {
        RegisterResult.Invalid casted = (RegisterResult.Invalid) result;
        assertTrue(casted.exception().hasPasswordErrors());
    }

    @Then("there are no password errors")
    public void t0passwordNo() {
        RegisterResult.Invalid casted = (RegisterResult.Invalid) result;
        assertFalse(casted.exception().hasPasswordErrors());
    }

    // rule 1

    @When("I register with an email {string} and a password {string}")
    public void w1(String email, String password) {
        when(email, password);
    }

    @Then("registration passes")
    public void t1() {
        assertInstanceOf(RegisterResult.Valid.class, result);
        RegisterResult.Valid valid = (RegisterResult.Valid) result;
        RegistrationPassedEvent event = (RegistrationPassedEvent) valid.event();
        assertTrue(userRepository.existsBy(event.email()));
    }

    // rule 2

    @Given("a user with an email {string} has already been registered")
    public void g2(String email) {
        registerUseCase.execute(email, VALID_PASSWORD);
    }

    @When("I register with an email {string} and any other required valid parameters")
    public void w2(String email) {
        when(email, VALID_PASSWORD);
    }

    @Then("registration fails")
    public void t2() {
        assertInstanceOf(RegisterResult.Valid.class, result);
        RegisterResult.Valid valid = (RegisterResult.Valid) result;
        assertInstanceOf(RegistrationFailedEvent.class, valid.event());
    }
}
