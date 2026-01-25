package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.application.feature.register.context.RegisterUseCase;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationFailedEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.*;

public class RegisterRules {

    private final RegisterUseCase registerUseCase;
    private final UserRepository userRepository;

    private UserRegistration input;
    private RegistrationEvent output;

    public RegisterRules(RegisterUseCase registerUseCase, UserRepository userRepository) {
        this.registerUseCase = registerUseCase;
        this.userRepository = userRepository;
    }

    // rule 1

    @When("I pass an email {string} and a password {string}")
    public void g1(String email, String password) {
        input = new UserRegistration(
            new Email(email),
            new PlainTextPassword(password)
        );
    }

    @When("I try to register")
    public void w1() {
        output = registerUseCase.apply(input);
    }

    @Then("registration passes")
    public void t1() {
        RegistrationPassedEvent result = (RegistrationPassedEvent) output;
        assertTrue(userRepository.existsBy(result.email()));
    }

    // rule 2

    @Given("a user with an email {string} has already been registered")
    public void g2(String string) throws Exception {
        input = new UserRegistration(
                new Email(string),
                new PlainTextPassword("StrongPassword1!")
        );
        registerUseCase.apply(input);
    }

    @Then("registration fails")
    public void t2() {
        assertInstanceOf(RegistrationFailedEvent.class, output);
    }

    // rule 3

    @Then("I get an error for password")
    public void t3() {
        assertInstanceOf(RegistrationFailedEvent.class, output);
    }
}
