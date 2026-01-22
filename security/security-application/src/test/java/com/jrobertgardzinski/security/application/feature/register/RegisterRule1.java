package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.application.feature.register.context.RegisterUseCase;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.jupiter.api.Assertions;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RegisterRule1 {

    private final RegisterUseCase registerUseCase;
    private final UserRepository userRepository;

    private UserRegistration input;
    private RegistrationEvent output;

    public RegisterRule1(RegisterUseCase registerUseCase, UserRepository userRepository) {
        this.registerUseCase = registerUseCase;
        this.userRepository = userRepository;
    }

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
}
