package com.jrobertgardzinski.security.system.feature.register;

import com.jrobertgardzinski.security.system.feature.Register;
import com.jrobertgardzinski.security.system.stub.StubHashAlgorithm;
import com.jrobertgardzinski.security.system.stub.StubUserRepository;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationEvent;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.*;

public class RegisterRules {

    private final Register register;
    private RegistrationEvent result;

    public RegisterRules(StubUserRepository userRepository, StubHashAlgorithm hashAlgorithm) {
        this.register = new Register(userRepository, hashAlgorithm);
    }

    // given

    @Given("the system already has an account with email {string}")
    public void givenAccountExists(String email) {
        UserRegistration registration = new UserRegistration(
                new Email(email),
                new PlaintextPassword("StrongPassword1#")
        );
        register.apply(registration);
    }

    // when

    @When("the system receives a registration with email {string} and password {string}")
    public void whenSystemReceivesRegistration(String email, String password) {
        UserRegistration registration = new UserRegistration(
                new Email(email),
                new PlaintextPassword(password)
        );
        result = register.apply(registration);
    }

    // then

    @Then("the registration passes")
    public void thenRegistrationPasses() {
        assertInstanceOf(RegistrationPassedEvent.class, result);
    }

    @Then("the registration fails")
    public void thenRegistrationFails() {
        assertInstanceOf(UserAlreadyExistsEvent.class, result);
    }
}
