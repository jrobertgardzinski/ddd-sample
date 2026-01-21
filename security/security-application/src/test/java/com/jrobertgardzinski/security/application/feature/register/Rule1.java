package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class Rule1 {

    private final RegisterTestContext context;

    public Rule1(RegisterTestContext context) {
        this.context = context;
    }

    @When("I pass an email {string}")
    public void w11(String email) {
        context.setEmail(email);
    }

    @When("I pass a password {string}")
    public void w12(String password) {
        context.setPassword(password);
    }

    @Then("registration passes")
    public void t11() {
        context.getRegister().apply(
                new UserRegistration(
                        new Email(context.getEmail()),
                        new PlainTextPassword(context.getPassword())
                ));
    }
}
