package com.jrobertgardzinski.security.application.feature.input;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.*;

public class PlainTextPasswordRules {

    private Exception exception;
    private PlainTextPassword password;

    // rule 0

    @When("I provide no password")
    public void w0() {
        try {
            password = new PlainTextPassword(null);
        } catch (Exception e) {
            exception = e;
        }
    }

    // rule 1

    @When("I create a password from {string}")
    public void w1(String value) {
        try {
            password = new PlainTextPassword(value);
        } catch (Exception e) {
            exception = e;
        }
    }

    @Then("password creation fails")
    public void tFails() {
        assertNotNull(exception);
    }

    @Then("password creation passes")
    public void tPasses() {
        assertNull(exception);
        assertNotNull(password);
    }
}
