package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.password.policy.domain.StrongPasswordPolicyAdapter;
import com.jrobertgardzinski.security.application.factory.RegisterFactory;
import com.jrobertgardzinski.security.application.factory.UserRegistrationValidationException;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RegisterInputRules {

    private final RegisterFactory registerFactory = new RegisterFactory(new StrongPasswordPolicyAdapter());

    private UserRegistrationValidationException exception;

    @When("I create user registration with email {string} and password {string}")
    public void createUserRegistration(String email, String password) {
        try {
            registerFactory.create(email, password);
            exception = null;
        } catch (UserRegistrationValidationException e) {
            exception = e;
        }
    }

    @Then("I get validation error for email")
    public void validationErrorForEmail() {
        assertTrue(exception != null && exception.hasEmailErrors());
    }

    @Then("I get validation error for password")
    public void validationErrorForPassword() {
        assertTrue(exception != null && exception.hasPasswordErrors());
    }

    @Then("I get validation errors for password:")
    public void validationErrorsForPassword(DataTable dataTable) {
        assertTrue(exception != null && exception.hasPasswordErrors());
        List<String> expectedErrors = dataTable.asList();
        assertThat(exception.passwordErrors(), containsInAnyOrder(expectedErrors.toArray()));
    }
}
