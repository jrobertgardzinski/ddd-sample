package com.jrobertgardzinski.security.application.feature.input.policy;

import com.jrobertgardzinski.password.policy.domain.PasswordPolicyPort;
import com.jrobertgardzinski.password.policy.domain.StrongPasswordPolicyAdapter;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class StrongPasswordPolicyRules {

    private final PasswordPolicyPort policy = new StrongPasswordPolicyAdapter();
    private List<String> violations;

    @When("I validate {string} against strong password policy")
    public void w(String password) {
        violations = policy.validate(new PlainTextPassword(password));
    }

    @Then("the policy reports {string}")
    public void tReports(String expectedViolation) {
        assertTrue(violations.contains(expectedViolation),
                "Expected violation '%s' but got: %s".formatted(expectedViolation, violations));
    }

    @Then("the policy reports {int} violations")
    public void tCount(int expectedCount) {
        assertEquals(expectedCount, violations.size(),
                "Expected %d violations but got: %s".formatted(expectedCount, violations));
    }

    @Then("the password satisfies the policy")
    public void tSatisfies() {
        assertTrue(violations.isEmpty(),
                "Expected no violations but got: %s".formatted(violations));
    }
}
