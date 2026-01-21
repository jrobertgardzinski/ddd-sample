package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class Rule2 {

    private final RegisterTestContext context;
    private String emailAlreadyUsed;

    public Rule2(RegisterTestContext context) {
        this.context = context;
    }

    @Given("a user with an email {string} has already been registered")
    public void g21(String string) throws Exception {
        emailAlreadyUsed = string;

        context.getUserRepository().save(
                new User(
                        new Email(string),
                        context.getHashAlgorithm().hash(
                                new PlainTextPassword("RobertLewandowski9theBest!"),
                                new Salt("salt213442354235")
                        )
                ));
    }

    @When("another user tries to use the same email for registration")
    public void w21() {
        context.setEmail(emailAlreadyUsed);
        context.setPassword("ButLeoMessiAndCR7wereWayBetter! :)");
    }

    @Then("registration fails")
    public void t21() {

    }
}
