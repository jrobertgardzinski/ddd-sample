package com.jrobertgardzinski.security.application.feature.register;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class RegisterRule2 {

    private final RegisterTestContext context;

    public RegisterRule2(RegisterTestContext context) {
        this.context = context;
    }

    @Given("a user with an email {string} has already been registered")
    public void g2(String string) throws Exception {
        context.getUserRepository().save(
                new User(
                        new Email(string),
                        context.getHashAlgorithm().hash(
                                new PlainTextPassword("RobertLewandowski9theBest!"),
                                new Salt("salt213442354235")
                        )
                ));
    }

    @Then("registration fails")
    public void t2() {
        assertFalse(context.getUserRepository().existsBy(new Email(context.getEmail())));
    }
}
