package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
//import static org.assertj.core.api.Assertions.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

class LoginTest {

    private static Validator validator;

    @BeforeAll
    static void init() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    void template(Supplier<Login> loginSupplier, Consumer<List<ConstraintViolation<Login>>> assertions) {
        Login login = loginSupplier.get();

        List<ConstraintViolation<Login>> constraintViolations = List.copyOf(validator.validate(login));

        assertions.accept(constraintViolations);
    }

    @Test
    void notNull() {
        template(
                () -> new Login(null),
                constraintViolations -> assertAll(
                        () -> assertThat(constraintViolations.size(), equalTo(2)),
                        () -> assertThat(constraintViolations.stream().map(ConstraintViolation::getMessage).toList(), containsInAnyOrder("must not be null", "must not be empty"))
                )
        );
    }
}