package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertAll;

class IdTest {
    private static Validator validator;

    @BeforeAll
    static void init() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @Test
    void test() {
        Id id = new Id(null);

        Set<ConstraintViolation<Id>> constraintViolations = validator.validate(id);
        assertAll(
                () -> assertThat(
                        constraintViolations.size(),
                        equalTo(1)),
                () -> assertThat(
                        constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                        containsInAnyOrder("must not be null"))
        );
    }
}