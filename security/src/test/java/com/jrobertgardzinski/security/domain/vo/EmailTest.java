package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertAll;

class EmailTest {

    private static Validator validator;

    @BeforeAll
    static void init() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @Test
    void notNull() {
        Email email = new Email(null);

        Set<ConstraintViolation<Email>> constraintViolations = validator.validate(email);
        assertAll(
                () -> assertThat(
                        constraintViolations.size(),
                        equalTo(1)),
                () -> assertThat(
                        constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                        containsInAnyOrder("must not be null"))
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"abc\"", "some-random_string text"})
    void failingRegex(String value) {
        Email email = new Email(value);

        Set<ConstraintViolation<Email>> constraintViolations = validator.validate(email);
        assertAll(
                () -> assertThat(
                        constraintViolations.size(),
                        equalTo(1)),
                () -> assertThat(
                        constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                        containsInAnyOrder("Invalid e-mail format"))
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"user@gmail.com", "andrzej@wp.pl"})
    void success(String value) {
        Email email = new Email(value);

        Set<ConstraintViolation<Email>> constraintViolations = validator.validate(email);
        assertThat(constraintViolations.size(), equalTo(0));
    }


}