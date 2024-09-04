package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import jakarta.validation.constraints.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertAll;

class PasswordTest {

    private static Validator validator;

    @BeforeAll
    static void init() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @Test
    void notNull() {
        Password password = new Password(null);

        Set<ConstraintViolation<Password>> constraintViolations = validator.validate(password);
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
    @ValueSource(strings = {"too short", "secret", "password123"})
    void doesNotMatchSize(String value) {
        Password password = new Password(value);

        Set<ConstraintViolation<Password>> constraintViolations = validator.validate(password);
        assertAll(
                () -> assertThat(
                        constraintViolations.size(),
                        equalTo(1)),
                () -> assertThat(
                        constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                        containsInAnyOrder("must be at least 12 characters long"))
        );
    }

    @Nested
    class BreakingRegex {

        @Test
        @DisplayName("Breaks all but small letter")
        void test1() {
            Password password = new Password("strong password");

            Set<ConstraintViolation<Password>> constraintViolations = validator.validate(password);
            assertAll(
                    () -> assertThat(
                            constraintViolations.size(),
                            equalTo(3)),
                    () -> assertThat(
                            constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                            containsInAnyOrder(
                                    "must contain a capital letter",
                                    "must contain a digit",
                                    "must contain one of special characters: [#, ?, !]"))
            );
        }

        @Test
        @DisplayName("Fixed capital letter constraint...")
        void test2() {
            Password password = new Password("strong Password");

            Set<ConstraintViolation<Password>> constraintViolations = validator.validate(password);
            assertAll(
                    () -> assertThat(
                            constraintViolations.size(),
                            equalTo(2)),
                    () -> assertThat(
                            constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                            containsInAnyOrder(
                                    "must contain a digit",
                                    "must contain one of special characters: [#, ?, !]"))
            );
        }

        @Test
        @DisplayName("..then added digit...")
        void test3() {
            Password password = new Password("strong Password1");

            Set<ConstraintViolation<Password>> constraintViolations = validator.validate(password);
            assertAll(
                    () -> assertThat(
                            constraintViolations.size(),
                            equalTo(1)),
                    () -> assertThat(
                            constraintViolations.stream().map(ConstraintViolation::getMessage).toList(),
                            containsInAnyOrder(
                                    "must contain one of special characters: [#, ?, !]"))
            );
        }

        @Test
        @DisplayName("..and a special character passed validation!")
        void test4() {
            Password password = new Password("strong Password1!");

            Set<ConstraintViolation<Password>> constraintViolations = validator.validate(password);
            assertThat(constraintViolations.size(), equalTo(0));
        }
    }
}