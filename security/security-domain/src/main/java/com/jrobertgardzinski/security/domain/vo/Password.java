package com.jrobertgardzinski.security.domain.vo;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public record Password(
        String value
) {
        static final String EX_1_PASSWORD_LENGTH = "must be at least 12 characters long";
        static final String EX_2_SMALL_LETTER = "must contain a small letter";
        static final String EX_3_CAPITAL_LETTER = "must contain a capital letter";
        static final String EX_4_DIGIT = "must contain a digit";
        static final String EX_5_SPECIAL_CHARACTERS = "must contain one of special characters: [#, ?, !]";

        public Password {
                Objects.requireNonNull(value);

                List<String> errors = new LinkedList<>();
                if (value.length() < 12) {
                        errors.add(EX_1_PASSWORD_LENGTH);
                }
                if (!value.matches(".*[a-z].*")) {
                        errors.add(EX_2_SMALL_LETTER);
                }
                if (!value.matches(".*[A-Z].*")) {
                        errors.add(EX_3_CAPITAL_LETTER);
                }
                if (!value.matches(".*\\d.*")) {
                        errors.add(EX_4_DIGIT);
                }
                if (!value.matches(".*[#?!].*")) {
                        errors.add(EX_5_SPECIAL_CHARACTERS);
                }

                if (!errors.isEmpty()) {
                        throw new IllegalArgumentException(errors.toString());
                }
        }

        public boolean enteredRight(Password password) {
                return this.value.equals(password.value());
        }
}
