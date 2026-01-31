package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

public class StrongPasswordPolicyAdapter implements PasswordPolicyPort {

    private static final int MIN_LENGTH = 12;
    private static final String SPECIAL_CHARS = "#?!";

    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern DIGIT = Pattern.compile("\\d");
    private static final Pattern SPECIAL = Pattern.compile("[#?!]");

    @Override
    public List<String> validate(PlainTextPassword password) {
        Objects.requireNonNull(password);

        String value = password.value();
        List<String> violations = new ArrayList<>();

        if (value.length() < MIN_LENGTH) {
            violations.add("must be at least %d characters long".formatted(MIN_LENGTH));
        }
        if (!LOWERCASE.matcher(value).find()) {
            violations.add("must contain a lowercase letter");
        }
        if (!UPPERCASE.matcher(value).find()) {
            violations.add("must contain an uppercase letter");
        }
        if (!DIGIT.matcher(value).find()) {
            violations.add("must contain a digit");
        }
        if (!SPECIAL.matcher(value).find()) {
            violations.add("must contain one of special characters: [%s]".formatted(SPECIAL_CHARS));
        }

        return violations;
    }
}
