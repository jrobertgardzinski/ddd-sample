package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.Optional;
import java.util.regex.Pattern;

class ContainsDigitSpecification implements PasswordSpecification {

    private static final Pattern DIGIT = Pattern.compile("\\d");

    @Override
    public Optional<String> check(PlaintextPassword password) {
        return DIGIT.matcher(password.value()).find()
                ? Optional.empty()
                : Optional.of("must contain a digit");
    }
}
