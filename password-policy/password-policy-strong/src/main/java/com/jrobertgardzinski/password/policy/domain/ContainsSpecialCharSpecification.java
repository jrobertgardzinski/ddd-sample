package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.Optional;
import java.util.regex.Pattern;

class ContainsSpecialCharSpecification implements PasswordSpecification {

    private static final String SPECIAL_CHARS = "#?!";
    private static final Pattern SPECIAL = Pattern.compile("[#?!]");

    @Override
    public Optional<String> check(PlaintextPassword password) {
        return SPECIAL.matcher(password.value()).find()
                ? Optional.empty()
                : Optional.of("must contain one of special characters: [%s]".formatted(SPECIAL_CHARS));
    }
}
