package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;

import java.util.Optional;

class MinLengthSpecification implements PasswordSpecification {

    private final int minLength;

    MinLengthSpecification(int minLength) {
        this.minLength = minLength;
    }

    @Override
    public Optional<String> check(PlainTextPassword password) {
        return password.value().length() < minLength
                ? Optional.of("must be at least %d characters long".formatted(minLength))
                : Optional.empty();
    }
}
