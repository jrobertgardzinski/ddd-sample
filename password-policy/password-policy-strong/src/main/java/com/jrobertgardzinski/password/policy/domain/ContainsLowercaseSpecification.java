package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;

import java.util.Optional;

class ContainsLowercaseSpecification implements PasswordSpecification {

    @Override
    public Optional<String> check(PlainTextPassword password) {
        return password.value().chars().anyMatch(Character::isLowerCase)
                ? Optional.empty()
                : Optional.of("must contain a lowercase letter");
    }
}
