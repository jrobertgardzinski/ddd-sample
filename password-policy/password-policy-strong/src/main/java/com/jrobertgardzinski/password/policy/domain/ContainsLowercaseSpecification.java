package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.Optional;

class ContainsLowercaseSpecification implements PasswordSpecification {

    @Override
    public Optional<String> check(PlaintextPassword password) {
        return password.value().chars().anyMatch(Character::isLowerCase)
                ? Optional.empty()
                : Optional.of("must contain a lowercase letter");
    }
}
