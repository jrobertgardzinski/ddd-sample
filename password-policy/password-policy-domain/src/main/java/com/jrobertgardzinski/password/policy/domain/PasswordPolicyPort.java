package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.List;
import java.util.Optional;

public interface PasswordPolicyPort {

    List<PasswordSpecification> specifications();

    default List<String> validate(PlaintextPassword password) {
        return specifications().stream()
                .map(spec -> spec.check(password))
                .flatMap(Optional::stream)
                .toList();
    }

    default boolean isSatisfiedBy(PlaintextPassword password) {
        return validate(password).isEmpty();
    }
}
