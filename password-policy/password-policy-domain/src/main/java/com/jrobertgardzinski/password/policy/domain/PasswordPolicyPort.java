package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.List;

public interface PasswordPolicyPort {

    List<String> validate(PlaintextPassword password);

    default boolean isSatisfiedBy(PlaintextPassword password) {
        return validate(password).isEmpty();
    }
}
