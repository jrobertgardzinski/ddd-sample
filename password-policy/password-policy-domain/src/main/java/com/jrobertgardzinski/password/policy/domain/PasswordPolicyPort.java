package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;

import java.util.List;

public interface PasswordPolicyPort {

    List<String> validate(PlainTextPassword password);

    default boolean isSatisfiedBy(PlainTextPassword password) {
        return validate(password).isEmpty();
    }
}
