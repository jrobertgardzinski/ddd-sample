package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;

import java.util.Optional;

public interface PasswordSpecification {
    Optional<String> check(PlainTextPassword password);
}
