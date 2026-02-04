package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.Optional;

public interface PasswordSpecification {
    Optional<String> check(PlaintextPassword password);
}
