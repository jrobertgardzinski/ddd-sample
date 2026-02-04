package com.jrobertgardzinski.password.policy.domain;

import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class StrongPasswordPolicyAdapter implements PasswordPolicyPort {

    private final List<PasswordSpecification> specifications = List.of(
            new MinLengthSpecification(12),
            new ContainsLowercaseSpecification(),
            new ContainsUppercaseSpecification(),
            new ContainsDigitSpecification(),
            new ContainsSpecialCharSpecification()
    );

    @Override
    public List<String> validate(PlaintextPassword password) {
        Objects.requireNonNull(password);
        return specifications.stream()
                .map(spec -> spec.check(password))
                .flatMap(Optional::stream)
                .toList();
    }
}
