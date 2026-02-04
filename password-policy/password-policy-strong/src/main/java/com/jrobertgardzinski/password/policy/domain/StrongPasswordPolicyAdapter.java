package com.jrobertgardzinski.password.policy.domain;

import java.util.List;

public class StrongPasswordPolicyAdapter implements PasswordPolicyPort {

    private final List<PasswordSpecification> specifications = List.of(
            new MinLengthSpecification(12),
            new ContainsLowercaseSpecification(),
            new ContainsUppercaseSpecification(),
            new ContainsDigitSpecification(),
            new ContainsSpecialCharSpecification()
    );

    @Override
    public List<PasswordSpecification> specifications() {
        return specifications;
    }
}
