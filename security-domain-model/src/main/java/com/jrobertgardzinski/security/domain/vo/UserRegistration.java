package com.jrobertgardzinski.security.domain.vo;

public record UserRegistration(
        Email email,
        PlaintextPassword plaintextPassword
) {
}
