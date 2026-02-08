package com.jrobertgardzinski.security.domain.vo;

public record Credentials(
        Email email,
        PlaintextPassword plaintextPassword
) {
}
