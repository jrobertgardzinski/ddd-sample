package com.jrobertgardzinski.security.domain.vo;

public record UserRegistration(
        Email email,
        PlainTextPassword plainTextPassword
) {
}
