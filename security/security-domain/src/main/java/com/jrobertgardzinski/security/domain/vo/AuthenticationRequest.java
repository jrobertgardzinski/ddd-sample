package com.jrobertgardzinski.security.domain.vo;

public record AuthenticationRequest (
        IpAddress ipAddress,
        Email email,
        Password password
) {
}
