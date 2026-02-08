package com.jrobertgardzinski.security.domain.vo;

import java.util.Objects;

public record IpAddress (String value) {

    public IpAddress {
        Objects.requireNonNull(value);

        if (!IpAddressValidator.isValid(value)) {
            throw new IllegalArgumentException(value + " is not valid!");
        }
    }
}
