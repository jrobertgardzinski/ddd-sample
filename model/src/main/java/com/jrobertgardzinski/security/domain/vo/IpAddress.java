package com.jrobertgardzinski.security.domain.vo;

import org.apache.commons.validator.routines.InetAddressValidator;

import java.util.Objects;

public record IpAddress (String value) {

    private static final InetAddressValidator validator = InetAddressValidator.getInstance();
    
    public IpAddress {
        Objects.requireNonNull(value);

        if (!validator.isValid(value)) {
            throw new IllegalArgumentException(value + " is not valid!");
        }
    }
}
