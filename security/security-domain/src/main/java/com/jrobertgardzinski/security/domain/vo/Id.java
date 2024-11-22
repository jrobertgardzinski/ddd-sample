package com.jrobertgardzinski.security.domain.vo;

import java.util.Objects;

public record Id(Long value) {
    public Id {
        Objects.requireNonNull(value);
    }
}
