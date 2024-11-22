package com.jrobertgardzinski.security.domain.vo;

import java.util.Objects;

public record Email(
        String value
) {
        public Email {
                Objects.requireNonNull(value);

                if (!value.matches("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")) {
                        throw new IllegalArgumentException("%s does not meet regex".formatted(value));
                }
        }
}