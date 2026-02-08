package com.jrobertgardzinski.security.domain.vo;

import java.util.Objects;

public record Email(
        String value
) {
        public Email {
                Objects.requireNonNull(value, "Cannot be null");

                if (!value.matches("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")) {
                        throw new IllegalArgumentException("%s does not meet regex".formatted(value));
                }
                // todo remove below
                if (value.endsWith("@gmail.com")) {
                        int atIndex = value.indexOf("@");
                        String before = value.substring(0, atIndex);
                        String filtered = before.replaceAll("[.]", "");
                        if (filtered.contains("+")) {
                                int plusIndex = filtered.indexOf("+");
                                filtered = filtered.substring(0, plusIndex);
                        }
                        value = filtered;
                }
        }
}