package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record Password(
        @NotNull
        @Size(min = 12,
                message = "'${validatedValue}' must be at least {min} characters long")
        @Pattern(regexp = "[a-z]?",
                message = "'${validatedValue}' must contain a small letter")
        @Pattern(regexp = "[A-Z]?",
                message = "'${validatedValue}' must contain a capital letter")
        @Pattern(regexp = "\\d",
                message = "'${validatedValue}' must contain a digit")
        @Pattern(regexp = "[#?!]",
                message = "'${validatedValue}' must contain one of special characters: #, ?, !")
        String value
) {
}
